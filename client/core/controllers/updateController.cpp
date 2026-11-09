#include "updateController.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QProcess>
#include <QRegularExpression>
#include <QSaveFile>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTimer>
#include <QUuid>

#include <cmath>
#include <array>
#include <limits>
#include <utility>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "amneziaApplication.h"
#include "core/controllers/gatewayController.h"
#include "core/utils/api/gatewayPayloadBuilder.h"
#include "core/utils/appUiConfig.h"
#include "version.h"
#include "core/utils/constants/apiConstants.h"
#include "core/utils/constants/apiKeys.h"
#include "core/utils/selfhosted/scriptsRegistry.h"
#include "logger.h"
#include "vpnConnection.h"

#if defined(Q_OS_ANDROID)
#include "platforms/android/android_controller.h"
#endif

namespace
{
    Logger logger("UpdateController");

    constexpr qsizetype kMaxManifestBytes = 128 * 1024;
    constexpr quint64 kMaxPackageBytes = 512ULL * 1024ULL * 1024ULL;
    constexpr int kPeriodicCheckIntervalMs = 6 * 60 * 60 * 1000;
    constexpr qsizetype kNetworkReadChunkBytes = 64 * 1024;

#if defined(Q_OS_WIN)
    const QLatin1String kInstallerRemoteFileNamePattern("AmneziaVPN_%1_windows_x64.exe");
    const QString kInstallerLocalPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/AmneziaVPN_installer.exe";
#elif defined(Q_OS_MACOS) && !defined(MACOS_NE)
    const QLatin1String kInstallerRemoteFileNamePattern("AmneziaVPN_%1_macos_x64.pkg");
    const QString kInstallerLocalPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/AmneziaVPN.pkg";
#elif defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    const QLatin1String kInstallerRemoteFileNamePattern("AmneziaVPN_%1_linux_x64.run");
    const QString kInstallerLocalPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/AmneziaVPN.run";
#endif

    bool failWith(QString *error, const QString &message)
    {
        if (error) {
            *error = message;
        }
        return false;
    }

    bool isCanonicalBase64(const QString &text, QByteArray *decoded)
    {
        const QByteArray encoded = text.toLatin1();
        if (QString::fromLatin1(encoded) != text) {
            return false;
        }
        const QByteArray value = QByteArray::fromBase64(encoded);
        if (value.toBase64() != encoded) {
            return false;
        }
        *decoded = value;
        return true;
    }

    bool parseUtcTimestamp(const QString &text, QDateTime *result)
    {
        static const QRegularExpression utcPattern(
            QStringLiteral("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,3})?Z$"));
        if (!utcPattern.match(text).hasMatch()) {
            return false;
        }
        const QDateTime value = QDateTime::fromString(text, Qt::ISODateWithMs);
        if (!value.isValid() || value.timeSpec() != Qt::UTC) {
            return false;
        }
        *result = value.toUTC();
        return true;
    }

    QStringList jsonObjectKeys(const QJsonObject &object)
    {
        QStringList keys = object.keys();
        keys.sort();
        return keys;
    }

    bool readPositiveInteger(const QJsonObject &object, const QString &key, quint64 maxValue, quint64 *value)
    {
        const QJsonValue jsonValue = object.value(key);
        if (!jsonValue.isDouble()) {
            return false;
        }
        const double number = jsonValue.toDouble();
        if (!std::isfinite(number) || number < 1.0 || number > static_cast<double>(maxValue)
            || std::floor(number) != number) {
            return false;
        }
        *value = static_cast<quint64>(number);
        return true;
    }

    bool ed25519Verify(const QByteArray &publicKeyPem, const QByteArray &message, const QByteArray &signature)
    {
        if (publicKeyPem.isEmpty() || signature.size() != 64) {
            return false;
        }

        BIO *bio = BIO_new_mem_buf(publicKeyPem.constData(), static_cast<int>(publicKeyPem.size()));
        if (!bio) {
            return false;
        }
        EVP_PKEY *key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_ED25519) {
            EVP_PKEY_free(key);
            return false;
        }

        EVP_MD_CTX *context = EVP_MD_CTX_new();
        const bool verified = context
            && EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key) == 1
            && EVP_DigestVerify(context,
                                reinterpret_cast<const unsigned char *>(signature.constData()),
                                static_cast<size_t>(signature.size()),
                                reinterpret_cast<const unsigned char *>(message.constData()),
                                static_cast<size_t>(message.size())) == 1;
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(key);
        return verified;
    }

    QStringList stringListFromJsonValue(const QJsonValue &value)
    {
        QStringList result;
        for (const QJsonValue &item : value.toArray()) {
            const QString text = item.toString();
            if (!text.isEmpty()) {
                result.append(text);
            }
        }
        return result;
    }
}

UpdateControllerDependencies UpdateController::productionDependencies()
{
    UpdateControllerDependencies dependencies;
    dependencies.platform = productionPlatform();
    dependencies.installedVersion = QStringLiteral(APP_VERSION);
    dependencies.installedVersionCode = APP_ANDROID_VERSION_CODE;
    dependencies.signingPublicKeyPem = productionUpdateSigningPublicKey();
    dependencies.automaticChecksEnabled = true;
    dependencies.checkOnConstruction = true;
#if defined(AMNEZIA_BUILD_TESTS)
    // Integration tests must not contact the production feed merely by
    // constructing CoreController. Tests can opt in with an injected transport.
    dependencies.automaticChecksEnabled = false;
    dependencies.checkOnConstruction = false;
#endif
    if (dependencies.platform == QStringLiteral("windows-x64")) {
        dependencies.manifestUrl = QUrl(QStringLiteral("https://mayaklight.ru/updates/stable/windows-x64.json"));
    } else if (dependencies.platform == QStringLiteral("android-arm64")) {
        dependencies.manifestUrl = QUrl(QStringLiteral("https://mayaklight.ru/updates/stable/android-arm64.json"));
    }
    return dependencies;
}

QByteArray UpdateController::productionUpdateSigningPublicKey()
{
    QFile keyFile(QStringLiteral(":/mayak/update_signing_public.pem"));
    if (!keyFile.open(QIODevice::ReadOnly)) {
        logger.error() << "Mayak update signing key resource is unavailable";
        return {};
    }
    return keyFile.readAll();
}

QString UpdateController::productionPlatform()
{
#if defined(Q_OS_WIN) && (defined(Q_PROCESSOR_X86_64) || defined(_M_X64))
    return QStringLiteral("windows-x64");
#elif defined(Q_OS_ANDROID) && (defined(Q_PROCESSOR_ARM_64) || defined(__aarch64__))
    return QStringLiteral("android-arm64");
#else
    return {};
#endif
}

UpdateController::UpdateController(SecureAppSettingsRepository *appSettingsRepository, QObject *parent)
    : UpdateController(appSettingsRepository, nullptr, productionDependencies(), parent)
{
}

UpdateController::UpdateController(SecureAppSettingsRepository *appSettingsRepository, VpnConnection *vpnConnection,
                                   QObject *parent)
    : UpdateController(appSettingsRepository, vpnConnection, productionDependencies(), parent)
{
}

UpdateController::UpdateController(SecureAppSettingsRepository *appSettingsRepository,
                                   UpdateControllerDependencies dependencies, QObject *parent)
    : UpdateController(appSettingsRepository, nullptr, std::move(dependencies), parent)
{
}

UpdateController::UpdateController(SecureAppSettingsRepository *appSettingsRepository, VpnConnection *vpnConnection,
                                   UpdateControllerDependencies dependencies, QObject *parent)
    : QObject(parent),
      m_appSettingsRepository(appSettingsRepository),
      m_vpnConnection(vpnConnection),
      m_networkAccessManager(dependencies.networkAccessManager),
      m_dependencies(std::move(dependencies))
{
    if (!m_networkAccessManager) {
        m_networkAccessManager = new QNetworkAccessManager(this);
    }
    if (m_dependencies.signingPublicKeyPem.isEmpty()) {
        m_dependencies.signingPublicKeyPem = productionUpdateSigningPublicKey();
    }
    if (m_dependencies.platform.isEmpty()) {
        m_dependencies.platform = productionPlatform();
    }
    if (m_dependencies.installedVersion.isEmpty()) {
        m_dependencies.installedVersion = QStringLiteral(APP_VERSION);
    }
    if (m_dependencies.installedVersionCode == 0) {
        m_dependencies.installedVersionCode = APP_ANDROID_VERSION_CODE;
    }
    if (m_dependencies.manifestUrl.isEmpty()) {
        if (m_dependencies.platform == QStringLiteral("windows-x64")) {
            m_dependencies.manifestUrl = QUrl(QStringLiteral("https://mayaklight.ru/updates/stable/windows-x64.json"));
        } else if (m_dependencies.platform == QStringLiteral("android-arm64")) {
            m_dependencies.manifestUrl = QUrl(QStringLiteral("https://mayaklight.ru/updates/stable/android-arm64.json"));
        }
    }
    m_signedFeedEnabled = !m_dependencies.manifestUrl.isEmpty();
#if defined(Q_OS_WIN)
    m_updateSupported = m_signedFeedEnabled && m_dependencies.platform == QStringLiteral("windows-x64");
#elif defined(Q_OS_ANDROID)
    m_updateSupported = m_signedFeedEnabled && m_dependencies.platform == QStringLiteral("android-arm64");
#elif defined(Q_OS_IOS) || defined(MACOS_NE)
    m_updateSupported = isStoreUpdate();
#else
    m_updateSupported = true;
#endif

    m_periodicCheckTimer = new QTimer(this);
    m_periodicCheckTimer->setInterval(kPeriodicCheckIntervalMs);
    connect(m_periodicCheckTimer, &QTimer::timeout, this, &UpdateController::checkForUpdatesAutomatically);
    m_periodicCheckTimer->start();
    if (m_dependencies.checkOnConstruction) {
        QTimer::singleShot(0, this, &UpdateController::checkForUpdatesAutomatically);
    }
}

QString UpdateController::getVersion() const { return m_version; }
QString UpdateController::getReleaseDate() const { return m_releaseDate; }
QString UpdateController::getDescription() const { return m_description; }
QStringList UpdateController::getTags() const { return m_tags; }
QStringList UpdateController::getNewFeatures() const { return m_newFeatures; }
QStringList UpdateController::getImprovements() const { return m_improvements; }
QStringList UpdateController::getBugFixes() const { return m_bugFixes; }
UpdateState::State UpdateController::getUpdateState() const { return m_updateState; }
bool UpdateController::isUpdateCheckRunning() const { return m_updateCheckRunning; }
bool UpdateController::isUpdateSupported() const { return m_updateSupported; }
int UpdateController::getDownloadProgress() const { return m_downloadProgress; }
QString UpdateController::getStatusMessage() const { return m_statusMessage; }

bool UpdateController::isStoreUpdate() const
{
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    return true;
#else
    return false;
#endif
}

void UpdateController::setUpdateState(UpdateState::State state)
{
    if (m_updateState == state) {
        return;
    }
    m_updateState = state;
    emit updateStateChanged();
}

void UpdateController::setUpdateCheckRunning(bool running)
{
    if (m_updateCheckRunning == running) {
        return;
    }
    m_updateCheckRunning = running;
    emit updateCheckRunningChanged();
}

void UpdateController::setDownloadProgress(int percent)
{
    percent = qBound(0, percent, 100);
    if (m_downloadProgress == percent) {
        return;
    }
    m_downloadProgress = percent;
    emit downloadProgressChanged();
}

void UpdateController::setStatusMessage(const QString &message)
{
    if (m_statusMessage == message) {
        return;
    }
    m_statusMessage = message;
    emit statusMessageChanged();
}

bool UpdateController::compareVersions(const QString &left, const QString &right, int *comparison)
{
    static const QRegularExpression pattern(
        QStringLiteral("^(0|[1-9][0-9]{0,4})\\.(0|[1-9][0-9]{0,4})\\.(0|[1-9][0-9]{0,4})\\.(0|[1-9][0-9]{0,4})$"));
    const QRegularExpressionMatch leftMatch = pattern.match(left);
    const QRegularExpressionMatch rightMatch = pattern.match(right);
    if (!leftMatch.hasMatch() || !rightMatch.hasMatch()) {
        return false;
    }

    std::array<uint, 4> leftComponents{};
    std::array<uint, 4> rightComponents{};
    for (int i = 1; i <= 4; ++i) {
        bool leftOk = false;
        bool rightOk = false;
        leftComponents[static_cast<size_t>(i - 1)] = leftMatch.captured(i).toUInt(&leftOk);
        rightComponents[static_cast<size_t>(i - 1)] = rightMatch.captured(i).toUInt(&rightOk);
        if (!leftOk || !rightOk || leftComponents[static_cast<size_t>(i - 1)] > 65535
            || rightComponents[static_cast<size_t>(i - 1)] > 65535) {
            return false;
        }
    }
    for (size_t i = 0; i < leftComponents.size(); ++i) {
        if (leftComponents[i] != rightComponents[i]) {
            if (comparison) {
                *comparison = leftComponents[i] > rightComponents[i] ? 1 : -1;
            }
            return true;
        }
    }
    if (comparison) {
        *comparison = 0;
    }
    return true;
}

QDateTime UpdateController::currentTimeUtc() const
{
    const QDateTime supplied = m_dependencies.nowUtc ? m_dependencies.nowUtc() : QDateTime::currentDateTimeUtc();
    return supplied.toUTC();
}

bool UpdateController::isAllowedPackageUrl(const QUrl &url, const QUrl &manifestUrl, QString *error)
{
    if (!url.isValid() || !manifestUrl.isValid() || url.scheme() != QStringLiteral("https")
        || manifestUrl.scheme() != QStringLiteral("https") || url.host().isEmpty()
        || url.host().compare(manifestUrl.host(), Qt::CaseInsensitive) != 0
        || url.port(443) != 443 || manifestUrl.port(443) != 443 || !url.userInfo().isEmpty()
        || !url.query().isEmpty() || !url.fragment().isEmpty()) {
        return failWith(error, QStringLiteral("The package URL must use the feed's HTTPS origin."));
    }

    const QString path = url.path(QUrl::FullyEncoded);
    static const QRegularExpression packagePath(QStringLiteral("^/updates/packages/[A-Za-z0-9][A-Za-z0-9._-]*$"));
    if (!packagePath.match(path).hasMatch() || path.contains(QStringLiteral("..")) || path.contains(QStringLiteral("//"))
        || path.contains(QLatin1Char('%')) || path.contains(QLatin1Char('\\'))) {
        return failWith(error, QStringLiteral("The package path is not allowed."));
    }
    return true;
}

bool UpdateController::verifySignedManifest(const QByteArray &envelopeBytes, const QByteArray &publicKeyPem,
                                            const QString &expectedPlatform, const QString &installedVersion,
                                            quint64 installedVersionCode, const QUrl &manifestUrl,
                                            const QDateTime &nowUtc, SignedUpdateManifest *manifest, QString *error)
{
    if (!manifest || envelopeBytes.isEmpty() || envelopeBytes.size() > kMaxManifestBytes) {
        return failWith(error, QStringLiteral("The update manifest is empty or too large."));
    }
    if (expectedPlatform != QStringLiteral("windows-x64") && expectedPlatform != QStringLiteral("android-arm64")) {
        return failWith(error, QStringLiteral("This update platform is not supported."));
    }

    QJsonParseError parseError;
    const QJsonDocument envelopeDocument = QJsonDocument::fromJson(envelopeBytes, &parseError);
    if (parseError.error != QJsonParseError::NoError || !envelopeDocument.isObject()) {
        return failWith(error, QStringLiteral("The update envelope is malformed."));
    }
    const QJsonObject envelope = envelopeDocument.object();
    QStringList envelopeKeys = { QStringLiteral("alg"), QStringLiteral("payload"), QStringLiteral("schema"), QStringLiteral("signature") };
    envelopeKeys.sort();
    if (jsonObjectKeys(envelope) != envelopeKeys || !envelope.value(QStringLiteral("schema")).isDouble()
        || envelope.value(QStringLiteral("schema")).toInt(-1) != 1
        || envelope.value(QStringLiteral("alg")).toString() != QStringLiteral("Ed25519")
        || !envelope.value(QStringLiteral("payload")).isString()
        || !envelope.value(QStringLiteral("signature")).isString()) {
        return failWith(error, QStringLiteral("The update envelope fields are invalid."));
    }

    QByteArray payload;
    QByteArray signature;
    if (!isCanonicalBase64(envelope.value(QStringLiteral("payload")).toString(), &payload)
        || !isCanonicalBase64(envelope.value(QStringLiteral("signature")).toString(), &signature)
        || payload.isEmpty() || signature.size() != 64
        || QString::fromUtf8(payload).toUtf8() != payload) {
        return failWith(error, QStringLiteral("The update envelope encoding is invalid."));
    }
    if (!ed25519Verify(publicKeyPem, payload, signature)) {
        return failWith(error, QStringLiteral("The update signature is invalid."));
    }

    const QJsonDocument payloadDocument = QJsonDocument::fromJson(payload, &parseError);
    if (parseError.error != QJsonParseError::NoError || !payloadDocument.isObject()) {
        return failWith(error, QStringLiteral("The signed update payload is malformed."));
    }
    const QJsonObject object = payloadDocument.object();
    QStringList requiredKeys = {
        QStringLiteral("channel"), QStringLiteral("expiresAt"), QStringLiteral("platform"),
        QStringLiteral("product"), QStringLiteral("publishedAt"), QStringLiteral("sha256"),
        QStringLiteral("size"), QStringLiteral("url"), QStringLiteral("version"), QStringLiteral("versionCode")
    };
    if (object.contains(QStringLiteral("releaseNotes"))) {
        requiredKeys.append(QStringLiteral("releaseNotes"));
    }
    requiredKeys.sort();
    if (jsonObjectKeys(object) != requiredKeys) {
        return failWith(error, QStringLiteral("The signed update payload has unexpected fields."));
    }

    const auto isString = [&object](const QString &key) { return object.value(key).isString(); };
    if (!isString(QStringLiteral("product")) || object.value(QStringLiteral("product")).toString() != QStringLiteral("mayak-vpn")
        || !isString(QStringLiteral("channel")) || object.value(QStringLiteral("channel")).toString() != QStringLiteral("stable")
        || !isString(QStringLiteral("platform")) || object.value(QStringLiteral("platform")).toString() != expectedPlatform
        || !isString(QStringLiteral("version")) || !isString(QStringLiteral("url"))
        || !isString(QStringLiteral("sha256")) || !isString(QStringLiteral("publishedAt"))
        || !isString(QStringLiteral("expiresAt"))) {
        return failWith(error, QStringLiteral("The signed update does not match this product and platform."));
    }

    SignedUpdateManifest parsed;
    parsed.product = object.value(QStringLiteral("product")).toString();
    parsed.channel = object.value(QStringLiteral("channel")).toString();
    parsed.platform = object.value(QStringLiteral("platform")).toString();
    parsed.version = object.value(QStringLiteral("version")).toString();
    parsed.url = QUrl(object.value(QStringLiteral("url")).toString(), QUrl::StrictMode);
    parsed.sha256 = object.value(QStringLiteral("sha256")).toString().toLatin1();
    if (!QRegularExpression(QStringLiteral("^[0-9a-f]{64}$")).match(QString::fromLatin1(parsed.sha256)).hasMatch()) {
        return failWith(error, QStringLiteral("The signed package hash is malformed."));
    }

    quint64 size = 0;
    quint64 versionCode = 0;
    if (!readPositiveInteger(object, QStringLiteral("size"), kMaxPackageBytes, &size)
        || !readPositiveInteger(object, QStringLiteral("versionCode"), std::numeric_limits<quint32>::max(), &versionCode)) {
        return failWith(error, QStringLiteral("The signed package size or version code is invalid."));
    }
    parsed.size = size;
    parsed.versionCode = versionCode;

    int versionComparison = 0;
    if (!compareVersions(parsed.version, installedVersion, &versionComparison) || versionComparison <= 0) {
        return failWith(error, QStringLiteral("The signed update version is not newer than the installed version."));
    }
    if (expectedPlatform == QStringLiteral("android-arm64") && versionCode <= installedVersionCode) {
        return failWith(error, QStringLiteral("The Android update version code is not newer than the installed app."));
    }
    if (!isAllowedPackageUrl(parsed.url, manifestUrl, error)) {
        return false;
    }
    if (expectedPlatform == QStringLiteral("windows-x64") && !parsed.url.path().endsWith(QStringLiteral(".exe"), Qt::CaseSensitive)) {
        return failWith(error, QStringLiteral("The Windows package must be an executable installer."));
    }
    if (expectedPlatform == QStringLiteral("android-arm64") && !parsed.url.path().endsWith(QStringLiteral(".apk"), Qt::CaseSensitive)) {
        return failWith(error, QStringLiteral("The Android package must be an APK."));
    }

    if (!parseUtcTimestamp(object.value(QStringLiteral("publishedAt")).toString(), &parsed.publishedAt)
        || !parseUtcTimestamp(object.value(QStringLiteral("expiresAt")).toString(), &parsed.expiresAt)
        || parsed.publishedAt >= parsed.expiresAt || parsed.publishedAt > nowUtc || parsed.expiresAt <= nowUtc) {
        return failWith(error, QStringLiteral("The signed update validity interval is invalid or expired."));
    }

    if (object.contains(QStringLiteral("releaseNotes"))) {
        if (!object.value(QStringLiteral("releaseNotes")).isString()) {
            return failWith(error, QStringLiteral("The update release notes must be plain text."));
        }
        parsed.releaseNotes = object.value(QStringLiteral("releaseNotes")).toString();
        if (parsed.releaseNotes.size() > 10000 || parsed.releaseNotes.contains(QChar::Null)) {
            return failWith(error, QStringLiteral("The update release notes are too long or malformed."));
        }
    }

    *manifest = parsed;
    if (error) {
        error->clear();
    }
    return true;
}

void UpdateController::checkForUpdates()
{
    performUpdateCheck();
}

void UpdateController::checkForUpdatesAutomatically()
{
#if CLIENT_ENABLE_APP_UPDATES
    if (!m_dependencies.automaticChecksEnabled
        || (m_appSettingsRepository && !m_appSettingsRepository->isAutoUpdateCheckEnabled())) {
        return;
    }
    performUpdateCheck();
#endif
}

void UpdateController::performUpdateCheck()
{
#if !CLIENT_ENABLE_APP_UPDATES
    return;
#endif
    if (!m_updateSupported || m_updateCheckRunning || m_activeReply
        || m_updateState == UpdateState::State::Downloading) {
        if (!m_updateSupported) {
            setStatusMessage(tr("Автоматическое обновление недоступно для этой версии приложения."));
            emit updateCheckFailed();
        }
        return;
    }

    if (m_signedFeedEnabled) {
        requestSignedManifest();
        return;
    }

    // Upstream behavior remains available only on platforms outside the
    // Mayak Windows and Android release targets.
    if (!m_appSettingsRepository) {
        emit updateCheckFailed();
        return;
    }
    setUpdateCheckRunning(true);
    auto gatewayController = QSharedPointer<GatewayController>::create(m_appSettingsRepository->getGatewayEndpoint(),
                                                                       m_appSettingsRepository->isDevGatewayEnv(),
                                                                       apiDefs::requestTimeoutMsecs,
                                                                       m_appSettingsRepository->isStrictKillSwitchEnabled(),
                                                                       m_appSettingsRepository);
    const QJsonObject apiPayload = GatewayPayloadBuilder(m_appSettingsRepository).build();
    QTimer::singleShot(1000, this, [this, gatewayController, apiPayload]() {
        gatewayController->postAsync(QStringLiteral("%1v1/app_update").arg(m_appSettingsRepository->getGatewayEndpoint()), apiPayload)
            .then(this, [this, gatewayController](QPair<ErrorCode, QByteArray> result) {
                setUpdateCheckRunning(false);
                const auto [err, gatewayResponse] = result;
                if (err != ErrorCode::NoError) {
                    logger.error() << "Gateway update request failed with code:" << static_cast<int>(err);
                    emit updateCheckFailed();
                    return;
                }
                const QJsonObject gatewayData = QJsonDocument::fromJson(gatewayResponse).object();
                if (!gatewayData.value(apiDefs::key::updateAvailable).toBool()) {
                    emit updateNotFound();
                    return;
                }
                m_version = gatewayData.value(apiDefs::key::updateVersion).toString();
                m_releaseDate = gatewayData.value(apiDefs::key::releaseDate).toString();
                m_description = gatewayData.value(apiDefs::key::updateDescription).toString();
                m_tags = stringListFromJsonValue(gatewayData.value(apiDefs::key::updateTags));
                m_newFeatures = stringListFromJsonValue(gatewayData.value(apiDefs::key::newFeatures));
                m_improvements = stringListFromJsonValue(gatewayData.value(apiDefs::key::improvements));
                m_bugFixes = stringListFromJsonValue(gatewayData.value(apiDefs::key::bugFixes));
                m_downloadBaseUrl = gatewayData.value(apiDefs::key::downloadBaseUrl).toString();
                if (m_downloadBaseUrl.endsWith('/')) {
                    m_downloadBaseUrl.chop(1);
                }
                m_releasePageUrl = gatewayData.value(apiDefs::key::releasePageUrl).toString();
                if (m_version.isEmpty()) {
                    emit updateCheckFailed();
                    return;
                }
                setUpdateState(UpdateState::State::Idle);
                emit updateFound();
            });
    });
}

QNetworkRequest UpdateController::requestForUrl(const QUrl &url) const
{
    QNetworkRequest request(url);
    request.setTransferTimeout(30000);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    request.setRawHeader("Accept", "application/json, application/octet-stream");
    return request;
}

void UpdateController::requestSignedManifest()
{
    if (!m_dependencies.manifestUrl.isValid() || m_dependencies.manifestUrl.scheme() != QStringLiteral("https")
        || m_dependencies.manifestUrl.host() != QStringLiteral("mayaklight.ru")
        || m_dependencies.manifestUrl.port(443) != 443 || !m_dependencies.manifestUrl.userInfo().isEmpty()
        || !m_dependencies.manifestUrl.query().isEmpty() || !m_dependencies.manifestUrl.fragment().isEmpty()) {
        setStatusMessage(tr("Адрес сервера обновлений недействителен."));
        emit updateCheckFailed();
        return;
    }
    const QString expectedPath = m_dependencies.platform == QStringLiteral("windows-x64")
        ? QStringLiteral("/updates/stable/windows-x64.json")
        : QStringLiteral("/updates/stable/android-arm64.json");
    if (m_dependencies.manifestUrl.path(QUrl::FullyDecoded) != expectedPath) {
        setStatusMessage(tr("Адрес сервера обновлений недействителен."));
        emit updateCheckFailed();
        return;
    }

    setUpdateCheckRunning(true);
    m_manifestBuffer.clear();
    m_requestKind = RequestKind::Manifest;
    m_activeReply = m_networkAccessManager->get(requestForUrl(m_dependencies.manifestUrl));
    connect(m_activeReply, &QIODevice::readyRead, this, [this]() {
        if (m_requestKind != RequestKind::Manifest || !m_activeReply) {
            return;
        }
        const qsizetype remaining = kMaxManifestBytes - m_manifestBuffer.size() + 1;
        const QByteArray chunk = m_activeReply->read(qMax<qsizetype>(1, remaining));
        m_manifestBuffer.append(chunk);
        if (m_manifestBuffer.size() > kMaxManifestBytes) {
            failActiveRequest(tr("Ответ сервера обновлений слишком большой."), true);
        }
    });
    connect(m_activeReply, &QNetworkReply::finished, this, [this]() {
        if (m_requestKind == RequestKind::Manifest) {
            finishManifestRequest();
        }
    });
}

void UpdateController::finishActiveReply()
{
    if (m_activeReply) {
        m_activeReply->deleteLater();
        m_activeReply = nullptr;
    }
    m_requestKind = RequestKind::None;
}

void UpdateController::finishManifestRequest()
{
    if (!m_activeReply) {
        return;
    }
    const qsizetype remaining = kMaxManifestBytes - m_manifestBuffer.size() + 1;
    m_manifestBuffer.append(m_activeReply->read(qMax<qsizetype>(1, remaining)));
    const QNetworkReply::NetworkError networkError = m_activeReply->error();
    const int status = m_activeReply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const bool redirected = m_activeReply->attribute(QNetworkRequest::RedirectionTargetAttribute).isValid();
    finishActiveReply();
    setUpdateCheckRunning(false);

    if (networkError != QNetworkReply::NoError || status != 200 || redirected || m_manifestBuffer.isEmpty()
        || m_manifestBuffer.size() > kMaxManifestBytes) {
        m_manifestBuffer.clear();
        setStatusMessage(tr("Не удалось проверить обновления. Проверьте подключение и попробуйте снова."));
        emit updateCheckFailed();
        return;
    }

    SignedUpdateManifest update;
    QString error;
    if (!verifySignedManifest(m_manifestBuffer, m_dependencies.signingPublicKeyPem,
                              m_dependencies.platform, m_dependencies.installedVersion,
                              m_dependencies.installedVersionCode, m_dependencies.manifestUrl,
                              currentTimeUtc(), &update, &error)) {
        logger.warning() << "Signed update manifest rejected:" << error;
        m_manifestBuffer.clear();
        setStatusMessage(tr("Сервер не вернул проверенное обновление."));
        emit updateCheckFailed();
        return;
    }
    m_manifestBuffer.clear();

    m_signedUpdate = update;
    m_version = update.version;
    m_releaseDate = update.publishedAt.toString(Qt::ISODate);
    m_description = update.releaseNotes;
    m_tags = { tr("Официальное обновление") };
    m_newFeatures.clear();
    m_improvements.clear();
    m_bugFixes.clear();
    m_verifiedArtifactPath.clear();
    setDownloadProgress(0);
    setStatusMessage(tr("Доступна версия %1.").arg(m_version));
    setUpdateState(UpdateState::State::Idle);
    emit updateFound();
}

void UpdateController::startUpdate()
{
    if (!m_updateSupported) {
        setStatusMessage(tr("Обновление недоступно для этой архитектуры устройства."));
        setUpdateState(UpdateState::State::DownloadError);
        return;
    }
    if (isStoreUpdate()) {
        openStorePage();
        return;
    }
    if (m_signedFeedEnabled) {
        if (m_updateState == UpdateState::State::Downloading) {
            return;
        }
        if (m_signedUpdate.version.isEmpty()) {
            checkForUpdates();
            return;
        }
        beginPackageDownload();
        return;
    }

#if defined(Q_OS_ANDROID)
    if (m_releasePageUrl.isEmpty()) {
        setUpdateState(UpdateState::State::DownloadError);
        return;
    }
    QDesktopServices::openUrl(QUrl(m_releasePageUrl));
#elif !defined(Q_OS_IOS) && !defined(MACOS_NE)
    downloadInstaller();
#endif
}

void UpdateController::cancelUpdate()
{
    if (m_requestKind != RequestKind::Package && m_updateState != UpdateState::State::Downloading) {
        return;
    }
    failActiveRequest(tr("Загрузка обновления отменена."), false);
    setUpdateState(UpdateState::State::Idle);
}

QString UpdateController::packageCacheDirectory() const
{
    if (!m_dependencies.cacheDirectory.isEmpty()) {
        return m_dependencies.cacheDirectory;
    }
    return QStandardPaths::writableLocation(QStandardPaths::CacheLocation) + QStringLiteral("/updates");
}

void UpdateController::beginPackageDownload()
{
    if (m_requestKind != RequestKind::None || m_updateState == UpdateState::State::Downloading
        || m_signedUpdate.version.isEmpty()) {
        return;
    }
    if (m_signedUpdate.expiresAt <= currentTimeUtc()) {
        m_signedUpdate = {};
        m_verifiedArtifactPath.clear();
        setStatusMessage(tr("Срок действия проверки истёк. Нажмите «Обновить», чтобы проверить ещё раз."));
        setUpdateState(UpdateState::State::Idle);
        return;
    }
    QString urlError;
    if (!isAllowedPackageUrl(m_signedUpdate.url, m_dependencies.manifestUrl, &urlError)) {
        setStatusMessage(tr("Адрес файла обновления недействителен."));
        setUpdateState(UpdateState::State::DownloadError);
        return;
    }

    const QString cacheDir = packageCacheDirectory();
    if (cacheDir.isEmpty() || !QDir().mkpath(cacheDir)) {
        setStatusMessage(tr("Не удалось создать защищённую папку для обновления."));
        setUpdateState(UpdateState::State::DownloadError);
        return;
    }
#if !defined(Q_OS_WIN)
    const QFile::Permissions privateDirectoryPermissions = QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner;
    QFile::setPermissions(cacheDir, privateDirectoryPermissions);
#endif

    const QString suffix = m_signedUpdate.platform == QStringLiteral("windows-x64")
        ? QStringLiteral("exe") : QStringLiteral("apk");
    const QString fileName = QStringLiteral("mayak-update-%1-%2.%3")
                                 .arg(m_signedUpdate.version,
                                      QUuid::createUuid().toString(QUuid::WithoutBraces), suffix);
    m_verifiedArtifactPath = QDir(cacheDir).absoluteFilePath(fileName);
    m_downloadFile = new QSaveFile(m_verifiedArtifactPath, this);
    m_downloadFile->setDirectWriteFallback(false);
    if (!m_downloadFile->open(QIODevice::WriteOnly)) {
        delete m_downloadFile;
        m_downloadFile = nullptr;
        m_verifiedArtifactPath.clear();
        setStatusMessage(tr("Не удалось подготовить файл обновления."));
        setUpdateState(UpdateState::State::DownloadError);
        return;
    }
    m_downloadHash = new QCryptographicHash(QCryptographicHash::Sha256);
    m_downloadedBytes = 0;
    setDownloadProgress(0);
    setStatusMessage(tr("Загрузка обновления…"));
    setUpdateState(UpdateState::State::Downloading);
    m_requestKind = RequestKind::Package;
    m_activeReply = m_networkAccessManager->get(requestForUrl(m_signedUpdate.url));
    connect(m_activeReply, &QIODevice::readyRead, this, &UpdateController::consumePackageData);
    connect(m_activeReply, &QNetworkReply::downloadProgress, this, [this](qint64 received, qint64) {
        if (m_signedUpdate.size > 0 && received >= 0) {
            const int percent = static_cast<int>(qMin<quint64>(100, static_cast<quint64>(received) * 100 / m_signedUpdate.size));
            setDownloadProgress(percent);
        }
    });
    connect(m_activeReply, &QNetworkReply::finished, this, &UpdateController::finishPackageDownload);
}

bool UpdateController::writePackageChunk(const QByteArray &chunk)
{
    if (!m_downloadFile || !m_downloadHash || chunk.isEmpty()) {
        return chunk.isEmpty();
    }
    if (m_downloadedBytes > m_signedUpdate.size
        || static_cast<quint64>(chunk.size()) > m_signedUpdate.size - m_downloadedBytes) {
        failActiveRequest(tr("Файл обновления превышает заявленный размер."), false);
        return false;
    }
    if (m_downloadFile->write(chunk) != chunk.size()) {
        failActiveRequest(tr("Не удалось сохранить файл обновления."), false);
        return false;
    }
    m_downloadHash->addData(chunk);
    m_downloadedBytes += static_cast<quint64>(chunk.size());
    setDownloadProgress(static_cast<int>(m_downloadedBytes * 100 / m_signedUpdate.size));
    return true;
}

void UpdateController::consumePackageData()
{
    if (m_requestKind != RequestKind::Package || !m_activeReply) {
        return;
    }
    while (m_activeReply->bytesAvailable() > 0) {
        const QByteArray chunk = m_activeReply->read(kNetworkReadChunkBytes);
        if (chunk.isEmpty() || !writePackageChunk(chunk)) {
            return;
        }
    }
}

void UpdateController::finishPackageDownload()
{
    if (m_requestKind != RequestKind::Package || !m_activeReply) {
        return;
    }
    consumePackageData();
    if (m_requestKind != RequestKind::Package || !m_activeReply) {
        return;
    }

    const QNetworkReply::NetworkError networkError = m_activeReply->error();
    const int status = m_activeReply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const bool redirected = m_activeReply->attribute(QNetworkRequest::RedirectionTargetAttribute).isValid();
    const QVariant contentLengthHeader = m_activeReply->header(QNetworkRequest::ContentLengthHeader);
    const qint64 contentLength = contentLengthHeader.isValid() ? contentLengthHeader.toLongLong() : -1;
    finishActiveReply();

    if (networkError != QNetworkReply::NoError || status != 200 || redirected
        || (contentLength >= 0 && static_cast<quint64>(contentLength) != m_signedUpdate.size)
        || m_downloadedBytes != m_signedUpdate.size) {
        failActiveRequest(tr("Загрузка обновления прервалась. Попробуйте ещё раз."), false);
        return;
    }
    if (!m_downloadHash || m_downloadHash->result().toHex() != m_signedUpdate.sha256) {
        failActiveRequest(tr("Контрольная сумма обновления не совпала. Файл удалён."), false);
        return;
    }
    delete m_downloadHash;
    m_downloadHash = nullptr;
    if (!m_downloadFile || !m_downloadFile->commit()) {
        failActiveRequest(tr("Не удалось сохранить проверенное обновление."), false);
        return;
    }
    delete m_downloadFile;
    m_downloadFile = nullptr;
#if !defined(Q_OS_WIN)
    QFile::setPermissions(m_verifiedArtifactPath, QFile::ReadOwner | QFile::WriteOwner);
#endif

    QString error;
    if (!verifyDownloadedFile(&error)) {
        QFile::remove(m_verifiedArtifactPath);
        m_verifiedArtifactPath.clear();
        setStatusMessage(tr("Файл обновления изменился после загрузки и был удалён."));
        setUpdateState(UpdateState::State::DownloadError);
        return;
    }
    setDownloadProgress(100);
    setStatusMessage(tr("Файл обновления проверен. Нажмите «Установить обновление», чтобы продолжить."));
    setUpdateState(UpdateState::State::ReadyToInstall);
}

void UpdateController::failActiveRequest(const QString &message, bool isCheck)
{
    if (m_activeReply) {
        QNetworkReply *reply = m_activeReply;
        m_activeReply = nullptr;
        QObject::disconnect(reply, nullptr, this, nullptr);
        reply->abort();
        reply->deleteLater();
    }
    m_requestKind = RequestKind::None;
    if (m_downloadFile) {
        m_downloadFile->cancelWriting();
        delete m_downloadFile;
        m_downloadFile = nullptr;
    }
    delete m_downloadHash;
    m_downloadHash = nullptr;
    m_downloadedBytes = 0;
    if (!m_verifiedArtifactPath.isEmpty() && m_updateState != UpdateState::State::ReadyToInstall) {
        QFile::remove(m_verifiedArtifactPath);
        m_verifiedArtifactPath.clear();
    }
    setStatusMessage(message);
    if (isCheck) {
        setUpdateCheckRunning(false);
        emit updateCheckFailed();
    } else {
        setDownloadProgress(0);
        if (m_updateState != UpdateState::State::Idle) {
            setUpdateState(UpdateState::State::DownloadError);
        }
    }
}

bool UpdateController::verifyDownloadedFile(QString *error) const
{
    if (m_verifiedArtifactPath.isEmpty() || m_signedUpdate.size == 0) {
        return failWith(error, QStringLiteral("No verified update file is available."));
    }
    const QFileInfo fileInfo(m_verifiedArtifactPath);
    const QFileInfo cacheInfo(packageCacheDirectory());
    if (!fileInfo.exists() || !fileInfo.isFile() || fileInfo.isSymLink()
        || fileInfo.size() != static_cast<qint64>(m_signedUpdate.size)
        || fileInfo.canonicalPath() != cacheInfo.canonicalFilePath()) {
        return failWith(error, QStringLiteral("The verified update file is missing or outside the private cache."));
    }

    QFile file(m_verifiedArtifactPath);
    if (!file.open(QIODevice::ReadOnly)) {
        return failWith(error, QStringLiteral("The verified update file cannot be reopened."));
    }
    QCryptographicHash hash(QCryptographicHash::Sha256);
    while (!file.atEnd()) {
        const QByteArray chunk = file.read(kNetworkReadChunkBytes);
        if (chunk.isEmpty() && file.error() != QFileDevice::NoError) {
            return failWith(error, QStringLiteral("The verified update file could not be read."));
        }
        hash.addData(chunk);
    }
    if (hash.result().toHex() != m_signedUpdate.sha256) {
        return failWith(error, QStringLiteral("The verified update file hash changed."));
    }
    return true;
}

bool UpdateController::isTunnelDisconnected() const
{
    if (m_dependencies.tunnelDisconnected) {
        return m_dependencies.tunnelDisconnected();
    }
    return m_vpnConnection && m_vpnConnection->connectionState() == Vpn::ConnectionState::Disconnected;
}

bool UpdateController::launchInstaller(const QString &path)
{
    if (m_dependencies.installerLauncher) {
        return m_dependencies.installerLauncher(path);
    }
#if defined(Q_OS_WIN)
    return runWindowsInstaller(path) == 0;
#elif defined(Q_OS_ANDROID)
    Q_UNUSED(path)
    return false;
#else
    Q_UNUSED(path)
    return false;
#endif
}

void UpdateController::installUpdate()
{
    if (m_updateState != UpdateState::State::ReadyToInstall) {
        setStatusMessage(tr("Сначала загрузите и проверьте обновление."));
        return;
    }
    if (m_signedUpdate.expiresAt <= currentTimeUtc()) {
        QFile::remove(m_verifiedArtifactPath);
        m_verifiedArtifactPath.clear();
        m_signedUpdate = {};
        setStatusMessage(tr("Срок действия проверки истёк. Нажмите «Обновить», чтобы проверить ещё раз."));
        setUpdateState(UpdateState::State::Idle);
        return;
    }
#if !defined(Q_OS_ANDROID)
    if (!isTunnelDisconnected()) {
        setStatusMessage(tr("Перед установкой обновления отключите VPN."));
        return;
    }
#endif
    // Android's package installer asks for explicit confirmation and stops this
    // package during replacement. A failed/unknown VPN service must not prevent
    // the user from installing the update that repairs that very service.
    QString error;
    if (!verifyDownloadedFile(&error)) {
        QFile::remove(m_verifiedArtifactPath);
        m_verifiedArtifactPath.clear();
        setStatusMessage(tr("Файл обновления отсутствует или изменён. Загрузите его ещё раз."));
        setUpdateState(UpdateState::State::DownloadError);
        return;
    }

#if defined(Q_OS_ANDROID)
    if (m_dependencies.installerLauncher) {
        if (!m_dependencies.installerLauncher(m_verifiedArtifactPath)) {
            setStatusMessage(tr("Не удалось открыть системную установку Android."));
            setUpdateState(UpdateState::State::DownloadError);
            return;
        }
        setStatusMessage(tr("Подтвердите установку в системном окне Android."));
        return;
    }
    const int installResult = AndroidController::instance()->installUpdateApk(m_verifiedArtifactPath);
    if (installResult == AndroidController::UpdateInstallSettingsOpened) {
        setStatusMessage(tr("Разрешите установку приложения в настройках Android, затем нажмите «Установить обновление» ещё раз."));
    } else if (installResult == AndroidController::UpdateInstallInstallerOpened) {
        setStatusMessage(tr("Подтвердите установку в системном окне Android."));
    } else {
        setStatusMessage(tr("Не удалось открыть системную установку Android."));
        setUpdateState(UpdateState::State::DownloadError);
    }
#else
    if (!launchInstaller(m_verifiedArtifactPath)) {
        setStatusMessage(tr("Не удалось запустить установщик обновления."));
        setUpdateState(UpdateState::State::DownloadError);
        return;
    }
    setStatusMessage(tr("Установщик запущен. Подтвердите действие в Windows."));
#endif
}

void UpdateController::openStorePage() const
{
#if defined(Q_OS_IOS)
    QDesktopServices::openUrl(QUrl(QLatin1String(APP_IOS_STORE_URL_FALLBACK)));
#elif defined(MACOS_NE)
    QDesktopServices::openUrl(QUrl(QStringLiteral("https://apps.apple.com/app/id1600529900")));
#endif
}

QString UpdateController::composeDownloadUrl() const
{
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    if (m_downloadBaseUrl.isEmpty() || m_version.isEmpty()) {
        return QString();
    }
    const QString fileName = QString(kInstallerRemoteFileNamePattern).arg(m_version);
    return m_downloadBaseUrl + "/" + fileName;
#else
    return QString();
#endif
}

void UpdateController::downloadInstaller()
{
    if (m_signedFeedEnabled) {
        beginPackageDownload();
        return;
    }
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    if (m_updateState == UpdateState::State::Downloading) {
        return;
    }
    const QString downloadUrl = composeDownloadUrl();
    if (downloadUrl.isEmpty()) {
        setUpdateState(UpdateState::State::DownloadError);
        return;
    }
    setUpdateState(UpdateState::State::Downloading);
    QNetworkRequest request;
    request.setTransferTimeout(30000);
    request.setUrl(QUrl(downloadUrl));
    QNetworkReply *reply = amnApp->networkManager()->get(request);
    QObject::connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            setUpdateState(UpdateState::State::DownloadError);
            return;
        }
        QFile file(kInstallerLocalPath);
        if (!file.open(QIODevice::WriteOnly) || file.write(reply->readAll()) < 0) {
            setUpdateState(UpdateState::State::DownloadError);
            return;
        }
        file.close();
        setUpdateState(UpdateState::State::ReadyToInstall);
    });
#endif
}

#if defined(Q_OS_WIN)
int UpdateController::runWindowsInstaller(const QString &installerPath)
{
    qint64 pid = 0;
    const bool success = QProcess::startDetached(installerPath, QStringList(), QCoreApplication::applicationDirPath(), &pid);
    if (success) {
        logger.info() << "Mayak installer process started with PID:" << pid;
        return 0;
    }
    logger.error() << "Mayak installer process could not be started";
    return -1;
}
#endif

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
int UpdateController::runMacInstaller(const QString &installerPath)
{
    QTemporaryDir extractDir;
    extractDir.setAutoRemove(false);
    if (!extractDir.isValid()) {
        return -1;
    }
    const QString scriptPath = extractDir.path() + "/mac_installer.sh";
    QFile scriptFile(scriptPath);
    if (!scriptFile.open(QIODevice::WriteOnly)) {
        return -1;
    }
    const QString scriptContent = amnezia::scriptData(amnezia::ClientScriptType::mac_installer);
    if (scriptContent.isEmpty() || scriptFile.write(scriptContent.toUtf8()) < 0) {
        return -1;
    }
    scriptFile.close();
    QFile::setPermissions(scriptPath, QFile::permissions(scriptPath) | QFile::ExeUser);
    qint64 pid = 0;
    return QProcess::startDetached(QStringLiteral("/bin/bash"),
                                  QStringList() << scriptPath << extractDir.path() << installerPath,
                                  extractDir.path(), &pid) ? 0 : -1;
}
#endif

#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
int UpdateController::runLinuxInstaller(const QString &installerPath)
{
    QFile::setPermissions(installerPath, QFile::permissions(installerPath) | QFile::ExeUser);
    qint64 pid = 0;
    return QProcess::startDetached(installerPath, QStringList(), QString(), &pid) ? 0 : -1;
}
#endif
