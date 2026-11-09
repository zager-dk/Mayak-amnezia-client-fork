#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSignalSpy>
#include <QSaveFile>
#include <QProcess>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTest>
#include <QTimer>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "core/controllers/updateController.h"
#include "ui/controllers/updateUiController.h"

namespace
{
    class FixtureReply final : public QNetworkReply
    {
    public:
        FixtureReply(const QNetworkRequest &request, QNetworkAccessManager::Operation operation, QByteArray bytes,
                     int status, int delayMs, bool redirect, QObject *parent)
            : QNetworkReply(parent), m_bytes(std::move(bytes))
        {
            setRequest(request);
            setUrl(request.url());
            setOperation(operation);
            setAttribute(QNetworkRequest::HttpStatusCodeAttribute, status);
            if (redirect) {
                const QUrl redirectUrl(QStringLiteral("https://evil.example/redirect"));
                setAttribute(QNetworkRequest::RedirectionTargetAttribute, redirectUrl);
                setRawHeader("Location", redirectUrl.toEncoded());
            }
            open(QIODevice::ReadOnly | QIODevice::Unbuffered);
            QTimer::singleShot(delayMs, this, [this]() {
                setFinished(true);
                emit readyRead();
                emit finished();
            });
        }
        void abort() override { setError(OperationCanceledError, QStringLiteral("cancelled")); }
        void failTransport() { setError(QNetworkReply::ConnectionRefusedError, QStringLiteral("fixture connection failure")); }
        qint64 bytesAvailable() const override { return m_bytes.size() - m_offset + QNetworkReply::bytesAvailable(); }
    protected:
        qint64 readData(char *data, qint64 maximum) override
        {
            const qint64 count = qMin(maximum, m_bytes.size() - m_offset);
            if (count <= 0) return -1;
            std::memcpy(data, m_bytes.constData() + m_offset, static_cast<size_t>(count));
            m_offset += count;
            return count;
        }
    private:
        QByteArray m_bytes;
        qint64 m_offset = 0;
    };

    class FixtureNetwork final : public QNetworkAccessManager
    {
    public:
        QByteArray manifest;
        QByteArray package;
        QByteArray packageResponse;
        int manifestStatus = 200;
        int packageStatus = 200;
        bool packageRedirect = false;
        bool manifestNetworkFailure = false;
        bool packageNetworkFailure = false;
        bool delayPackage = false;
        int manifestRequests = 0;
        int packageRequests = 0;
    protected:
        QNetworkReply *createRequest(Operation operation, const QNetworkRequest &request, QIODevice *) override
        {
            const bool isFeed = request.url().path().endsWith(QStringLiteral(".json"));
            isFeed ? ++manifestRequests : ++packageRequests;
            const QByteArray body = isFeed ? manifest : (packageResponse.isNull() ? package : packageResponse);
            auto *reply = new FixtureReply(request, operation, body, isFeed ? manifestStatus : packageStatus,
                                           isFeed ? 0 : (delayPackage ? 1000 : 0), !isFeed && packageRedirect, this);
            if ((isFeed && manifestNetworkFailure) || (!isFeed && packageNetworkFailure)) {
                reply->failTransport();
            }
            return reply;
        }
    };

    struct SigningFixture { QByteArray publicPem; QByteArray privatePem; EVP_PKEY *privateKey = nullptr; };

    SigningFixture makeSigningFixture()
    {
        SigningFixture fixture;
        EVP_PKEY_CTX *keyContext = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        if (!keyContext || EVP_PKEY_keygen_init(keyContext) <= 0
            || EVP_PKEY_keygen(keyContext, &fixture.privateKey) <= 0) {
            EVP_PKEY_CTX_free(keyContext);
            return fixture;
        }
        EVP_PKEY_CTX_free(keyContext);
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio || PEM_write_bio_PUBKEY(bio, fixture.privateKey) != 1) {
            BIO_free(bio);
            return fixture;
        }
        char *data = nullptr;
        const long length = BIO_get_mem_data(bio, &data);
        fixture.publicPem = QByteArray(data, static_cast<qsizetype>(length));
        BIO_free(bio);
        bio = BIO_new(BIO_s_mem());
        if (!bio || PEM_write_bio_PrivateKey(bio, fixture.privateKey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            BIO_free(bio);
            return fixture;
        }
        data = nullptr;
        const long privateLength = BIO_get_mem_data(bio, &data);
        fixture.privatePem = QByteArray(data, static_cast<qsizetype>(privateLength));
        BIO_free(bio);
        return fixture;
    }

    QByteArray makeEnvelopeForPayload(EVP_PKEY *key, const QByteArray &payloadBytes)
    {
        unsigned char signature[64] = {};
        size_t signatureSize = sizeof(signature);
        EVP_MD_CTX *context = EVP_MD_CTX_new();
        const bool signedOk = context && EVP_DigestSignInit(context, nullptr, nullptr, nullptr, key) == 1
            && EVP_DigestSign(context, signature, &signatureSize,
                              reinterpret_cast<const unsigned char *>(payloadBytes.constData()),
                              static_cast<size_t>(payloadBytes.size())) == 1;
        EVP_MD_CTX_free(context);
        if (!signedOk) return {};
        QJsonObject envelope {{"schema", 1}, {"alg", "Ed25519"},
                              {"payload", QString::fromLatin1(payloadBytes.toBase64())},
                              {"signature", QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(signature),
                                                                            static_cast<qsizetype>(signatureSize)).toBase64())}};
        return QJsonDocument(envelope).toJson(QJsonDocument::Compact);
    }

    QByteArray makeEnvelope(EVP_PKEY *key, const QByteArray &package)
    {
        const QByteArray now = QDateTime::currentDateTimeUtc().toString(Qt::ISODate).toLatin1();
        const QByteArray expires = QDateTime::currentDateTimeUtc().addDays(1).toString(Qt::ISODate).toLatin1();
        QJsonObject payload {
            {"product", "mayak-vpn"}, {"channel", "stable"}, {"platform", "windows-x64"},
            {"version", "5.1.0.5"}, {"versionCode", 2187},
            {"url", "https://mayaklight.ru/updates/packages/mayak-5.1.0.5.exe"},
            {"size", package.size()}, {"sha256", QString::fromLatin1(QCryptographicHash::hash(package, QCryptographicHash::Sha256).toHex())},
            {"publishedAt", QString::fromLatin1(now)}, {"expiresAt", QString::fromLatin1(expires)},
            {"releaseNotes", "Fixture release"}
        };
        return makeEnvelopeForPayload(key, QJsonDocument(payload).toJson(QJsonDocument::Compact));
    }
}

class UpdateControllerTest final : public QObject
{
    Q_OBJECT
private slots:
    void manualCheckOriginIsTaggedAndConcurrentChecksCannotStealIt()
    {
        SigningFixture signing = makeSigningFixture();
        QVERIFY(signing.privateKey);
        QTemporaryDir cache(QDir::currentPath() + QStringLiteral("/update-ui-origin-XXXXXX"));
        QVERIFY(cache.isValid());
        FixtureNetwork network;
        network.package = QByteArray("fixture installer bytes");
        network.manifest = makeEnvelope(signing.privateKey, network.package);
        QVERIFY(!network.manifest.isEmpty());

        UpdateControllerDependencies dependencies;
        dependencies.networkAccessManager = &network;
        dependencies.signingPublicKeyPem = signing.publicPem;
        dependencies.manifestUrl = QUrl(QStringLiteral("https://mayaklight.ru/updates/stable/windows-x64.json"));
        dependencies.platform = QStringLiteral("windows-x64");
        dependencies.installedVersion = QStringLiteral("5.1.0.4");
        dependencies.installedVersionCode = 2186;
        dependencies.cacheDirectory = cache.path();
        dependencies.tunnelDisconnected = []() { return true; };
        dependencies.installerLauncher = [](const QString &) { return false; };
        dependencies.automaticChecksEnabled = true;
        dependencies.checkOnConstruction = false;
        UpdateController controller(nullptr, dependencies);
        UpdateUiController uiController(&controller);

        QStringList signalOrder;
        connect(&uiController, &UpdateUiController::manualCheckStarted, &uiController,
                [&signalOrder]() { signalOrder.append(QStringLiteral("manual")); });
        connect(&uiController, &UpdateUiController::updateFound, &uiController,
                [&signalOrder]() { signalOrder.append(QStringLiteral("found")); });
        QSignalSpy manualSpy(&uiController, &UpdateUiController::manualCheckStarted);
        QSignalSpy foundSpy(&uiController, &UpdateUiController::updateFound);

        controller.checkForUpdatesAutomatically();
        QVERIFY(controller.isUpdateCheckRunning());
        uiController.checkForUpdates(); // A manual request during an automatic check must not claim its result.
        QCOMPARE(manualSpy.count(), 0);
        QTRY_COMPARE_WITH_TIMEOUT(foundSpy.count(), 1, 2000);
        QCOMPARE(signalOrder, QStringList{QStringLiteral("found")});

        uiController.checkForUpdates();
        QCOMPARE(manualSpy.count(), 1);
        QVERIFY(controller.isUpdateCheckRunning());
        uiController.checkForUpdates(); // Repeated clicks cannot start a parallel check or duplicate the origin marker.
        QCOMPARE(manualSpy.count(), 1);
        controller.checkForUpdatesAutomatically();
        QCOMPARE(manualSpy.count(), 1);
        QTRY_COMPARE_WITH_TIMEOUT(foundSpy.count(), 2, 2000);
        QCOMPARE(signalOrder, (QStringList{QStringLiteral("found"), QStringLiteral("manual"), QStringLiteral("found")}));
        QCOMPARE(network.manifestRequests, 2);
        QCOMPARE(network.packageRequests, 0);
        EVP_PKEY_free(signing.privateKey);
    }

    void signedFeedDownloadAndInstallRequireExplicitActionAndIdleTunnel()
    {
        SigningFixture signing = makeSigningFixture();
        QVERIFY(signing.privateKey);
        QTemporaryDir cache(QDir::currentPath() + QStringLiteral("/update-controller-XXXXXX"));
        QVERIFY(cache.isValid());
        QSaveFile probe(cache.filePath(QStringLiteral("probe.tmp")));
        QVERIFY2(probe.open(QIODevice::WriteOnly), qPrintable(probe.errorString()));
        QCOMPARE(probe.write("probe"), qint64(5));
        QVERIFY(probe.commit());
        FixtureNetwork network;
        network.package = QByteArray("fixture installer bytes");
        network.manifest = makeEnvelope(signing.privateKey, network.package);
        QVERIFY(!network.manifest.isEmpty());

        bool tunnelDisconnected = false;
        int installerCalls = 0;
        QString installedPath;
        UpdateControllerDependencies dependencies;
        dependencies.networkAccessManager = &network;
        dependencies.signingPublicKeyPem = signing.publicPem;
        dependencies.manifestUrl = QUrl(QStringLiteral("https://mayaklight.ru/updates/stable/windows-x64.json"));
        dependencies.platform = QStringLiteral("windows-x64");
        dependencies.installedVersion = QStringLiteral("5.1.0.4");
        dependencies.installedVersionCode = 2186;
        dependencies.cacheDirectory = cache.path();
        dependencies.tunnelDisconnected = [&]() { return tunnelDisconnected; };
        dependencies.installerLauncher = [&](const QString &path) { ++installerCalls; installedPath = path; return true; };
        dependencies.automaticChecksEnabled = false;
        dependencies.checkOnConstruction = false;
        UpdateController controller(nullptr, dependencies);
        QSignalSpy foundSpy(&controller, &UpdateController::updateFound);
        controller.checkForUpdates();
        QTRY_COMPARE_WITH_TIMEOUT(foundSpy.count(), 1, 2000);
        QCOMPARE(controller.getVersion(), QStringLiteral("5.1.0.5"));

        QCOMPARE(installerCalls, 0); // Checking never starts an installer.
        network.packageResponse = network.package.left(2);
        controller.startUpdate();
        QTRY_COMPARE_WITH_TIMEOUT(controller.getUpdateState(), UpdateState::State::DownloadError, 2000);
        QVERIFY(QDir(cache.path()).entryList({QStringLiteral("*.exe")}, QDir::Files).isEmpty());

        network.packageResponse = QByteArray();
        network.delayPackage = true;
        controller.startUpdate();
        QCOMPARE(controller.getUpdateState(), UpdateState::State::Downloading);
        controller.cancelUpdate();
        QCOMPARE(controller.getUpdateState(), UpdateState::State::Idle);
        network.delayPackage = false;
        controller.startUpdate();
        QTRY_COMPARE_WITH_TIMEOUT(controller.getUpdateState(), UpdateState::State::ReadyToInstall, 2000);
        QVERIFY(!QDir(cache.path()).entryList({QStringLiteral("*.exe")}, QDir::Files).isEmpty());
        QCOMPARE(installerCalls, 0); // A verified download still waits for the Install button.

        controller.installUpdate();
        QCOMPARE(installerCalls, 0);
        QVERIFY(controller.getStatusMessage().contains(QStringLiteral("отключите VPN")));

        const QString cachedArtifact = QDir(cache.path()).absoluteFilePath(
            QDir(cache.path()).entryList({QStringLiteral("*.exe")}, QDir::Files).constFirst());
        QFile tampered(cachedArtifact);
        QVERIFY(tampered.open(QIODevice::WriteOnly | QIODevice::Truncate));
        QCOMPARE(tampered.write("tampered"), qint64(8));
        tampered.close();
        controller.installUpdate();
        QCOMPARE(installerCalls, 0);
        tunnelDisconnected = true;
        controller.installUpdate();
        QCOMPARE(installerCalls, 0);
        QCOMPARE(controller.getUpdateState(), UpdateState::State::DownloadError);

        controller.startUpdate();
        QTRY_COMPARE_WITH_TIMEOUT(controller.getUpdateState(), UpdateState::State::ReadyToInstall, 2000);
        controller.installUpdate();
        QCOMPARE(installerCalls, 1);
        QVERIFY(QFileInfo::exists(installedPath));
        EVP_PKEY_free(signing.privateKey);
    }

    void rejectsTamperedSignatureAndRedirects()
    {
        SigningFixture signing = makeSigningFixture();
        QVERIFY(signing.privateKey);
        const QByteArray package("x");
        QByteArray envelope = makeEnvelope(signing.privateKey, package);
        QJsonObject object = QJsonDocument::fromJson(envelope).object();
        QByteArray signature = QByteArray::fromBase64(object.value("signature").toString().toLatin1());
        signature[0] = static_cast<char>(signature[0] ^ 0x01);
        object.insert("signature", QString::fromLatin1(signature.toBase64()));
        SignedUpdateManifest manifest;
        QString error;
        const QUrl feed(QStringLiteral("https://mayaklight.ru/updates/stable/windows-x64.json"));
        QVERIFY(!UpdateController::verifySignedManifest(QJsonDocument(object).toJson(QJsonDocument::Compact),
                                                        signing.publicPem, QStringLiteral("windows-x64"),
                                                        QStringLiteral("5.1.0.4"), 0, feed,
                                                        QDateTime::currentDateTimeUtc(), &manifest, &error));
        QVERIFY(!error.isEmpty());
        QVERIFY(!UpdateController::isAllowedPackageUrl(QUrl(QStringLiteral("https://evil.example/updates/packages/x.exe")), feed, &error));
        EVP_PKEY_free(signing.privateKey);
    }

    void rejectsSignedButInvalidMetadata()
    {
        SigningFixture signing = makeSigningFixture();
        QVERIFY(signing.privateKey);
        const QUrl feed(QStringLiteral("https://mayaklight.ru/updates/stable/windows-x64.json"));
        const QByteArray original = makeEnvelope(signing.privateKey, QByteArray("artifact"));
        const QByteArray payloadBytes = QByteArray::fromBase64(
            QJsonDocument::fromJson(original).object().value("payload").toString().toLatin1());
        const QJsonObject validPayload = QJsonDocument::fromJson(payloadBytes).object();
        const QList<QPair<QString, QJsonValue>> mutations = {
            {QStringLiteral("product"), QStringLiteral("other-product")},
            {QStringLiteral("platform"), QStringLiteral("android-arm64")},
            {QStringLiteral("channel"), QStringLiteral("beta")},
            {QStringLiteral("version"), QStringLiteral("5.1.0.4")},
            {QStringLiteral("version"), QStringLiteral("05.1.0.5")},
            {QStringLiteral("version"), QStringLiteral("5.1.65536.0")},
            {QStringLiteral("version"), QStringLiteral("6.99999.0.0")},
            {QStringLiteral("version"), QStringLiteral("5.2.99999.0")},
            {QStringLiteral("expiresAt"), QStringLiteral("2020-01-01T00:00:00Z")},
            {QStringLiteral("sha256"), QStringLiteral("not-a-hash")},
            {QStringLiteral("url"), QStringLiteral("https://evil.example/updates/packages/file.exe")},
            {QStringLiteral("size"), 0}
        };
        for (const auto &mutation : mutations) {
            QJsonObject changed = validPayload;
            changed.insert(mutation.first, mutation.second);
            const QByteArray envelope = makeEnvelopeForPayload(signing.privateKey,
                QJsonDocument(changed).toJson(QJsonDocument::Compact));
            SignedUpdateManifest result;
            QString error;
            QVERIFY2(!UpdateController::verifySignedManifest(envelope, signing.publicPem,
                QStringLiteral("windows-x64"), QStringLiteral("5.1.0.4"), 0, feed,
                QDateTime::currentDateTimeUtc(), &result, &error), qPrintable(mutation.first + QStringLiteral(": ") + error));
        }

        SignedUpdateManifest ignored;
        QString error;
        QVERIFY(!UpdateController::verifySignedManifest(original, signing.publicPem,
            QStringLiteral("windows-x64"), QStringLiteral("5.2.99999.0"), 0, feed,
            QDateTime::currentDateTimeUtc(), &ignored, &error));

        QVERIFY(!UpdateController::verifySignedManifest(QByteArray(128 * 1024 + 1, 'x'), signing.publicPem,
            QStringLiteral("windows-x64"), QStringLiteral("5.1.0.4"), 0, feed,
            QDateTime::currentDateTimeUtc(), &ignored, &error));
        EVP_PKEY_free(signing.privateKey);
    }

    void androidRequiresIncreasingVersionCode()
    {
        SigningFixture signing = makeSigningFixture();
        QVERIFY(signing.privateKey);
        QJsonObject payload {
            {"product", "mayak-vpn"}, {"channel", "stable"}, {"platform", "android-arm64"},
            {"version", "5.1.0.5"}, {"versionCode", 2186},
            {"url", "https://mayaklight.ru/updates/packages/mayak-5.1.0.5.apk"},
            {"size", 1}, {"sha256", QString(64, QLatin1Char('a'))},
            {"publishedAt", QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},
            {"expiresAt", QDateTime::currentDateTimeUtc().addDays(1).toString(Qt::ISODate)}
        };
        const QUrl feed(QStringLiteral("https://mayaklight.ru/updates/stable/android-arm64.json"));
        SignedUpdateManifest parsed;
        QString error;
        QByteArray envelope = makeEnvelopeForPayload(signing.privateKey,
            QJsonDocument(payload).toJson(QJsonDocument::Compact));
        QVERIFY(!UpdateController::verifySignedManifest(envelope, signing.publicPem,
            QStringLiteral("android-arm64"), QStringLiteral("5.1.0.4"), 2186, feed,
            QDateTime::currentDateTimeUtc(), &parsed, &error));

        payload.insert(QStringLiteral("versionCode"), 2187);
        envelope = makeEnvelopeForPayload(signing.privateKey, QJsonDocument(payload).toJson(QJsonDocument::Compact));
        QVERIFY2(UpdateController::verifySignedManifest(envelope, signing.publicPem,
            QStringLiteral("android-arm64"), QStringLiteral("5.1.0.4"), 2186, feed,
            QDateTime::currentDateTimeUtc(), &parsed, &error), qPrintable(error));
        QCOMPARE(parsed.versionCode, quint64(2187));
        EVP_PKEY_free(signing.privateKey);
    }

    void controllerRejectsManifestHttpAndNetworkFailures()
    {
        SigningFixture signing = makeSigningFixture();
        QVERIFY(signing.privateKey);
        for (int failure = 0; failure < 2; ++failure) {
            FixtureNetwork network;
            network.manifest = makeEnvelope(signing.privateKey, QByteArray("fixture"));
            network.manifestStatus = failure == 0 ? 404 : 200;
            network.manifestNetworkFailure = failure == 1;
            QTemporaryDir cache(QDir::currentPath() + QStringLiteral("/update-manifest-failure-XXXXXX"));
            UpdateControllerDependencies dependencies;
            dependencies.networkAccessManager = &network;
            dependencies.signingPublicKeyPem = signing.publicPem;
            dependencies.manifestUrl = QUrl(QStringLiteral("https://mayaklight.ru/updates/stable/windows-x64.json"));
            dependencies.platform = QStringLiteral("windows-x64");
            dependencies.installedVersion = QStringLiteral("5.1.0.4");
            dependencies.cacheDirectory = cache.path();
            dependencies.automaticChecksEnabled = false;
            dependencies.checkOnConstruction = false;
            UpdateController controller(nullptr, dependencies);
            QSignalSpy failedSpy(&controller, &UpdateController::updateCheckFailed);
            controller.checkForUpdates();
            QTRY_COMPARE_WITH_TIMEOUT(failedSpy.count(), 1, 2000);
            QCOMPARE(controller.getUpdateState(), UpdateState::State::Idle);
            QCOMPARE(network.manifestRequests, 1);
        }
        EVP_PKEY_free(signing.privateKey);
    }

    void controllerRejectsPackageRedirectHashOversizeAndPartial()
    {
        SigningFixture signing = makeSigningFixture();
        QVERIFY(signing.privateKey);
        const QByteArray package("verified fixture package");
        for (int failure = 0; failure < 4; ++failure) {
            FixtureNetwork network;
            network.package = package;
            network.packageRedirect = failure == 0;
            if (failure == 1) network.packageResponse = QByteArray("tampered fixture");
            if (failure == 2) network.packageResponse = package + QByteArray("oversize");
            if (failure == 3) network.packageResponse = package.left(4);
            QByteArray envelope = makeEnvelope(signing.privateKey, package);
            if (failure == 1) {
                QJsonObject envelopeObject = QJsonDocument::fromJson(envelope).object();
                QJsonObject payload = QJsonDocument::fromJson(QByteArray::fromBase64(
                    envelopeObject.value(QStringLiteral("payload")).toString().toLatin1())).object();
                payload.insert(QStringLiteral("sha256"), QString(64, QLatin1Char('0')));
                envelope = makeEnvelopeForPayload(signing.privateKey, QJsonDocument(payload).toJson(QJsonDocument::Compact));
            }
            network.manifest = envelope;
            QTemporaryDir cache(QDir::currentPath() + QStringLiteral("/update-package-failure-XXXXXX"));
            UpdateControllerDependencies dependencies;
            dependencies.networkAccessManager = &network;
            dependencies.signingPublicKeyPem = signing.publicPem;
            dependencies.manifestUrl = QUrl(QStringLiteral("https://mayaklight.ru/updates/stable/windows-x64.json"));
            dependencies.platform = QStringLiteral("windows-x64");
            dependencies.installedVersion = QStringLiteral("5.1.0.4");
            dependencies.cacheDirectory = cache.path();
            dependencies.automaticChecksEnabled = false;
            dependencies.checkOnConstruction = false;
            UpdateController controller(nullptr, dependencies);
            QSignalSpy foundSpy(&controller, &UpdateController::updateFound);
            controller.checkForUpdates();
            QTRY_COMPARE_WITH_TIMEOUT(foundSpy.count(), 1, 2000);
            controller.startUpdate();
            QTRY_COMPARE_WITH_TIMEOUT(controller.getUpdateState(), UpdateState::State::DownloadError, 2000);
            QCOMPARE(network.packageRequests, 1);
            QVERIFY(QDir(cache.path()).entryList(QDir::Files | QDir::NoDotAndDotDot).isEmpty());
        }
        EVP_PKEY_free(signing.privateKey);
    }

    void controllerRejectsPackageUrlVariants()
    {
        SigningFixture signing = makeSigningFixture();
        QVERIFY(signing.privateKey);
        const QUrl feed(QStringLiteral("https://mayaklight.ru/updates/stable/windows-x64.json"));
        const QStringList invalidUrls = {
            QStringLiteral("http://mayaklight.ru/updates/packages/a.exe"),
            QStringLiteral("https://evil.example/updates/packages/a.exe"),
            QStringLiteral("https://mayaklight.ru/updates/packages/../a.exe"),
            QStringLiteral("https://mayaklight.ru/updates/packages//a.exe"),
            QStringLiteral("https://mayaklight.ru/updates/packages/a.exe?x=1"),
            QStringLiteral("https://user@mayaklight.ru/updates/packages/a.exe"),
            QStringLiteral("https://mayaklight.ru:444/updates/packages/a.exe")
        };
        for (const QString &url : invalidUrls) {
            FixtureNetwork network;
            QByteArray envelope = makeEnvelope(signing.privateKey, QByteArray("fixture"));
            QJsonObject envelopeObject = QJsonDocument::fromJson(envelope).object();
            QJsonObject payload = QJsonDocument::fromJson(QByteArray::fromBase64(
                envelopeObject.value(QStringLiteral("payload")).toString().toLatin1())).object();
            payload.insert(QStringLiteral("url"), url);
            network.manifest = makeEnvelopeForPayload(signing.privateKey, QJsonDocument(payload).toJson(QJsonDocument::Compact));
            QTemporaryDir cache(QDir::currentPath() + QStringLiteral("/update-url-rejection-XXXXXX"));
            UpdateControllerDependencies dependencies;
            dependencies.networkAccessManager = &network;
            dependencies.signingPublicKeyPem = signing.publicPem;
            dependencies.manifestUrl = feed;
            dependencies.platform = QStringLiteral("windows-x64");
            dependencies.installedVersion = QStringLiteral("5.1.0.4");
            dependencies.cacheDirectory = cache.path();
            dependencies.automaticChecksEnabled = false;
            dependencies.checkOnConstruction = false;
            UpdateController controller(nullptr, dependencies);
            QSignalSpy failedSpy(&controller, &UpdateController::updateCheckFailed);
            controller.checkForUpdates();
            QTRY_COMPARE_WITH_TIMEOUT(failedSpy.count(), 1, 2000);
            QCOMPARE(network.packageRequests, 0);
        }
        EVP_PKEY_free(signing.privateKey);
    }

    void controllerRechecksExpiryForDownloadAndInstallAndDeduplicates()
    {
        SigningFixture signing = makeSigningFixture();
        QVERIFY(signing.privateKey);
        QDateTime now = QDateTime::currentDateTimeUtc();
        const QByteArray package("fixture");
        FixtureNetwork network;
        network.package = package;
        QJsonObject payload = QJsonDocument::fromJson(QByteArray::fromBase64(
            QJsonDocument::fromJson(makeEnvelope(signing.privateKey, package)).object()
                .value(QStringLiteral("payload")).toString().toLatin1())).object();
        payload.insert(QStringLiteral("publishedAt"), now.addSecs(-1).toString(Qt::ISODate));
        payload.insert(QStringLiteral("expiresAt"), now.addSecs(3).toString(Qt::ISODate));
        network.manifest = makeEnvelopeForPayload(signing.privateKey, QJsonDocument(payload).toJson(QJsonDocument::Compact));
        network.delayPackage = true;
        QTemporaryDir cache(QDir::currentPath() + QStringLiteral("/update-expiry-XXXXXX"));
        UpdateControllerDependencies dependencies;
        dependencies.networkAccessManager = &network;
        dependencies.signingPublicKeyPem = signing.publicPem;
        dependencies.manifestUrl = QUrl(QStringLiteral("https://mayaklight.ru/updates/stable/windows-x64.json"));
        dependencies.platform = QStringLiteral("windows-x64");
        dependencies.installedVersion = QStringLiteral("5.1.0.4");
        dependencies.cacheDirectory = cache.path();
        dependencies.nowUtc = [&now]() { return now; };
        dependencies.automaticChecksEnabled = false;
        dependencies.checkOnConstruction = false;
        UpdateController controller(nullptr, dependencies);
        QSignalSpy foundSpy(&controller, &UpdateController::updateFound);
        controller.checkForUpdates();
        QTRY_COMPARE_WITH_TIMEOUT(foundSpy.count(), 1, 2000);
        now = now.addSecs(4);
        controller.startUpdate();
        QCOMPARE(controller.getUpdateState(), UpdateState::State::Idle);
        QVERIFY(controller.getStatusMessage().contains(QStringLiteral("Срок действия проверки истёк")));
        QCOMPARE(network.packageRequests, 0);

        // Acquire another unexpired manifest and make sure repeated starts share one in-flight download.
        now = QDateTime::currentDateTimeUtc();
        payload.insert(QStringLiteral("publishedAt"), now.addSecs(-1).toString(Qt::ISODate));
        payload.insert(QStringLiteral("expiresAt"), now.addSecs(30).toString(Qt::ISODate));
        network.manifest = makeEnvelopeForPayload(signing.privateKey, QJsonDocument(payload).toJson(QJsonDocument::Compact));
        controller.checkForUpdates();
        QTRY_COMPARE_WITH_TIMEOUT(foundSpy.count(), 2, 2000);
        network.delayPackage = false;
        controller.startUpdate();
        controller.startUpdate();
        QCOMPARE(network.packageRequests, 1);
        QTRY_COMPARE_WITH_TIMEOUT(controller.getUpdateState(), UpdateState::State::ReadyToInstall, 2000);
        now = now.addSecs(31);
        controller.installUpdate();
        QCOMPARE(controller.getUpdateState(), UpdateState::State::Idle);
        QVERIFY(controller.getStatusMessage().contains(QStringLiteral("Срок действия проверки истёк")));
        QCOMPARE(QDir(cache.path()).entryList(QDir::Files | QDir::NoDotAndDotDot).size(), 0);
        EVP_PKEY_free(signing.privateKey);
    }

    void rejectsRedirectResponseWithoutFollowingIt()
    {
        SigningFixture signing = makeSigningFixture();
        QVERIFY(signing.privateKey);
        FixtureNetwork network;
        network.manifest = makeEnvelope(signing.privateKey, QByteArray("artifact"));
        network.manifestStatus = 302;
        QTemporaryDir cache(QDir::currentPath() + QStringLiteral("/update-redirect-XXXXXX"));
        UpdateControllerDependencies dependencies;
        dependencies.networkAccessManager = &network;
        dependencies.signingPublicKeyPem = signing.publicPem;
        dependencies.manifestUrl = QUrl(QStringLiteral("https://mayaklight.ru/updates/stable/windows-x64.json"));
        dependencies.platform = QStringLiteral("windows-x64");
        dependencies.installedVersion = QStringLiteral("5.1.0.4");
        dependencies.cacheDirectory = cache.path();
        dependencies.automaticChecksEnabled = false;
        dependencies.checkOnConstruction = false;
        UpdateController controller(nullptr, dependencies);
        QSignalSpy failedSpy(&controller, &UpdateController::updateCheckFailed);
        controller.checkForUpdates();
        QTRY_COMPARE_WITH_TIMEOUT(failedSpy.count(), 1, 2000);
        QCOMPARE(controller.getUpdateState(), UpdateState::State::Idle);
        EVP_PKEY_free(signing.privateKey);
    }

    void releaseHelperOutputPassesProductionVerifier()
    {
        SigningFixture signing = makeSigningFixture();
        QVERIFY(signing.privateKey);
        QVERIFY(!signing.privatePem.isEmpty());
        QTemporaryDir fixtureDir(QDir::currentPath() + QStringLiteral("/update-release-helper-XXXXXX"));
        QVERIFY(fixtureDir.isValid());
        const QString artifactPath = fixtureDir.filePath(QStringLiteral("fixture.exe"));
        const QString privateKeyPath = fixtureDir.filePath(QStringLiteral("fixture-private.pem"));
        const QString manifestPath = fixtureDir.filePath(QStringLiteral("windows-x64.json"));
        QFile artifact(artifactPath);
        QVERIFY(artifact.open(QIODevice::WriteOnly));
        QCOMPARE(artifact.write("release fixture"), qint64(15));
        artifact.close();
        QFile keyFile(privateKeyPath);
        QVERIFY(keyFile.open(QIODevice::WriteOnly));
        QCOMPARE(keyFile.write(signing.privatePem), signing.privatePem.size());
        keyFile.close();

        const QString python = QStandardPaths::findExecutable(QStringLiteral("python"));
        QVERIFY2(!python.isEmpty(), "Python executable not found in the test environment");
        QProcess helper;
        helper.start(python, {
            QStringLiteral(MAYAK_SOURCE_DIR) + QStringLiteral("/mayak/tools/sign_update_manifest.py"),
            QStringLiteral("--artifact"), artifactPath,
            QStringLiteral("--platform"), QStringLiteral("windows-x64"),
            QStringLiteral("--version"), QStringLiteral("5.1.0.5"),
            QStringLiteral("--version-code"), QStringLiteral("2187"),
            QStringLiteral("--expires-at"), QDateTime::currentDateTimeUtc().addDays(1).toString(QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")),
            QStringLiteral("--url"), QStringLiteral("https://mayaklight.ru/updates/packages/fixture.exe"),
            QStringLiteral("--private-key"), privateKeyPath,
            QStringLiteral("--output"), manifestPath,
            QStringLiteral("--release-notes"), QStringLiteral("Fixture notes")
        });
        QVERIFY(helper.waitForStarted(5000));
        QVERIFY2(helper.waitForFinished(15000), qPrintable(QString::fromUtf8(helper.readAllStandardError())));
        QCOMPARE(helper.exitStatus(), QProcess::NormalExit);
        QVERIFY2(helper.exitCode() == 0, qPrintable(QStringLiteral("helper exit=%1 stdout=%2 stderr=%3")
            .arg(helper.exitCode())
            .arg(QString::fromLatin1(helper.readAllStandardOutput().toBase64()))
            .arg(QString::fromLatin1(helper.readAllStandardError().toBase64()))));
        QFile manifestFile(manifestPath);
        QVERIFY(manifestFile.open(QIODevice::ReadOnly));
        SignedUpdateManifest manifest;
        QString error;
        const QUrl feed(QStringLiteral("https://mayaklight.ru/updates/stable/windows-x64.json"));
        QVERIFY2(UpdateController::verifySignedManifest(manifestFile.readAll(), signing.publicPem,
                                                        QStringLiteral("windows-x64"), QStringLiteral("5.1.0.4"),
                                                        2186, feed, QDateTime::currentDateTimeUtc(),
                                                        &manifest, &error), qPrintable(error));
        QCOMPARE(manifest.version, QStringLiteral("5.1.0.5"));
        EVP_PKEY_free(signing.privateKey);
    }
};

QTEST_GUILESS_MAIN(UpdateControllerTest)
#include "testUpdateController.moc"
