#include "gatewayController.h"
#include "mayak_build.h"

#include <QDebug>
#include <QEventLoop>
#include <QFutureWatcher>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QThread>
#include <QHostInfo>
#include <QHostAddress>
#include <QAbstractSocket>
#include <QDeadlineTimer>
#include <QElapsedTimer>
#include <QTimer>
#include <QUrl>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <QtConcurrent/QtConcurrentRun>

#include "core/repositories/secureAppSettingsRepository.h"
#include "core/utils/constants/apiConstants.h"
#include "core/utils/constants/apiKeys.h"
#include "core/utils/api/apiUtils.h"

#ifdef AMNEZIA_DESKTOP
    #include "core/utils/ipcClient.h"
    #include "core/utils/networkUtilities.h"
#endif

#ifdef Q_OS_IOS
    #include "platforms/ios/ios_controller.h"
#endif

namespace
{
    namespace agwConfigKey
    {
        constexpr QLatin1String gatewayEndpoint("gateway_endpoint");
        constexpr QLatin1String publicKeyPem("public_key_pem");
        constexpr QLatin1String s3PrimaryEndpoints("s3_primary_endpoints");
        constexpr QLatin1String s3FallbackEndpoints("s3_fallback_endpoints");
        constexpr QLatin1String isDevEnvironment("is_dev_environment");
        constexpr QLatin1String requestTimeoutMsecs("request_timeout_msecs");
        constexpr QLatin1String proxyRequestTimeoutMsecs("proxy_request_timeout_msecs");
        constexpr QLatin1String proxyStorageTimeoutMsecs("proxy_storage_timeout_msecs");
        constexpr QLatin1String proxyHealthTimeoutMsecs("proxy_health_timeout_msecs");
    }

    namespace agwOptionsKey
    {
        constexpr QLatin1String serviceType("service_type");
        constexpr QLatin1String userCountryCode("user_country_code");
    }

    namespace agwStateKey
    {
        constexpr QLatin1String workingProxy("working_proxy");
    }

    constexpr QLatin1String agwStateCacheKey("agw_state");
    constexpr QLatin1String agwTracePrefix("agw trace:");
    constexpr QLatin1String agwTraceFailoverMarker("suspicious");
    constexpr QLatin1String endpointListSeparator(", ");
    constexpr QLatin1String legacyEndpointPlaceholder("%1");

    QStringList splitEndpoints(const char *raw)
    {
        return QString::fromUtf8(raw).split(endpointListSeparator, Qt::SkipEmptyParts);
    }

    void logAgwTrace(const QString &path, const int code, const QString &trace)
    {
        if (trace.isEmpty()) {
            return;
        }
        const QString text = QStringLiteral("%1 %2\n%3").arg(agwTracePrefix, path, trace).replace(QLatin1Char('\n'), QStringLiteral("\n    "));
        if (code != AGW_OK) {
            qWarning().noquote() << text;
        } else if (trace.contains(agwTraceFailoverMarker)) {
            qInfo().noquote() << text;
        } else {
            qDebug().noquote() << text;
        }
    }
}

GatewayController::GatewayController(const QString &gatewayEndpoint, const bool isDevEnvironment, const int requestTimeoutMsecs,
                                     const bool isStrictKillSwitchEnabled, SecureAppSettingsRepository *appSettingsRepository,
                                     QObject *parent)
    : QObject(parent),
      m_gatewayEndpoint(gatewayEndpoint),
      m_requestTimeoutMsecs(requestTimeoutMsecs),
      m_isStrictKillSwitchEnabled(isStrictKillSwitchEnabled),
      m_appSettingsRepository(appSettingsRepository)
{
    m_requestDeadline = QDeadlineTimer(qMax(0, m_requestTimeoutMsecs), Qt::PreciseTimer);
    // Маяк: ключ нашего шлюза вшит при сборке (mayak/mayak.cmake → mayak_build.h).
    const QByteArray publicKey = isDevEnvironment ? QByteArray(DEV_AGW_PUBLIC_KEY) : QByteArray(MAYAK_AGW_PUBLIC_KEY);
    m_publicKeyMissing = publicKey.isEmpty();

    QStringList primaryEndpoints;
    QStringList fallbackEndpoints;
    if (isDevEnvironment) {
        primaryEndpoints = splitEndpoints(DEV_S3_ENDPOINT);
    } else {
        primaryEndpoints = splitEndpoints(PROD_S3_ENDPOINT);
        fallbackEndpoints = splitEndpoints(FALLBACK_S3_ENDPOINT);
    }

    QJsonObject config;
    config[agwConfigKey::gatewayEndpoint] = gatewayEndpoint;
    config[agwConfigKey::publicKeyPem] = QString::fromUtf8(publicKey);
    config[agwConfigKey::s3PrimaryEndpoints] = QJsonArray::fromStringList(primaryEndpoints);
    config[agwConfigKey::s3FallbackEndpoints] = QJsonArray::fromStringList(fallbackEndpoints);
    config[agwConfigKey::isDevEnvironment] = isDevEnvironment;
    config[agwConfigKey::requestTimeoutMsecs] = requestTimeoutMsecs;
    config[agwConfigKey::proxyRequestTimeoutMsecs] = apiDefs::proxyRequestTimeoutMsecs;
    config[agwConfigKey::proxyStorageTimeoutMsecs] = apiDefs::proxyStorageTimeoutMsecs;
    config[agwConfigKey::proxyHealthTimeoutMsecs] = apiDefs::proxyHealthTimeoutMsecs;

    m_client = agw_client_create(QJsonDocument(config).toJson(QJsonDocument::Compact).constData(), nullptr);
    if (m_client == 0) {
        qCritical() << "GatewayController: failed to create gateway client (missing key or endpoint?)";
        return;
    }

    if (m_appSettingsRepository != nullptr) {
        const QByteArray state = m_appSettingsRepository->readGatewayProxyUrls(agwStateCacheKey);
        if (!state.isEmpty() && agw_import_state(m_client, state.constData()) == AGW_OK) {
            m_lastPersistedState = state;
        }
    }
}

GatewayController::~GatewayController()
{
    agw_client_destroy(m_client);
}

amnezia::ErrorCode GatewayController::post(const QString &endpoint, const QJsonObject apiPayload, QByteArray &responseBody)
{
    QFuture<QPair<amnezia::ErrorCode, QByteArray>> future = postAsync(endpoint, apiPayload);

    QFutureWatcher<QPair<amnezia::ErrorCode, QByteArray>> watcher;
    QEventLoop wait;
    connect(&watcher, &QFutureWatcherBase::finished, &wait, &QEventLoop::quit);
    watcher.setFuture(future);
    if (!future.isFinished()) {
        wait.exec(QEventLoop::ExcludeUserInputEvents);
    }

    const QPair<amnezia::ErrorCode, QByteArray> result = future.result();
    responseBody = result.second;
    return result.first;
}

QFuture<QPair<amnezia::ErrorCode, QByteArray>> GatewayController::postAsync(const QString &endpoint, const QJsonObject apiPayload)
{
    prepareRequest(m_requestTimeoutMsecs);
    return QtConcurrent::run(
            [this, endpoint, apiPayload]() -> QPair<amnezia::ErrorCode, QByteArray> { return executePost(endpoint, apiPayload); });
}

QFuture<GatewayPostResult> GatewayController::postAuthenticatedAsync(const QString &endpoint, const QJsonObject apiPayload)
{
#ifdef Q_OS_IOS
    // Preserve the platform permission prompt's owning-thread requirement; this
    // path is a fixed 10 ms legacy allowance, while desktop DNS/IPC stays async.
    IosController::Instance()->requestInetAccess();
    QThread::msleep(10);
#endif
    // DNS lookup and strict kill-switch IPC can block. Keep both off the caller/UI
    // thread; the gateway owner is retained by MayakAdmissionClient until completion.
    return QtConcurrent::run([this, endpoint, apiPayload]() {
        const QDeadlineTimer deadline = m_requestDeadline;
        const int remaining = static_cast<int>(deadline.remainingTime());
        if (remaining <= 0 || !prepareRequest(remaining, &deadline))
            return GatewayPostResult{amnezia::ErrorCode::ApiConfigTimeoutError, QByteArray(), false};
        return executePostDetailed(endpoint, apiPayload, 0, &deadline);
    });
}

QPair<amnezia::ErrorCode, QByteArray> GatewayController::executePost(const QString &endpoint, const QJsonObject &apiPayload)
{
    const GatewayPostResult result = executePostDetailed(endpoint, apiPayload);
    return qMakePair(result.error, result.body);
}

GatewayPostResult GatewayController::executePostDetailed(const QString &endpoint, const QJsonObject &apiPayload,
                                                          const int timeoutOverrideMsecs, const QDeadlineTimer *totalDeadline)
{
    if (m_client == 0) {
        return {m_publicKeyMissing ? amnezia::ErrorCode::ApiMissingAgwPublicKey : amnezia::ErrorCode::ApiConfigDownloadError,
                QByteArray(), false};
    }

    QString path = endpoint;
    path.remove(legacyEndpointPlaceholder);

    QJsonObject options;
    options[agwOptionsKey::serviceType] = apiPayload.value(apiDefs::key::serviceType).toString();
    options[agwOptionsKey::userCountryCode] = apiPayload.value(apiDefs::key::userCountryCode).toString();

    const QByteArray payload = QJsonDocument(apiPayload).toJson(QJsonDocument::Compact);
    const QByteArray optionsJson = QJsonDocument(options).toJson(QJsonDocument::Compact);
    const QByteArray pathBytes = path.toUtf8();

    // Serialization/preparation can consume the final budget too. Check at the
    // transport boundary and pass only the same absolute deadline's remainder.
    const int transportTimeout = totalDeadline ? static_cast<int>(totalDeadline->remainingTime()) : timeoutOverrideMsecs;
    if (totalDeadline && transportTimeout <= 0)
        return {amnezia::ErrorCode::ApiConfigTimeoutError, QByteArray(), false};
    // libagw's fifth argument is a cancellation HANDLE, never a millisecond value.
    // A separate timer enforces the remaining total budget without guessing a handle.
    const agw_cancel_handle cancel = transportTimeout > 0 ? agw_cancel_create() : 0;
    if (transportTimeout > 0 && cancel == 0)
        return {amnezia::ErrorCode::ApiConfigDownloadError, QByteArray(), false};
    std::mutex cancelMutex;
    std::condition_variable cancelWake;
    bool completed = false;
    std::thread deadlineThread;
    if (cancel != 0) {
        deadlineThread = std::thread([&] {
            std::unique_lock<std::mutex> lock(cancelMutex);
            if (!cancelWake.wait_for(lock, std::chrono::milliseconds(transportTimeout), [&] { return completed; }))
                agw_cancel_cancel(cancel);
        });
    }
    agw_result result = agw_post(m_client, pathBytes.constData(), payload.constData(), optionsJson.constData(), cancel);
    if (cancel != 0) {
        { std::lock_guard<std::mutex> lock(cancelMutex); completed = true; }
        cancelWake.notify_one();
        deadlineThread.join();
        agw_cancel_destroy(cancel);
    }

    QByteArray responseBody;
    if (result.body != nullptr) {
        responseBody = QByteArray(result.body, static_cast<qsizetype>(result.body_len));
    }
    QString trace;
    if (result.trace != nullptr) {
        trace = QString::fromUtf8(result.trace, static_cast<qsizetype>(result.trace_len));
    }
    const int code = result.code;
    agw_result_free(&result);

    logAgwTrace(path, code, trace);
    persistState();

    return {mapResultCode(code, responseBody), responseBody, code == AGW_OK};
}

amnezia::ErrorCode GatewayController::mapResultCode(const int code, const QByteArray &responseBody)
{
    switch (code) {
    case AGW_OK: return apiUtils::checkApiResponseErrors(responseBody);
    case AGW_CANCELLED:
    case AGW_ERR_TIMEOUT: return amnezia::ErrorCode::ApiConfigTimeoutError;
    case AGW_ERR_SSL: return amnezia::ErrorCode::ApiConfigSslError;
    case AGW_ERR_CONFIG: return amnezia::ErrorCode::ApiMissingAgwPublicKey;
    case AGW_ERR_DECRYPT: return amnezia::ErrorCode::ApiConfigDecryptionError;
    default: return amnezia::ErrorCode::ApiConfigDownloadError;
    }
}

bool GatewayController::prepareRequest(const int maxPreparationMsecs, const QDeadlineTimer *totalDeadline)
{
#ifdef AMNEZIA_DESKTOP
    if (!m_isStrictKillSwitchEnabled) {
        return true;
    }
    QStringList ips;
    const QDeadlineTimer deadline = totalDeadline ? *totalDeadline : QDeadlineTimer(maxPreparationMsecs);
    for (const QString &host : requestHosts()) {
        if (totalDeadline && deadline.hasExpired()) return false;
        QHostAddress address(host);
        if (address.protocol() != QAbstractSocket::UnknownNetworkLayerProtocol) {
            ips.append(host);
            continue;
        }
        QEventLoop loop;
        QString resolved;
        const auto lookupId = QHostInfo::lookupHost(host, &loop, [&](const QHostInfo &info) {
            if (!info.addresses().isEmpty()) resolved = info.addresses().first().toString();
            loop.quit();
        });
        if (resolved.isEmpty()) {
            const int remaining = qMax(0, static_cast<int>(deadline.remainingTime()));
            if (remaining == 0) {
                QHostInfo::abortHostLookup(lookupId);
                return false;
            }
            QTimer timer;
            timer.setSingleShot(true);
            connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
            timer.start(remaining);
            loop.exec();
        }
        if (resolved.isEmpty() || deadline.hasExpired()) {
            QHostInfo::abortHostLookup(lookupId);
            return false;
        }
        ips.append(resolved);
    }
    if (ips.isEmpty()) {
        return false;
    }
    bool allowed = false;
    const auto allowRanges = [&](QSharedPointer<IpcInterfaceReplica> iface) {
        // Source acquisition may have exhausted the budget. Never send a late command.
        if (totalDeadline && deadline.hasExpired()) return;
        QRemoteObjectPendingReply<bool> reply = iface->addKillSwitchAllowedRange(ips);
        const int remaining = qMax(0, static_cast<int>(deadline.remainingTime()));
        if (remaining == 0 || !reply.waitForFinished(totalDeadline ? remaining : qMin(1000, remaining)) || !reply.returnValue()) {
            qWarning() << "GatewayController::prepareRequest(): Failed to execute remote addKillSwitchAllowedRange call";
        } else {
            allowed = true;
        }
    };
    if (totalDeadline) IpcClient::withInterfaceUntil(deadline, allowRanges);
    else IpcClient::withInterface(allowRanges);
    return allowed && !deadline.hasExpired();
#else
    Q_UNUSED(maxPreparationMsecs);
    Q_UNUSED(totalDeadline);
    return true;
#endif
}

QStringList GatewayController::requestHosts() const
{
    QStringList hosts;
    if (m_client != 0) {
        char *state = agw_export_state(m_client);
        if (state != nullptr) {
            const QString workingProxy = QJsonDocument::fromJson(QByteArray(state)).object().value(agwStateKey::workingProxy).toString();
            agw_string_free(state);
            if (!workingProxy.isEmpty()) {
                hosts.append(QUrl(workingProxy).host());
            }
        }
    }
    hosts.append(QUrl(m_gatewayEndpoint).host());
    hosts.removeAll(QString());
    hosts.removeDuplicates();
    return hosts;
}

void GatewayController::persistState()
{
    if (m_client == 0 || m_appSettingsRepository == nullptr) {
        return;
    }
    char *state = agw_export_state(m_client);
    if (state == nullptr) {
        return;
    }
    const QByteArray blob(state);
    agw_string_free(state);

    if (blob != m_lastPersistedState) {
        m_appSettingsRepository->writeGatewayProxyUrls(agwStateCacheKey, blob);
        m_lastPersistedState = blob;
    }
}
