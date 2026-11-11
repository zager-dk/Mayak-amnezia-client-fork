#include "mayakAutoConnectRuntime.h"
#include "mayakAutoConnectCoordinator.h"
#include "mayakAttemptStore.h"
#include "api/mayakAdmissionClient.h"
#include "api/subscriptionController.h"
#include "connectionController.h"
#include "core/repositories/secureAppSettingsRepository.h"
#include "core/repositories/secureServersRepository.h"
#include "core/utils/api/gatewayPayloadBuilder.h"
#include "core/utils/constants/apiKeys.h"
#include <algorithm>
#include <QCryptographicHash>
#include <QCoreApplication>
#include <QDebug>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QThread>
#include <QDateTime>
#include <QFutureWatcher>
#include <QPromise>
#include <QJsonDocument>
#include <QTimer>
#include <QUrl>
#include <QJsonArray>
#include <QNetworkInterface>
#include <QTcpServer>
#include "core/utils/mayakTunnelProbe.h"
#include "mayakForeignVpn.h"
#include "secureQSettings.h"
#include <map>

namespace ac = mayak::autoconnect;
namespace ad = mayak::admission;
namespace at = mayak::attempts;
using B = MayakBackendBridge;
using amnezia::ErrorCode;
namespace {
QString randomId() { return B::randomRequestId(); }
MayakAutoConnectRuntime::RecoveryTiming& recoveryTimingStorage() {
    static MayakAutoConnectRuntime::RecoveryTiming timing;
    return timing;
}
// Failover memory for the app process (every connect is a new Session): an exit that stopped
// working, or never answered a handshake while connecting, is tried last for a while.
struct AvoidedExit { QString candidateId; qint64 until = 0; int knownExits = 0; };
AvoidedExit& avoidedExitStorage() { static AvoidedExit avoided; return avoided; }
// Local adapter failure retries survive the automatic session restart below (bounded across
// sessions); a user-started connect or a confirmed connection resets them.
struct LocalStartRetries { int count = 0; bool autoRestart = false; };
LocalStartRetries& localStartRetriesStorage() { static LocalStartRetries retries; return retries; }
constexpr qint64 kAvoidExitMs = 10 * 60 * 1000;
// Path memory: on a network where AWG did not come up and an Xray path did, the next connects
// start with the Xray paths for a while. Stored only on this device as a salted hash of the
// local network (interface names and IPv4 subnets); never sent anywhere, never logged.
constexpr qint64 kXrayFirstMs = 12 * 60 * 60 * 1000;
const char* kPathMemoryKey = "Mayak/pathMemory";
const char* kPathSaltKey = "Mayak/pathMemorySalt";
QString localNetworkKey(SecureQSettings* settings) {
    if (!settings) return {};
    QString salt = settings->value(kPathSaltKey).toString();
    if (salt.size() != 64) { salt = B::randomRequestId(); settings->setValue(kPathSaltKey, salt); }
    QStringList parts;
    for (const auto& iface : QNetworkInterface::allInterfaces()) {
        const auto flags = iface.flags();
        if (!(flags & QNetworkInterface::IsUp) || !(flags & QNetworkInterface::IsRunning) || (flags & QNetworkInterface::IsLoopBack)) continue;
        for (const auto& entry : iface.addressEntries()) {
            if (entry.ip().protocol() != QAbstractSocket::IPv4Protocol || entry.prefixLength() <= 0) continue;
            const quint32 mask = entry.prefixLength() >= 32 ? 0xffffffffu : ~((1u << (32 - entry.prefixLength())) - 1u);
            parts << iface.name() + '/' + QHostAddress(entry.ip().toIPv4Address() & mask).toString() + '/' + QString::number(entry.prefixLength());
        }
    }
    if (parts.isEmpty()) return {};
    parts.sort();
    return QString::fromLatin1(QCryptographicHash::hash((salt + '|' + parts.join('|')).toUtf8(), QCryptographicHash::Sha256).toHex());
}
bool rememberedXrayFirst(SecureQSettings* settings, const QString& network) {
    if (!settings || network.isEmpty()) return false;
    const auto memory = QJsonDocument::fromJson(settings->value(kPathMemoryKey).toByteArray()).object();
    const auto entry = memory.value(network).toObject();
    return entry.value("xrayFirst").toBool() && entry.value("until").toDouble() > double(QDateTime::currentMSecsSinceEpoch());
}
void rememberPath(SecureQSettings* settings, const QString& network, bool xrayFirst) {
    if (!settings || network.isEmpty()) return;
    auto memory = QJsonDocument::fromJson(settings->value(kPathMemoryKey).toByteArray()).object();
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    for (const auto& key : memory.keys())
        if (memory.value(key).toObject().value("until").toDouble() <= double(now)) memory.remove(key);
    if (xrayFirst) memory.insert(network, QJsonObject{{"xrayFirst", true}, {"until", double(now + kXrayFirstMs)}});
    else memory.remove(network);
    while (memory.size() > 16) memory.remove(memory.keys().first());
    settings->setValue(kPathMemoryKey, QJsonDocument(memory).toJson(QJsonDocument::Compact));
}
using SplitPrepare = std::function<void(QObject*, std::function<void(bool, QString)>)>;
SplitPrepare& splitPrepareStorage() { static SplitPrepare hook; return hook; }
const char* kAppExclusionUnavailable =
    "Не удалось включить исключения программ: драйвер раздельного туннелирования недоступен. "
    "Перезагрузите компьютер или уберите исключения в «Раздельное туннелирование».";
QString splitPrepareText(const QString& result) {
    if (result == QLatin1String("amnezia_active"))
        return QStringLiteral("Исключения программ заняты AmneziaVPN: в ней сейчас включён VPN. Выключите VPN в AmneziaVPN и включите Маяк снова.");
    if (result == QLatin1String("amnezia_busy"))
        return QStringLiteral("AmneziaVPN сейчас запускается или останавливается. Включите Маяк через несколько секунд.");
    if (result == QLatin1String("mullvad"))
        return QStringLiteral("Исключения программ недоступны: их драйвер использует установленный Mullvad VPN. Уберите исключения в «Раздельное туннелирование».");
    if (result == QLatin1String("amnezia_holds"))
        return QStringLiteral("Исключения программ заняты AmneziaVPN. Перезагрузите компьютер или удалите AmneziaVPN, если она не нужна.");
    return QString::fromUtf8(kAppExclusionUnavailable);
}
quint16 freeLoopbackPort() {
    QTcpServer server;
    if (!server.listen(QHostAddress::LocalHost, 0)) return 0;
    const quint16 port = server.serverPort();
    server.close();
    return port;
}
qint64 utcDeadline(qint64 mono) { return QDateTime::currentMSecsSinceEpoch() + qMax<qint64>(0, mono-B::monotonicMillis()); }
QJsonObject payloadFor(const at::AttemptRecord& r) {
    return {{"auth_data", QJsonObject{{"api_key",r.deviceApiKey()}}}, {"installation_uuid",r.installationUuid()},
        {"public_key",r.publicKey()}, {"service_type",r.serviceType()}, {"service_protocol",r.serviceProtocol()},
        {"user_country_code",r.userCountryCode()}, {"server_country_code",r.serverCountryCode()}};
}
ad::GatewayFactory factoryFor(QString endpoint) {
    return [endpoint](int timeout) { return QSharedPointer<GatewayController>::create(endpoint,false,timeout,false,nullptr); };
}
ad::Transport gatewayTransport() {
    return [](const QString& api,const QJsonObject& payload,int timeout) {
        auto gateway=factoryFor(QStringLiteral("https://mayaklight.ru/gw/"))(timeout);
        auto promise=std::make_shared<QPromise<GatewayPostResult>>(); promise->start();
        auto future=promise->future();
        auto* watcher=new QFutureWatcher<GatewayPostResult>();
        QObject::connect(watcher,&QFutureWatcher<GatewayPostResult>::finished,watcher,[gateway,watcher,promise] {
            promise->addResult(watcher->result()); promise->finish(); watcher->deleteLater();
        });
        watcher->setFuture(gateway->postAuthenticatedAsync(api,payload));
        return future;
    };
}
QString errorText(ac::ErrorCategory e) {
    switch(e) {
    case ac::ErrorCategory::Capacity: return QStringLiteral("Серверы заняты. Повторите подключение немного позже.");
    case ac::ErrorCategory::AuthRevoked: return QStringLiteral("Доступ отозван. Войдите в личный кабинет.");
    case ac::ErrorCategory::AccountExpired: return QStringLiteral("Срок доступа закончился. Откройте личный кабинет.");
    case ac::ErrorCategory::NotReady: return QStringLiteral("Сервер готовит доступ. Повторите подключение через несколько секунд.");
    case ac::ErrorCategory::StopUnconfirmed: return QStringLiteral("Не удалось подтвердить отключение. Повторите попытку для безопасного завершения.");
    case ac::ErrorCategory::Unsupported: return QStringLiteral("Выбранный способ подключения недоступен для этого сервера. Выберите «Автоматически» в настройках подключения.");
    default: return QStringLiteral("Не удалось подключиться к доступному серверу. Проверьте интернет и повторите попытку.");
    }
}
}

// Callbacks retain Session, not UI or repositories. Every remote effect carries
// the immutable original device authority. The encrypted ledger survives exits.
struct MayakAutoConnectRuntime::Session : QObject, ac::Adapter, ac::Clock,
                                        std::enable_shared_from_this<Session> {
    QPointer<MayakAutoConnectRuntime> facade;
    QPointer<SecureServersRepository> servers;
    QPointer<SecureAppSettingsRepository> app;
    QPointer<ConnectionController> connection;
    SubscriptionController* subscription;
    SecureQSettings* settings = nullptr;
    ad::Transport transport;
    // Connection method for this session ("auto", "awg", "xray") and the local network key of
    // the path memory, both fixed when the session starts (before any tunnel exists).
    QString method = QStringLiteral("auto");
    QString networkKey;
    // Windows: the service could not apply the user's app exclusions (split tunnel driver unavailable).
    // The cycle ends with a clear error instead of retrying or falling back to a path without exclusions.
    qint64 sessionStartMono = mayak::split::monotonicNowMs();
    bool appExclusionBlocked = false;
    bool splitPrepared = false; // app exclusions prepared in the service for this session
    // Xray path race engine (one per session at a time). Starts wait until it is stopped.
    struct Race {
        bool engineActive = false;   // started or starting; a stop is still owed
        bool stopping = false;
        QString requestId;
        std::pair<ac::CycleId,ac::AttemptId> tag{0,0};
        std::vector<QPointer<MayakTunnelProbe>> probes;
        std::function<void()> afterStop; // a path start waiting for the engine to stop
    } race;
    std::unique_ptr<at::MayakAttemptStore> store;
    std::unique_ptr<B> bridge;
    std::unique_ptr<ac::Coordinator> coordinator;
    QTimer timer;
    QString serverId, epoch, cycleToken, endpoint;
    QJsonObject common;
    SubscriptionController::ProtocolData keys;
    at::CleanupAuthorityInput authority;
    int inFlight = 0;
    bool cancelled = false, preparing = true, terminal = false, reconnectWanted = false;
    bool permissionPending = false;
    bool cleanupPending = false, cleanupOperation = false;
    quint64 cleanupGeneration = 0, preflightGeneration = 0;
    qint64 cleanupDeadline = 0;
    bool preflightNativeOff = false;
    QString permissionRequestId;
    qint64 preflightDeadline = 0, lastMonitor = 0;
    bool monitorProbing = false;
    // Connect-time network failures are retried (RecoveryTiming::connectRetryMs) before an error.
    int connectRetries = 0;
    qint64 connectRetryAt = 0;
    // The local tunnel adapter did not come up in this cycle (RecoveryTiming::noHealthMeansLocalFailure).
    bool localStartFailed = false;
    int localStartRetries = 0;
    // Windows was still busy failing the adapter when the 3 s stop expired: confirm the stop
    // later (exact cleanup) and then start a fresh session.
    qint64 localRestartAt = 0;
    bool restartAfterCleanup = false;
    // Connected-state truth for the UI (rule: never "Connected" without a passing
    // tunnel probe) and Android soft recovery of a stuck AWG transport.
    struct Recovery {
        int probeFailures = 0;
        bool shown = false, shownNoNetwork = false;
        bool networkLost = false;
        qint64 networkLostAt = 0, networkChangedAt = 0, forceProbeAt = 0, outageStart = 0, nextAt = 0, lastRecoverAt = 0;
        int attempts = 0;
        bool inFlight = false;
    } rec;
    QVariantMap connectedLocation;
    struct XrayEntry { ad::XrayPath path; ad::XrayPathConfig config; };
    struct Attempt {
        at::AttemptIdentity identity;
        ac::Candidate candidate;
        ac::Path path{"awg", ac::PathKind::Awg}; // path of the current/last backend start
        int pathStarts = 0;
        std::vector<XrayEntry> xray;              // validated Xray paths of this allocation
        bool awgFailedHere = false;               // an AWG path of this allocation did not prove
        qint64 probeStartedMono = 0;
        QString allocation;
        QString encodedConfig;
        QString exitLocationCityId;
        qint64 connectBefore = 0;
        B::Ticket ticket;
        AwgHealthContext expected;
        AwgTunnelHealth health;
        qint64 startMono = 0, startUtc = 0, healthAt = 0;
        bool started = false, stopped = false, cancelled = false, probing = false;
        bool adopted = false; // continues the persisted attempt of an adopted running backend
        bool releasePending = false, releaseCallbackHandled = false, releaseLateHandled = false;
        quint64 releaseOperationId = 0;
        bool reset = false;
        qint64 rxChangedAt = 0;          // last time own-peer RX advanced
        qint64 replacementAllowedUntil = 0; // one requested backend replacement may change generation
        quint64 baselineRx = 0, baselineTx = 0;
        ProofDone proofDone;
        QString nonce;
        QStringList egress;
        qint64 proofDeadline = 0;
        bool tlsOk = false;
        MayakTunnelProbeProof proof;
        // Adopted attempt whose ownership transfer was never confirmed: the running backend is
        // still owned by the recovery ticket, so every stop/cleanup of this attempt uses it.
        B::Ticket stopTicket;
        const B::Ticket& ownTicket() const { return stopTicket.valid() ? stopTicket : ticket; }
        bool acceptNativeDown(const B::Result& result) {
            // The Ticket is immutable for this attempt. Native OFF evidence is
            // monotonic across observer, original stop and cleanup retry ingress;
            // a different operation's Unknown/Deadline cannot revoke it.
            if (result.outcome!=B::Outcome::ConfirmedDown || !(ticket.same(result.ticket) ||
                (stopTicket.valid() && stopTicket.same(result.ticket)))) return false;
            stopped=true;
            return true;
        }
    };
    std::map<std::pair<ac::CycleId,ac::AttemptId>, std::shared_ptr<Attempt>> attempts;
    // Cold-start adoption (Android): the inspected running backend continues its persisted
    // attempt instead of being stopped. While `pending`, only the recovery ticket owns it;
    // every path either hands it to an Attempt (fresh ticket) or stops it with that ticket.
    struct Adoption {
        bool pending = false;
        at::AttemptIdentity identity;
        QString allocationId;
        B::Ticket recovery;
        QString controlIdentity;
    } adoption;
    // An adoption is being given up (backend stop + reconcile in flight): the session stays
    // busy and a coordinator cancel must not publish "Disconnected" before it settles.
    bool abandoning = false, abandonHeldDisconnect = false;
    // Android UI hidden (Activity stopped): the service pauses streamed health and runs its own
    // watchdog, so health age and probes say nothing here; connected monitoring pauses.
    bool uiHidden = false;
    // Note 7: giving up an adoption could not confirm the backend stop.
    bool abandonUnconfirmed = false;
    // Failover: the exit that just stopped working goes last in the next cycles for a while.
    void avoidCandidate(const QString& id,const char* reason="connected_dead") {
        if (id.isEmpty()) return;
        avoidedExitStorage().candidateId=id; avoidedExitStorage().until=now()+kAvoidExitMs;
        logNet(QStringLiteral("event=failover_avoid reason=%1").arg(QLatin1String(reason)));
    }

    explicit Session(MayakAutoConnectRuntime* f, QString id)
        : facade(f), servers(f->m_servers), app(f->m_app), connection(f->m_connection),
          subscription(f->m_subscription), settings(f->m_settings), transport(f->m_transport), store(new at::MayakAttemptStore(f->m_settings)),
          bridge(new B(f->m_port)), serverId(std::move(id)), epoch(randomId()), cycleToken(randomId()) {
        auto& retries=localStartRetriesStorage();
        if (!retries.autoRestart) retries.count=0;
        retries.autoRestart=false;
        localStartRetries=retries.count;
        if (app) connect(app, &SecureAppSettingsRepository::mayakSessionChanging, this, [this] {
            if (permissionPending) stopUser();
        });
        if (servers) {
            connect(servers, &SecureServersRepository::serverEdited, this, [this](const QString &editedId) {
                if (permissionPending && editedId == serverId) stopUser();
            });
            connect(servers, &SecureServersRepository::serverRemoved, this, [this](const QString &removedId, int) {
                if (permissionPending && removedId == serverId) stopUser();
            });
        }
        timer.setInterval(100);
        connect(&timer,&QTimer::timeout,this,[this] {
            if (coordinator && !appExclusionBlocked && !cancelled &&
                mayak::split::appExclusionFailedSince(sessionStartMono)) {
                const auto st=coordinator->status().state;
                if (st!=ac::State::Idle && st!=ac::State::Failed && st!=ac::State::Cancelled) {
                    appExclusionBlocked=true; reconnectWanted=false; connectRetryAt=0; localStartFailed=false;
                    logNet(QStringLiteral("event=app_exclusion_unavailable"));
                    coordinator->cancel();
                }
            }
            if (coordinator) coordinator->tick();
            // Retry starts only after exact release acknowledgement and fresh fetch.
            if (reconnectWanted && coordinator && coordinator->status().state == ac::State::Failed && !inFlight) {
                const auto loaded=store->load();
                if (loaded.ok && loaded.records.isEmpty()) { reconnectWanted=false; terminal=false; coordinator->begin(); }
            }
            // Scheduled connect retry after a network failure: same release barrier as above.
            if (connectRetryAt && now()>=connectRetryAt && coordinator && !cancelled &&
                coordinator->status().state == ac::State::Failed && !inFlight) {
                const auto loaded=store->load();
                if (loaded.ok && loaded.records.isEmpty()) {
                    connectRetryAt=0; terminal=false;
                    logNet(QStringLiteral("event=connect_retry_start retry=%1 local_retry=%2").arg(connectRetries).arg(localStartRetries));
                    coordinator->begin();
                } else if (now()>=connectRetryAt+10000) {
                    // An unreleased attempt blocks a fresh cycle: never spin in "retrying" forever.
                    connectRetryAt=0; terminal=true; phase=QStringLiteral("failed");
                    logNet(QStringLiteral("event=connect_retry_blocked"));
                    output(Vpn::ConnectionState::Error,errorText(ac::ErrorCategory::Network));
                }
            }
            // Local adapter failure with an unconfirmed stop: confirm and release now, then restart.
            if (localRestartAt && now()>=localRestartAt && cleanupPending && !cleanupOperation && !cancelled) {
                localRestartAt=0;
                logNet(QStringLiteral("event=local_start_cleanup retry=%1").arg(localStartRetries));
                retryCleanup();
            }
            for (auto& [tag,a]:attempts) {
                if (a->proofDone) advanceProof(tag,a);
            }
            monitor();
        });
        connect(bridge.get(),&B::health,this,[this](B::Ticket ticket,AwgTunnelHealth h) {
            for(auto& [tag,a]:attempts) {
                if (!a->ticket.same(ticket) || !a->expected.matches(h) || !h.valid || a->cancelled) continue;
                if (a->health.valid && h.generation!=a->health.generation && now()<a->replacementAllowedUntil) {
                    // Exactly one owner-requested soft recovery: new backend, same proof context.
                    a->replacementAllowedUntil=0; a->rxChangedAt=now();
                    rec.forceProbeAt=now()+300; // the new interface identity is now known
                } else if (a->health.valid && (h.generation!=a->health.generation || h.rxTotal<a->health.rxTotal || h.txTotal<a->health.txTotal)) a->reset=true;
                else if (!a->health.valid || h.rxTotal>a->health.rxTotal) a->rxChangedAt=now();
                a->health=h; a->healthAt=now();
            }
        });
        connect(bridge.get(),&B::networkChanged,this,[this](B::Ticket ticket,bool available) { onNetwork(ticket,available); });
        connect(bridge.get(),&B::resumed,this,[this](B::Ticket ticket,bool replaced,bool available) { onResume(ticket,replaced,available); });
        connect(bridge.get(),&B::visibilityChanged,this,[this](bool visible) { onVisibility(visible); });
        // The service watchdog could not repair the current exit while the UI was hidden:
        // reconnect now, another exit first.
        connect(bridge.get(),&B::failoverRequested,this,[this](B::Ticket ticket) {
            auto a=connectedAttempt();
            if (!a || !a->ticket.same(ticket) || a->cancelled || cancelled || !coordinator) return;
            const auto s=coordinator->status();
            if (s.state!=ac::State::Connected) return;
            // N2: a hidden failover first takes the (dead) tunnel down. With no other exit known
            // that only trades "no traffic" for "traffic outside the VPN": keep the tunnel.
            if (avoidedExitStorage().knownExits<2) { logNet(QStringLiteral("event=failover_skip reason=single_exit")); return; }
            logNet(QStringLiteral("event=failover_start source=service"));
            reconnectWanted=true;
            avoidCandidate(a->identity.candidateId);
            coordinator->onOwnRepairExhausted(s.cycle);
        });
        // Stopped outside the app (notification/tile "Disconnect", VPN revoked): honour it as the
        // user's own disconnect -- never as a fault to recover or reconnect.
        connect(bridge.get(),&B::userStopped,this,[this](B::Ticket ticket) {
            if (cancelled) return;
            for (const auto& [tag,a]:attempts) {
                if (!a->ticket.same(ticket) || a->cancelled) continue;
                logNet(QStringLiteral("event=user_stop"));
                stopUser(); return;
            }
        });
        connect(bridge.get(),&B::error,this,[this](const B::Result& r) {
            if (!coordinator) return;
            if (r.detail==QStringLiteral("permissionDenied")) { cancelled=true; coordinator->cancel(); }
        });
        connect(bridge.get(),&B::backendDown,this,[this](const B::Result& r) {
            for(auto& [tag,a]:attempts) noteNativeDown(a,r);
        });
    }
    ac::Millis now() const override { return B::monotonicMillis(); }
    QString phase = QStringLiteral("preparing");
    void output(Vpn::ConnectionState state,QString text, QVariantMap exitLocation = {}) {
        if (facade) facade->publish(state,text,phase,exitLocation);
    }
    bool identityCurrent() const {
        if (!facade || !servers || !app || !connection || cancelled || app->mayakSessionToken().isEmpty()) return false;
        const auto cfg=servers->apiV2Config(serverId);
        return facade->manages(serverId) && cfg && cfg->authData.toJson()==common.value("auth_data").toObject() &&
            cfg->serviceType()==common.value("service_type").toString() &&
            cfg->apiConfig.serviceProtocol==common.value("service_protocol").toString() &&
            cfg->apiConfig.userCountryCode==common.value("user_country_code").toString();
    }
    void failure(QString text) { ++preflightGeneration; preparing=false; terminal=true; phase=QStringLiteral("failed"); output(Vpn::ConnectionState::Error,std::move(text)); }
    // Note 8: an early refusal after adoption began still stops the adopted backend first
    // (recovery ticket + reconcile), exactly like every other adoption give-up.
    void failureAfterAdoption(QString text) {
        if (!adoption.pending) { failure(std::move(text)); return; }
        preparing=false; terminal=false; // busy until the give-up settles
        auto self=shared_from_this();
        abandonAdoption([self,text](bool) { self->failure(text); });
    }
    void beginCoordinatorAfterPreflight() {
        if (cancelled || !identityCurrent()) {
            if (adoption.pending && !cancelled) { failureAfterAdoption(QStringLiteral("Сеанс Маяка изменился. Войдите снова и повторите попытку.")); return; }
            preparing=false; terminal=true;
            phase=cancelled ? QStringLiteral("cancelled") : QStringLiteral("idle");
            output(Vpn::ConnectionState::Disconnected,{}); return;
        }
        if (!splitPrepared && needsSplitPrepare()) {
            // Windows app exclusions need the split tunnel driver; the service prepares it first, with its
            // own time budget (it may release AmneziaVPN's copy), never inside the tunnel start deadline.
            splitPrepared=true; preparing=true;
            output(Vpn::ConnectionState::Preparing,QStringLiteral("Готовим исключения программ…"));
            auto done=[weak=weak_from_this()](bool replied,QString result) {
                auto self=weak.lock();
                if (!self || self->cancelled || self->terminal || self->coordinator) return;
                self->logNet(QStringLiteral("event=split_prepare replied=%1 result=%2").arg(replied ? 1 : 0).arg(result));
                if (replied && result==QLatin1String("ok")) { self->beginCoordinatorAfterPreflight(); return; }
                self->failureAfterAdoption(splitPrepareText(replied ? result : QStringLiteral("unavailable")));
            };
            if (auto& hook=splitPrepareStorage()) hook(this,done);
            else mayak::foreignvpn::requestPrepareSplitTunnel(this,done,25000);
            return;
        }
        coordinator=std::make_unique<ac::Coordinator>(*this,*this,[weak=weak_from_this()](const ac::Status& s) {
            if(auto self=weak.lock()) self->state(s);
        });
        preparing=false;
        coordinator->begin();
    }
    // Windows app exclusions ("all apps except these") are active for this connect.
    bool needsSplitPrepare() const {
#ifdef Q_OS_WINDOWS
        const bool windows=true;
#else
        const bool windows=bool(splitPrepareStorage());
#endif
        // An adopted running tunnel already has its exclusions; never release drivers under it.
        if (!windows || adoption.pending || !app || !app->isAppsSplitTunnelingEnabled()) return false;
        const auto mode=app->appsRouteMode();
        return mode!=amnezia::AppsRouteMode::VpnAllApps && !app->vpnApps(mode).isEmpty();
    }
    void preparePermissionsAndBeginCoordinator() {
        if (cancelled || terminal || !preparing || now()>=preflightDeadline || permissionPending || coordinator) return;
        if (!identityCurrent()) { failureAfterAdoption(QStringLiteral("Сеанс Маяка изменился. Войдите снова и повторите попытку.")); return; }
        permissionPending=true;
        permissionRequestId=randomId();
        const QString requestId=permissionRequestId;
        output(Vpn::ConnectionState::Preparing,QStringLiteral("Подтвердите разрешение VPN…"));
        bridge->preparePermissions(requestId,[weak=weak_from_this(),requestId](QString returnedId,B::PermissionResult result) {
            auto self=weak.lock();
            if (!self || self->cancelled || !self->permissionPending || returnedId!=requestId || self->permissionRequestId!=requestId) return;
            self->permissionPending=false;
            self->permissionRequestId.clear();
            if (result==B::PermissionResult::Denied) {
                self->failureAfterAdoption(QStringLiteral("Разрешение VPN не выдано. Нажмите «Включить Маяк» и разрешите подключение.")); return;
            }
            if (result!=B::PermissionResult::Ready) {
                self->failureAfterAdoption(QStringLiteral("Не удалось подготовить разрешение VPN. Повторите попытку.")); return;
            }
            self->beginCoordinatorAfterPreflight();
        });
    }
    void initialize() {
        auto self=shared_from_this();
        output(Vpn::ConnectionState::Preparing,QStringLiteral("Проверяем доступ…"));
        if (!facade || !servers || !app || app->mayakSessionToken().isEmpty()) { failure(QStringLiteral("Войдите в личный кабинет Маяка.")); return; }
        const auto cfg=servers->apiV2Config(serverId);
        if (!cfg || subscription->getOrCreateMayakAwgProtocolData(serverId,&keys)!=ErrorCode::NoError) {
            failure(QStringLiteral("Не удалось сохранить доступ. Повторите настройку в личном кабинете.")); return;
        }
        endpoint=QStringLiteral("https://mayaklight.ru/gw/");
        common=GatewayPayloadBuilder(app).addField(apiDefs::key::authData,cfg->authData.toJson())
            .addField(apiDefs::key::serviceType,cfg->serviceType()).addField(apiDefs::key::serviceProtocol,QStringLiteral("awg"))
            .addField(apiDefs::key::userCountryCode,cfg->apiConfig.userCountryCode)
            .addField(apiDefs::key::publicKey,keys.wireGuardClientPubKey).build();
        authority={endpoint,common.value("installation_uuid").toString(),keys.wireGuardClientPubKey,
            cfg->authData.toJson().value("api_key").toString(),cfg->serviceType(),QStringLiteral("awg"),cfg->apiConfig.userCountryCode,{}};
        method=app->mayakConnectionMethod();
        networkKey=localNetworkKey(settings);
        logNet(QStringLiteral("event=connection_method method=%1 xray_first=%2").arg(method)
            .arg(rememberedXrayFirst(settings,networkKey) ? 1 : 0));
        preflightDeadline=now()+10000;
        inspectPreflight();
        timer.start();
    }
    // A confirmed OFF of an adopted backend through its recovery authority also discharges the
    // cold-start "foreign backend" barrier: that backend was the only one inspection found.
    bool noteNativeDown(const std::shared_ptr<Attempt>& a,const B::Result& r) {
        const bool down=a->acceptNativeDown(r);
        if (down && a->stopTicket.valid() && a->stopTicket.same(r.ticket)) preflightNativeOff=true;
        return down;
    }
    bool nativeDown() const {
        if (!preflightNativeOff) return false;
        for (const auto& [tag,a]:attempts) if (a->started && !a->stopped) return false;
        return true;
    }
    QString cleanupText() const {
        return nativeDown()
            ? QStringLiteral("Туннель остановлен; очистка доступа на сервере ожидает повтора.")
            : QStringLiteral("Не удалось подтвердить отключение. Нажмите «Повторить отключение».");
    }
    bool finishCleanup() {
        const auto loaded=store->load();
        if (!loaded.ok || !loaded.records.isEmpty() || !nativeDown()) return false;
        abandonHeldDisconnect=false;
        cleanupPending=false; cleanupOperation=false; cancelled=true;
        preparing=false; terminal=true; reconnectWanted=false; timer.stop();
        if (restartAfterCleanup && facade) {
            // The local adapter attempt is fully stopped and released: start a fresh session
            // (preflight + reconcile + new cycle) that keeps the bounded retry count.
            restartAfterCleanup=false;
            phase=QStringLiteral("preparing");
            localStartRetriesStorage().count=localStartRetries;
            logNet(QStringLiteral("event=local_start_restart retry=%1").arg(localStartRetries));
            QTimer::singleShot(0,facade.data(),[f=facade,id=serverId] {
                if (!f) return;
                localStartRetriesStorage().autoRestart=true;
                f->begin(id);
                localStartRetriesStorage().autoRestart=false;
            });
            return true;
        }
        phase=QStringLiteral("cancelled"); output(Vpn::ConnectionState::Disconnected,{});
        return true;
    }
    void inspectPreflight() {
        auto self=shared_from_this();
        const auto deadline=cleanupOperation ? qMin(now()+3000,cleanupDeadline) : now()+3000;
        bridge->inspectOwnBackend(deadline,[self](B::Inspection i) {
            if (i.state==B::OwnState::Off) {
                self->preflightNativeOff=true;
                if (self->cancelled) {
                    self->cleanupOperation=false;
                    if (!self->finishCleanup()) {
                        self->cleanupPending=true;
                        self->phase=QStringLiteral("failed");
                        self->output(Vpn::ConnectionState::Error,self->cleanupText());
                    }
                } else if (!self->terminal) self->reconcileNext();
            } else if (i.state==B::OwnState::Active && i.recoveryTicket.valid()) {
                if (!self->cancelled && !self->cleanupOperation && self->tryBeginAdoption(i)) return;
                const auto ticket=i.recoveryTicket;
                self->bridge->cancel(ticket);
                self->bridge->stopAndConfirm(ticket,self->cleanupOperation ? qMin(self->now()+3000,self->cleanupDeadline) : self->now()+3000,[self,ticket](B::Result r) {
                    self->cleanupOperation=false;
                    if (r.outcome==B::Outcome::ConfirmedDown && ticket.same(r.ticket)) {
                        self->preflightNativeOff=true;
                        if (self->cancelled) {
                            if (!self->finishCleanup()) self->cleanupPending=true;
                        } else if (!self->terminal) self->reconcileNext();
                    } else {
                        if (self->cancelled) self->cleanupPending=true;
                        self->failure(errorText(ac::ErrorCategory::StopUnconfirmed));
                    }
                });
            } else {
                self->cleanupOperation=false;
                if (self->cancelled) self->cleanupPending=true;
#ifdef Q_OS_ANDROID
                self->failure(QStringLiteral("Служба VPN Android не ответила. Закройте и снова откройте Маяк. Если ошибка повторится, проверьте обновления."));
#else
                self->failure(QStringLiteral("Служба VPN не отвечает. Перезапустите приложение; на Windows проверьте установку Маяка."));
#endif
            }
        });
    }
    // Cold start found our running backend. Adopt it when the ledger holds exactly the attempt
    // that may own it (started, with an allocation, same device credential and gateway).
    // Server-side truth is re-checked by the idempotent acquire; the tunnel by the normal proof.
    bool tryBeginAdoption(const B::Inspection& i) {
        if (!bridge->canAdopt() || i.ownControlIdentity.isEmpty() || terminal || !preparing || now()>=preflightDeadline) return false;
        const auto loaded=store->load();
        if (!loaded.ok || loaded.records.size()!=1) return false;
        const auto& r=loaded.records.first();
        if (!r.mayHaveStarted() || r.tombstoned() || r.allocationId().isEmpty() || r.identity().attemptId.isEmpty() ||
            r.identity().localSubscriptionId!=serverId || r.deviceApiKey()!=authority.deviceApiKey ||
            r.gatewayEndpoint()!=authority.gatewayEndpoint) return false;
        adoption={true,r.identity(),r.allocationId(),i.recoveryTicket,i.ownControlIdentity};
        logNet(QStringLiteral("event=adopt_candidate"));
        output(Vpn::ConnectionState::Preparing,QStringLiteral("Проверяем подключение…"));
        preparePermissionsAndBeginCoordinator();
        return true;
    }
    // Give up adoption: stop the running backend with the recovery ticket, release every server
    // allocation of the persisted attempt (reconcile) and drop its ledger record. then(true) only
    // when all three are confirmed; otherwise the old cleanup/error paths remain responsible.
    void abandonAdoption(std::function<void(bool)> callerThen) {
        if (!adoption.pending) { if (callerThen) callerThen(true); return; }
        adoption.pending=false;
        const auto recovery=adoption.recovery; const auto identity=adoption.identity;
        auto self=shared_from_this();
        // Busy for the whole give-up (stop + reconcile); a cancel meanwhile is finished here.
        abandoning=true; ++inFlight;
        std::weak_ptr<Session> owner=self;
        const std::function<void(bool)> then=[owner,callerThen](bool ok) {
            auto self=owner.lock(); if (!self) return;
            --self->inFlight; self->abandoning=false;
            if (callerThen) callerThen(ok);
            if (!self->abandonHeldDisconnect) return;
            self->abandonHeldDisconnect=false;
            if (!self->finishCleanup()) {
                self->cleanupPending=true; self->terminal=true; self->phase=QStringLiteral("failed");
                self->output(Vpn::ConnectionState::Error,self->cleanupText());
            }
        };
        bridge->stopAndConfirm(recovery,now()+3000,[self,recovery,identity,then](B::Result r) {
            if (r.outcome!=B::Outcome::ConfirmedDown || !recovery.same(r.ticket)) {
                self->logNet(QStringLiteral("event=adopt_abandon_stop_unconfirmed"));
                self->abandonUnconfirmed=true; if (then) then(false); return;
            }
            self->preflightNativeOff=true;
            const auto loaded=self->store->load();
            if (!loaded.ok) { if (then) then(false); return; }
            const auto it=std::find_if(loaded.records.begin(),loaded.records.end(),[&](const at::AttemptRecord& x){ return x.identity()==identity; });
            if (it==loaded.records.end()) { if (then) then(true); return; }
            ad::Request req; req.action="reconcile"; req.attemptId=identity.attemptId; req.cycleToken=identity.cycleToken;
            req.commonPayload=payloadFor(*it); req.deadlineUtcMs=utcDeadline(self->now()+2500);
            ++self->inFlight;
            auto settled=std::make_shared<bool>(false);
            std::weak_ptr<Session> weak=self;
            auto settle=[weak,settled,identity,then](bool ok) {
                auto self=weak.lock(); if (!self || *settled) return;
                *settled=true; --self->inFlight;
                const bool removed=ok && self->store->removeAfterConfirmedCleanup(identity).ok;
                self->logNet(QStringLiteral("event=adopt_abandoned released=%1").arg(removed ? 1 : 0));
                if (then) then(removed);
            };
            QTimer::singleShot(2500,self.get(),[settle] { settle(false); });
            ad::MayakAdmissionClient::postAsync(req,self->transport,[settle](ad::Response response) {
                settle(response.success && response.authenticatedResponse);
            });
        });
    }
    void reconcileNext() {
        if (cancelled || terminal || !preparing) return;
        if (now()>=preflightDeadline) { failure(QStringLiteral("Завершаем прежнее подключение. Повторите попытку.")); return; }
        auto self=shared_from_this();
        const auto loaded=store->load();
        if (!loaded.ok) { failure(QStringLiteral("Хранилище доступа недоступно. Подключение остановлено.")); return; }
        if (!loaded.records.isEmpty()) {
            if (now()>=preflightDeadline) { failure(QStringLiteral("Завершаем прежнее подключение. Повторите попытку.")); return; }
            const auto r=loaded.records.first();
            ad::Request req; req.action="reconcile"; req.attemptId=r.identity().attemptId; req.cycleToken=r.identity().cycleToken;
            req.commonPayload=payloadFor(r); req.deadlineUtcMs=utcDeadline(preflightDeadline);
            ++inFlight;
            auto settled=std::make_shared<bool>(false);
            auto lateHandled=std::make_shared<bool>(false);
            auto timedOutSeen=std::make_shared<bool>(false);
            std::weak_ptr<Session> weak=self;
            const auto generation=preflightGeneration, cleanupOwner=cleanupGeneration;
            auto settle=[weak,r,generation,cleanupOwner,settled,lateHandled,timedOutSeen](ad::Response response, bool timedOut) {
                auto self=weak.lock(); if (!self) return;
                if (*settled && !(timedOut == false && *timedOutSeen && response.success && response.authenticatedResponse && !*lateHandled)) return;
                const bool first=!(*settled); *settled=true;
                if (timedOut) *timedOutSeen=true;
                if (!first) *lateHandled=true;
                if (first) --self->inFlight;
                // Settlement belongs to this old operation even after cancel;
                // presentation belongs only to the still-current ON intent.
                const auto currentPreflight=[&] {
                    return first && generation==self->preflightGeneration
                        && cleanupOwner==self->cleanupGeneration && self->preparing && !self->terminal
                        && !self->cancelled && !self->cleanupPending && !self->cleanupOperation;
                };
                if (timedOut) {
                    if (currentPreflight()) self->failure(QStringLiteral("Не удалось завершить прежний сеанс. Проверьте интернет и повторите попытку."));
                    return;
                }
                if (!response.success || !response.authenticatedResponse) {
                    if (currentPreflight()) self->failure(QStringLiteral("Не удалось завершить прежний сеанс. Проверьте интернет и повторите попытку."));
                    return;
                }
                if (!self->store->removeAfterConfirmedCleanup(r.identity()).ok) {
                    if (currentPreflight()) self->failure(QStringLiteral("Не удалось сохранить завершение прежнего сеанса. Повторите попытку."));
                    return;
                }
                // Authenticated late cleanup may discharge only its exact old
                // obligation. It cannot revive a failed/cancelled ON intent.
                if (self->cancelled && !self->cleanupOperation) self->finishCleanup();
                else if (currentPreflight() && self->now()<self->preflightDeadline) self->reconcileNext();
            };
            QTimer::singleShot(2500,this,[settle] { settle({},true); });
            ad::MayakAdmissionClient::postAsync(req,transport,[settle](ad::Response response) { settle(response,false); }); return;
        }
        preparePermissionsAndBeginCoordinator();
    }
    void state(const ac::Status& s) {
        // Copy the typed coordinator state on its owning thread. Consumers see
        // only this immutable value, never the coordinator or its session.
        switch(s.state) {
        case ac::State::Idle: phase=QStringLiteral("idle"); break;
        case ac::State::Fetching: phase=QStringLiteral("fetching"); break;
        case ac::State::Admitting: phase=QStringLiteral("admitting"); break;
        case ac::State::Racing: phase=QStringLiteral("starting"); break;
        case ac::State::Starting: phase=QStringLiteral("starting"); break;
        case ac::State::Verifying: phase=QStringLiteral("verifying"); break;
        case ac::State::Connected: phase=QStringLiteral("connected"); break;
        case ac::State::Stopping: phase=s.switchingPath ? QStringLiteral("starting") : QStringLiteral("stopping"); break;
        case ac::State::Failed: phase=QStringLiteral("failed"); break;
        case ac::State::Cancelled: phase=QStringLiteral("cancelled"); break;
        }
        switch(s.state) {
        case ac::State::Fetching: case ac::State::Admitting:
            terminal=false;
            output(Vpn::ConnectionState::Preparing, adoption.pending ? QStringLiteral("Проверяем подключение…")
                                                                     : QStringLiteral("Выбираем доступный сервер…"));
            break;
        case ac::State::Racing:
            logNet(QStringLiteral("event=race_begin"));
            output(Vpn::ConnectionState::Connecting,QStringLiteral("Подбираем способ подключения…")); break;
        case ac::State::Starting:
            logNet(QStringLiteral("event=path_start path=%1").arg(QString::fromStdString(s.pathId)));
            output(Vpn::ConnectionState::Connecting,QStringLiteral("Проверяем VPN-соединение…")); break;
        case ac::State::Verifying:
            output(Vpn::ConnectionState::Connecting,QStringLiteral("Проверяем VPN-соединение…")); break;
        case ac::State::Connected:
            lastMonitor=now(); {
                QVariantMap location;
                const auto selected = get(s.cycle, s.attempt);
                if (selected && !selected->cancelled) {
                    location.insert(QStringLiteral("candidateId"), selected->identity.candidateId);
                    location.insert(QStringLiteral("cityId"), selected->exitLocationCityId);
                    location.insert(QStringLiteral("pathId"), QString::fromStdString(s.pathId));
                    if (avoidedExitStorage().candidateId.compare(selected->identity.candidateId,Qt::CaseInsensitive)==0)
                        avoidedExitStorage()={{},0,avoidedExitStorage().knownExits};
                    selected->rxChangedAt=now();
                    // Path memory (auto mode only): Xray proved here after AWG did not -> Xray first
                    // for a while on this network; AWG proved -> back to the default order.
                    if (method==QStringLiteral("auto") && !selected->adopted) {
                        const bool viaXray=selected->path.kind==ac::PathKind::Xray;
                        if (!viaXray) rememberPath(settings,networkKey,false);
                        else if (selected->awgFailedHere || rememberedXrayFirst(settings,networkKey)) rememberPath(settings,networkKey,true);
                    }
                }
                logNet(QStringLiteral("event=connected path=%1").arg(QString::fromStdString(s.pathId)));
                const bool networkLost=rec.networkLost;
                rec={}; rec.networkLost=networkLost; rec.networkLostAt=networkLost ? now() : 0;
                connectRetries=0; connectRetryAt=0; abandonUnconfirmed=false;
                localStartFailed=false; localStartRetries=0; localStartRetriesStorage().count=0;
                connectedLocation=location;
                output(Vpn::ConnectionState::Connected,QStringLiteral("Подключено"),location);
            } break;
        case ac::State::Stopping:
            if (s.switchingPath) {
                logNet(QStringLiteral("event=path_failed path=%1 error=%2").arg(QString::fromStdString(s.pathId)).arg(int(s.error)));
                output(Vpn::ConnectionState::Connecting,QStringLiteral("Пробуем другой способ подключения…"));
            } else output(Vpn::ConnectionState::Disconnecting,QStringLiteral("Завершаем подключение…"));
            break;
        case ac::State::Failed:
            terminal=true;
            if (appExclusionBlocked && !cancelled) {
                // Stop of the failed attempt was not confirmed: keep the exact cleanup and its retry hint.
                if (s.error==ac::ErrorCategory::StopUnconfirmed) { cleanupPending=true; output(Vpn::ConnectionState::Error,cleanupText()); }
                else output(Vpn::ConnectionState::Error,QString::fromUtf8(kAppExclusionUnavailable));
            } else if (s.error==ac::ErrorCategory::StopUnconfirmed && localStartFailed && !cancelled && !reconnectWanted &&
                localStartRetries<recoveryTimingStorage().localStartRetryMs.size()) {
                // Windows is still failing the adapter (~16 s) so the 3 s stop could not be confirmed.
                // Not a user-facing cleanup error: confirm the stop after a pause, then restart.
                localStartFailed=false; cleanupPending=true; restartAfterCleanup=true; terminal=false;
                const qint64 delay=recoveryTimingStorage().localStartRetryMs.at(localStartRetries++);
                localRestartAt=now()+delay;
                phase=QStringLiteral("preparing");
                output(Vpn::ConnectionState::Preparing,
                       QStringLiteral("VPN-адаптер Windows не запустился — повторим через %1 с…").arg((delay+999)/1000));
                logNet(QStringLiteral("event=local_start_retry_scheduled retry=%1 delay_ms=%2 stop=unconfirmed").arg(localStartRetries).arg(delay));
            } else if (s.error==ac::ErrorCategory::StopUnconfirmed) {
                cleanupPending=true;
                if (localStartFailed && !cancelled) {
                    localStartFailed=false;
                    logNet(QStringLiteral("event=local_start_retry_exhausted stop=unconfirmed"));
                }
                output(Vpn::ConnectionState::Error,cleanupText());
            } else if (abandonUnconfirmed && !cancelled) {
                // Note 7: the adopted backend's stop was not confirmed. Not a network problem and
                // no automatic retry: a new connect re-inspects and stops it first.
                abandonUnconfirmed=false;
                output(Vpn::ConnectionState::Error,QStringLiteral("Не удалось завершить прежнее подключение. Нажмите «Включить Маяк» ещё раз."));
            } else if (localStartFailed && !cancelled && !reconnectWanted &&
                       (s.error==ac::ErrorCategory::Network || s.error==ac::ErrorCategory::Deadline ||
                        s.error==ac::ErrorCategory::ProofFailed)) {
                // The local tunnel adapter never came up (Windows refused to create it): no exit
                // is at fault and an immediate retry fails the same way. Wait, then a fresh cycle.
                localStartFailed=false;
                if (localStartRetries<recoveryTimingStorage().localStartRetryMs.size()) {
                    const qint64 delay=recoveryTimingStorage().localStartRetryMs.at(localStartRetries++);
                    connectRetryAt=now()+delay; terminal=false;
                    phase=QStringLiteral("preparing");
                    output(Vpn::ConnectionState::Preparing,
                           QStringLiteral("VPN-адаптер Windows не запустился — повторим через %1 с…").arg((delay+999)/1000));
                    logNet(QStringLiteral("event=local_start_retry_scheduled retry=%1 delay_ms=%2").arg(localStartRetries).arg(delay));
                } else {
                    logNet(QStringLiteral("event=local_start_retry_exhausted"));
                    output(Vpn::ConnectionState::Error,
                           QStringLiteral("VPN-адаптер Windows не запускается. Перезагрузите компьютер и включите Маяк снова."));
                }
            } else if ((s.error==ac::ErrorCategory::Network || s.error==ac::ErrorCategory::Deadline) && !cancelled &&
                       !reconnectWanted && connectRetries<recoveryTimingStorage().connectRetryMs.size()) {
                // The gateway was unreachable (DNS/timeout, e.g. a mobile network waking up):
                // keep the session busy and start a fresh cycle after a pause, not an error.
                const qint64 delay=recoveryTimingStorage().connectRetryMs.at(connectRetries++);
                connectRetryAt=now()+delay; terminal=false;
                phase=QStringLiteral("preparing");
                output(Vpn::ConnectionState::Preparing,QStringLiteral("Нет связи с сервером Маяка — повторяем…"));
                logNet(QStringLiteral("event=connect_retry_scheduled retry=%1 delay_ms=%2").arg(connectRetries).arg(delay));
            } else if (reconnectWanted && !cancelled) {
                // A dead connected exit is being replaced (another exit first): not an error.
                terminal=false; phase=QStringLiteral("preparing");
                output(Vpn::ConnectionState::Preparing,QStringLiteral("Сервер не отвечает — переподключаемся…"));
            } else output(Vpn::ConnectionState::Error,errorText(s.error));
            break;
        case ac::State::Cancelled: case ac::State::Idle:
            terminal=true;
            if (abandoning) {
                // The adopted backend is still being stopped/released: report it when settled.
                abandonHeldDisconnect=true; phase=QStringLiteral("stopping");
                output(Vpn::ConnectionState::Disconnecting,QStringLiteral("Завершаем подключение…"));
            } else if (appExclusionBlocked && !cancelled) {
                phase=QStringLiteral("failed");
                output(Vpn::ConnectionState::Error,QString::fromUtf8(kAppExclusionUnavailable));
            } else output(Vpn::ConnectionState::Disconnected,{});
            break;
        }
    }
    void stopUser() {
        const bool reconnectWaiting=reconnectWanted;
        cancelled=true; reconnectWanted=false; ++preflightGeneration;
        if (!permissionRequestId.isEmpty()) {
            bridge->cancelPermissionPreparation(permissionRequestId);
            permissionRequestId.clear(); permissionPending=false;
        }
        for(auto& [tag,a]:attempts) { a->cancelled=true; if(a->ticket.valid()) bridge->cancel(a->ticket); }
        const bool retryWaiting=connectRetryAt!=0; connectRetryAt=0;
        const bool localRestartWaiting=restartAfterCleanup; localRestartAt=0; restartAfterCleanup=false;
        const bool adopting=adoption.pending;
        if (adopting) {
            // The adopted backend is not yet owned by any attempt: stop it with the recovery
            // ticket and release its attempt, then finish like any cancelled cleanup.
            auto self=shared_from_this();
            abandonAdoption([self](bool ok) {
                if (ok && self->finishCleanup()) return;
                self->abandonHeldDisconnect=false;
                self->cleanupPending=true; self->terminal=true;
                self->phase=QStringLiteral("failed"); self->output(Vpn::ConnectionState::Error,self->cleanupText());
            });
        }
        if(coordinator) {
            coordinator->cancel();
            // A Failed coordinator ignores cancel(); a pending connect retry or failover
            // reconnect is ours to end.
            if ((retryWaiting || reconnectWaiting) && coordinator->status().state==ac::State::Failed) {
                terminal=true; phase=QStringLiteral("cancelled"); output(Vpn::ConnectionState::Disconnected,{});
            } else if (localRestartWaiting && cleanupPending && !cleanupOperation) {
                // The user's OFF during the local-adapter pause: no restart, finish the pending
                // exact cleanup now (Disconnected on success, the cleanup error otherwise).
                terminal=true; phase=QStringLiteral("stopping");
                output(Vpn::ConnectionState::Disconnecting,QStringLiteral("Завершаем подключение…"));
                retryCleanup();
            }
        } else {
            preparing=false; terminal=true;
            if (adopting) {
                // The abandon callback above finishes (or reports) this cleanup.
                phase=QStringLiteral("stopping"); output(Vpn::ConnectionState::Disconnecting,QStringLiteral("Завершаем подключение…"));
            } else if (!finishCleanup()) {
                cleanupPending=true;
                phase=QStringLiteral("failed");
                output(Vpn::ConnectionState::Error,errorText(ac::ErrorCategory::StopUnconfirmed));
            }
        }
    }
    // The user pressed the main button («Повторить отключение») while a local-adapter restart was
    // pending: the user wants OFF, so the cleanup must not end in an automatic new connection.
    void userRetryCleanup() {
        if (restartAfterCleanup || localRestartAt) {
            restartAfterCleanup=false; localRestartAt=0;
            logNet(QStringLiteral("event=local_start_restart_cancelled reason=user"));
        }
        retryCleanup();
    }
    void retryCleanup(bool continuation=false) {
        if (!cleanupPending || cleanupOperation || !facade) return;
        // The coordinator owns its first exact release request. Never race it
        // with reconciliation of the same encrypted attempt.
        for (const auto& [tag,attempt] : attempts)
            if (attempt->releasePending) return;
        for (const auto& [tag,attempt] : attempts) attempt->releaseOperationId=0;
        if (!continuation) cleanupDeadline=now()+10000;
        if (finishCleanup()) return;
        if (now()>=cleanupDeadline) {
            phase=QStringLiteral("failed");
            output(Vpn::ConnectionState::Error,QStringLiteral("Очистка доступа ожидает повтора. Нажмите «Повторить отключение».")); return;
        }
        if (!coordinator && !preflightNativeOff) {
            cleanupOperation=true; inspectPreflight(); return;
        }
        const auto loaded=store->load();
        if (!loaded.ok || loaded.records.isEmpty()) {
            phase=QStringLiteral("failed"); output(Vpn::ConnectionState::Error,QStringLiteral("Не удалось проверить сохранённую очистку. Отключение остаётся неподтверждённым."));
            return;
        }
        const auto record=loaded.records.first();
        // Before coordinator creation a fresh own-backend OFF/recovery-stop
        // barrier covers persisted records from a prior process. Once native
        // starts are possible, each relevant current ticket needs its own down.
        if (record.mayHaveStarted() && (coordinator || !preflightNativeOff)) {
            std::shared_ptr<Attempt> attempt;
            for (const auto& [tag,candidate] : attempts)
                if (candidate->identity==record.identity()) { attempt=candidate; break; }
            if (!attempt) {
                phase=QStringLiteral("failed"); output(Vpn::ConnectionState::Error,QStringLiteral("Сеанс VPN не подтверждён. Отключение остаётся неподтверждённым."));
                return;
            }
            if (!attempt->stopped) {
                cleanupOperation=true;
                const quint64 generation=++cleanupGeneration;
                bridge->cancel(attempt->ticket);
                auto self=shared_from_this();
                bridge->stopAndConfirm(attempt->ownTicket(),qMin(now()+3000,cleanupDeadline),[self,attempt,generation](B::Result result) {
                    self->noteNativeDown(attempt,result);
                    if (generation!=self->cleanupGeneration) {
                        if (attempt->stopped && !self->cleanupOperation) self->retryCleanup(true);
                        return;
                    }
                    if (!attempt->stopped) {
                        self->cleanupOperation=false;
                        self->cleanupPending=true;
                        self->phase=QStringLiteral("failed"); self->output(Vpn::ConnectionState::Error,QStringLiteral("Не удалось подтвердить отключение. Нажмите «Повторить отключение»."));
                        return;
                    }
                    self->cleanupOperation=false;
                    self->retryCleanup(true);
                });
                return;
            }
        }
        // Reconcile the original encrypted record with its stored device authority.
        cleanupOperation=true;
        const quint64 generation=++cleanupGeneration;
        ad::Request request; request.action="reconcile"; request.attemptId=record.identity().attemptId;
        request.cycleToken=record.identity().cycleToken; request.commonPayload=payloadFor(record);
        const auto operationDeadline=qMin(now()+2500,cleanupDeadline);
        request.deadlineUtcMs=utcDeadline(operationDeadline);
        ++inFlight;
        auto self=shared_from_this();
        auto settled=std::make_shared<bool>(false);
        auto lateHandled=std::make_shared<bool>(false);
        auto timedOutSeen=std::make_shared<bool>(false);
        std::weak_ptr<Session> weak=self;
        auto finish=[weak,record,generation,settled,lateHandled,timedOutSeen](ad::Response response, bool timedOut) {
            auto self=weak.lock(); if (!self) return;
            if (*settled && !(timedOut == false && *timedOutSeen && response.success && response.authenticatedResponse && !*lateHandled)) return;
            const bool first=!(*settled); *settled=true;
            if (timedOut) *timedOutSeen=true;
            if (!first) *lateHandled=true;
            if (first) --self->inFlight;
            if (generation!=self->cleanupGeneration) return;
            if (first) self->cleanupOperation=false;
            // Another authenticated operation may already have durably settled
            // this exact record. A later negative/timeout cannot reopen it.
            if (self->finishCleanup()) return;
            if (timedOut) {
                self->cleanupPending=true;
                self->phase=QStringLiteral("failed"); self->output(Vpn::ConnectionState::Error,self->cleanupText());
                return;
            }
            if (!response.success || !response.authenticatedResponse ||
                !self->store->removeAfterConfirmedCleanup(record.identity()).ok) {
                self->cleanupPending=true;
                self->phase=QStringLiteral("failed"); self->output(Vpn::ConnectionState::Error,self->cleanupText());
                return;
            }
            self->cleanupPending=true;
            self->retryCleanup(true);
        };
        QTimer::singleShot(qMax<qint64>(0,operationDeadline-now()),this,[finish] { finish({},true); });
        ad::MayakAdmissionClient::postAsync(request,transport,[finish](ad::Response response) { finish(response,false); });
    }
    void fetchFresh(ac::CycleId c,ac::AttemptId a,ac::Millis deadline,FetchDone done) override {
        if (!adoption.pending) { fetch(c,a,deadline,0,std::move(done)); return; }
        auto self=shared_from_this();
        fetch(c,a,deadline,0,[self,done](ac::CycleId c,ac::AttemptId a,ac::FetchStatus status,ac::Snapshot s) mutable {
            if (!self->adoption.pending) { done(c,a,status,std::move(s)); return; }
            if (status==ac::FetchStatus::Success) {
                const QString want=self->adoption.identity.candidateId;
                const auto it=std::find_if(s.candidates.begin(),s.candidates.end(),[&](const ac::Candidate& x) {
                    return QString::fromStdString(x.id).compare(want,Qt::CaseInsensitive)==0; });
                // The coordinator preserves order: the adopted exit is admitted first.
                if (it!=s.candidates.end()) { std::rotate(s.candidates.begin(),it,it+1); done(c,a,status,std::move(s)); return; }
                self->logNet(QStringLiteral("event=adopt_abandon reason=candidate_absent"));
            } else self->logNet(QStringLiteral("event=adopt_abandon reason=fetch_failed"));
            self->abandonAdoption([done,c,a,status,s](bool ok) mutable {
                done(c,a,ok?status:ac::FetchStatus::NetworkError,ok?std::move(s):ac::Snapshot{});
            });
        });
    }
    void fetch(ac::CycleId c,ac::AttemptId a,ac::Millis deadline,int retry,FetchDone done) {
        auto self=shared_from_this();
        if(!identityCurrent() || now()>=deadline) { done(c,a,ac::FetchStatus::AuthRevoked,{}); return; }
        const int timeout=int(qMax<qint64>(1,deadline-now()));
        auto* watcher=new QFutureWatcher<GatewayPostResult>();
        ++inFlight;
        connect(watcher,&QFutureWatcher<GatewayPostResult>::finished,watcher,[self,watcher,c,a,deadline,retry,done]() mutable {
            const auto r=watcher->result(); watcher->deleteLater(); --self->inFlight;
            ad::AdmissionError err;
            if(ad::parseAdmissionError(r.body,r.authenticatedResponse,&err)) {
                if(err.code=="provisioning" && retry<2 && self->now()+1500<deadline && !self->cancelled) {
                    const int delay=qBound(250,err.retryAfterMs,2000);
                    QTimer::singleShot(delay,self.get(),[self,c,a,deadline,retry,done] { self->fetch(c,a,deadline,retry+1,done); }); return;
                }
                done(c,a,err.code=="REVOKED"?ac::FetchStatus::AuthRevoked:err.code=="ACCOUNT_EXPIRED"?ac::FetchStatus::AccountExpired:ac::FetchStatus::NetworkError,{}); return;
            }
            ad::ConnectionCapability cap;
            if(!r.authenticatedResponse || !ad::parseConnectionCapability(r.body,QDateTime::currentDateTimeUtc(),&cap)) {
                done(c,a,ac::FetchStatus::NetworkError,{}); return;
            }
            ac::Snapshot s; s.schemaVersion=cap.schema; s.revision=QString::number(cap.revision).toStdString();
            s.expiresAt=self->now()+QDateTime::currentDateTimeUtc().msecsTo(cap.expiresAt);
            for(const auto& v:cap.candidates) {
                ac::Candidate x{v.id.toStdString(),v.host.toStdString(),v.port,v.preferred,{}};
                for(const auto& ip:v.expectedEgressIps) x.expectedEgressIps.push_back(ip.toStdString());
                s.candidates.push_back(std::move(x));
            }
            avoidedExitStorage().knownExits=int(s.candidates.size());
            // Failover: an exit that just stopped working is tried last (server order otherwise).
            if (!self->adoption.pending && s.candidates.size()>1 && self->now()<avoidedExitStorage().until) {
                const QString avoid=avoidedExitStorage().candidateId;
                std::stable_partition(s.candidates.begin(),s.candidates.end(),[&avoid](const ac::Candidate& x) {
                    return QString::fromStdString(x.id).compare(avoid,Qt::CaseInsensitive)!=0; });
            }
            done(c,a,ac::FetchStatus::Success,std::move(s));
        });
        watcher->setFuture(transport(QStringLiteral("%1v1/config"),ad::buildMayakConfigPayload(common),timeout));
    }
    void acquire(ac::CycleId c,ac::AttemptId n,const ac::Candidate& candidate,ac::Millis deadline,AdmissionDone done) override {
        auto self=shared_from_this();
        if (adoption.pending) {
            if (QString::fromStdString(candidate.id).compare(adoption.identity.candidateId,Qt::CaseInsensitive)==0) {
                acquireAdopted(c,n,candidate,deadline,std::move(done)); return;
            }
            logNet(QStringLiteral("event=adopt_abandon reason=other_candidate"));
            const auto chosen=candidate;
            abandonAdoption([self,c,n,chosen,deadline,done](bool ok) mutable {
                if (!ok) { done(c,n,{ac::AdmissionStatus::Malformed,{}}); return; }
                self->acquire(c,n,chosen,deadline,std::move(done));
            });
            return;
        }
        const auto loaded=store->load();
        // A lost earlier acquire may still own a slot. Never allocate over it.
        if(!identityCurrent() || !loaded.ok || !loaded.records.isEmpty()) { done(c,n,{ac::AdmissionStatus::Malformed,{}}); return; }
        auto a=std::make_shared<Attempt>(); a->candidate=candidate;
        a->identity={serverId,epoch,cycleToken,randomId(),QString::fromStdString(candidate.id)};
        a->ticket={a->identity.attemptId,std::make_shared<B::StartGate>()};
        if(!store->appendBeforeAcquire({a->identity,authority,false,false,{}}).ok) { done(c,n,{ac::AdmissionStatus::Malformed,{}}); return; }
        attempts[{c,n}]=a;
        ad::Request request; request.action="acquire"; request.attemptId=a->identity.attemptId; request.cycleToken=cycleToken;
        request.candidateId=a->identity.candidateId; request.commonPayload=common; request.deadlineUtcMs=utcDeadline(deadline);
        request.requestPaths=method!=QStringLiteral("awg");
        ++inFlight;
        ad::MayakAdmissionClient::postAsync(request,transport,[self,a,c,n,done](ad::Response r) mutable {
            --self->inFlight;
            if(r.authenticatedResponse && r.acquireValid && r.success) {
                a->allocation=r.acquire.allocationId; a->encodedConfig=r.acquire.encodedConfig;
                if (r.acquire.exitLocationCandidateId.compare(a->identity.candidateId, Qt::CaseInsensitive) == 0)
                    a->exitLocationCityId = r.acquire.exitLocationCityId;
                a->connectBefore=self->now()+QDateTime::currentDateTimeUtc().msecsTo(r.acquire.connectBefore);
                // Pre-send record remains sufficient for exact cleanup if this write fails.
                const bool saved=self->store->attachAllocation(a->identity,a->allocation).ok;
                ac::Allocation allocation{a->allocation.toStdString(), saved?a->encodedConfig.toStdString():std::string{}, {}, false};
                self->planPaths(a,r.acquire,&allocation);
                done(c,n,{ac::AdmissionStatus::Admitted,std::move(allocation)}); return;
            }
            ac::AdmissionStatus status=ac::AdmissionStatus::Malformed;
            if(r.authenticatedResponse && r.isError) {
                if(r.error.code=="FULL") status=ac::AdmissionStatus::Full;
                else if(r.error.code=="NOT_READY") status=ac::AdmissionStatus::NotReady;
                else if(r.error.code=="DISABLED") status=ac::AdmissionStatus::Disabled;
                else if(r.error.code=="REVOKED") status=ac::AdmissionStatus::AuthRevoked;
                else if(r.error.code=="ACCOUNT_EXPIRED") status=ac::AdmissionStatus::AccountExpired;
                if(status!=ac::AdmissionStatus::Malformed && !self->store->removeAfterConfirmedCleanup(a->identity).ok) status=ac::AdmissionStatus::Malformed;
            }
            // Unknown/lost reply retains record and terminates; next user retry reconciles.
            done(c,n,{status,{}});
        });
    }
    // Idempotent acquire of the adopted attempt: same attempt id and cycle token, so the server
    // re-validates account/device/exit and must return the SAME allocation (no new slot).
    void acquireAdopted(ac::CycleId c,ac::AttemptId n,const ac::Candidate& candidate,ac::Millis deadline,AdmissionDone done) {
        auto self=shared_from_this();
        if (!identityCurrent()) {
            abandonAdoption([done,c,n](bool) { done(c,n,{ac::AdmissionStatus::Malformed,{}}); }); return;
        }
        auto a=std::make_shared<Attempt>(); a->candidate=candidate; a->identity=adoption.identity; a->adopted=true;
        a->ticket={a->identity.attemptId,std::make_shared<B::StartGate>()};
        attempts[{c,n}]=a;
        ad::Request request; request.action="acquire"; request.attemptId=a->identity.attemptId; request.cycleToken=a->identity.cycleToken;
        request.candidateId=a->identity.candidateId; request.commonPayload=common; request.deadlineUtcMs=utcDeadline(deadline);
        request.resumeAllocation=true; // the allocation's original connect_before is long past
        ++inFlight;
        logNet(QStringLiteral("event=adopt_acquire"));
        ad::MayakAdmissionClient::postAsync(request,transport,[self,a,c,n,done](ad::Response r) mutable {
            --self->inFlight;
            if (r.authenticatedResponse && r.acquireValid && r.success &&
                r.acquire.allocationId==self->adoption.allocationId && self->adoption.pending) {
                a->allocation=r.acquire.allocationId; a->encodedConfig=r.acquire.encodedConfig;
                if (r.acquire.exitLocationCandidateId.compare(a->identity.candidateId, Qt::CaseInsensitive) == 0)
                    a->exitLocationCityId = r.acquire.exitLocationCityId;
                a->connectBefore=self->now()+qMax<qint64>(15000,QDateTime::currentDateTimeUtc().msecsTo(r.acquire.connectBefore));
                // The adopted backend is the AWG one that is already running.
                done(c,n,{ac::AdmissionStatus::Admitted,{a->allocation.toStdString(),a->encodedConfig.toStdString(),
                    {{"awg",ac::PathKind::Awg}},true}}); return;
            }
            ac::AdmissionStatus status=ac::AdmissionStatus::NetworkError;
            if (r.authenticatedResponse && r.isError) {
                if (r.error.code=="FULL") status=ac::AdmissionStatus::Full;
                else if (r.error.code=="NOT_READY") status=ac::AdmissionStatus::NotReady;
                else if (r.error.code=="DISABLED") status=ac::AdmissionStatus::Disabled;
                else if (r.error.code=="REVOKED") status=ac::AdmissionStatus::AuthRevoked;
                else if (r.error.code=="ACCOUNT_EXPIRED") status=ac::AdmissionStatus::AccountExpired;
            } else if (r.authenticatedResponse && r.success) status=ac::AdmissionStatus::NotReady; // a different allocation
            self->logNet(QStringLiteral("event=adopt_abandon reason=acquire status=%1").arg(int(status)));
            a->cancelled=true;
            // Stop the backend and release the attempt (reconcile releases every allocation of it).
            self->abandonAdoption([done,c,n,status](bool ok) { done(c,n,{ok?status:ac::AdmissionStatus::Malformed,{}}); });
        });
    }
    std::shared_ptr<Attempt> get(ac::CycleId c,ac::AttemptId a) {
        auto i=attempts.find({c,a}); return i==attempts.end()?nullptr:i->second;
    }
    // Orders the paths of a fresh allocation by the connection method and the path memory.
    void planPaths(const std::shared_ptr<Attempt>& a,const ad::AcquireResponse& acquired,ac::Allocation* allocation) {
        a->xray.clear();
        for (const auto& p:acquired.xrayPaths) {
            XrayEntry entry{p,{}}; QString reason;
            if (ad::decodeXrayPathConfig(p,QString::fromStdString(a->candidate.publicIpv4),&entry.config,&reason)) a->xray.push_back(entry);
            else logNet(QStringLiteral("event=xray_path_rejected path=%1 reason=%2").arg(p.id,reason));
        }
        if (acquired.xrayPathsOffered && !acquired.xrayPathsRejected.isEmpty())
            logNet(QStringLiteral("event=xray_paths_rejected reason=%1").arg(acquired.xrayPathsRejected));
        std::vector<ac::Path> xray;
        for (const auto& e:a->xray) xray.push_back({e.path.id.toStdString(),ac::PathKind::Xray});
        const ac::Path awg{"awg",ac::PathKind::Awg};
        allocation->pathsExplicit=true;
        if (method==QStringLiteral("awg")) allocation->paths={awg};
        else if (method==QStringLiteral("xray")) allocation->paths=xray;
        else if (rememberedXrayFirst(settings,networkKey)) { allocation->paths=xray; allocation->paths.push_back(awg); }
        else { allocation->paths={awg}; allocation->paths.insert(allocation->paths.end(),xray.begin(),xray.end()); }
        // The service does not enforce connect_before; a later path of this allocation still
        // belongs to the same admitted place on the exit.
        if (!xray.empty()) a->connectBefore=qMax(a->connectBefore,now()+ac::Coordinator::timing().cycleWithXrayMs);
        QStringList order; for (const auto& p:allocation->paths) order<<QString::fromStdString(p.id);
        logNet(QStringLiteral("event=paths order=%1").arg(order.join(',')));
    }
    // A later path of the same attempt gets a fresh backend ticket and clean per-start state.
    void preparePathStart(const std::shared_ptr<Attempt>& a,const ac::Path& path) {
        if (a->pathStarts>0) {
            a->ticket={a->identity.attemptId+QStringLiteral("-p")+QString::number(a->pathStarts),std::make_shared<B::StartGate>()};
            a->started=false; a->stopped=false; a->cancelled=false; a->stopTicket={};
            a->health={}; a->healthAt=0; a->expected={}; a->reset=false; a->rxChangedAt=0; a->replacementAllowedUntil=0;
            a->proofDone={}; a->probing=false; a->tlsOk=false; a->proof={};
        }
        ++a->pathStarts; a->path=path;
    }
    void start(ac::CycleId c,ac::AttemptId n,const ac::Allocation& allocation,const ac::Path& path,ac::Millis deadline,StartDone done) override {
        auto a=get(c,n);
        if (!a || cancelled) { done(c,n,{ac::StartStatus::MalformedConfig}); return; }
        if (!appExclusionBlocked && mayak::split::appExclusionFailedSince(sessionStartMono)) {
            // The service could not apply app exclusions: no further path (Xray ignores them on Windows).
            appExclusionBlocked=true; reconnectWanted=false; connectRetryAt=0; localStartFailed=false;
            logNet(QStringLiteral("event=app_exclusion_unavailable at=path_start"));
            QTimer::singleShot(0,this,[weak=weak_from_this()] { if (auto self=weak.lock(); self && self->coordinator) self->coordinator->cancel(); });
            return;
        }
        if (a->path.kind==ac::PathKind::Awg && a->pathStarts>0 && !a->adopted) a->awgFailedHere=true;
        preparePathStart(a,path);
        // Never start a tunnel while the race engine still runs: wait for its stop (bounded by the
        // race stop deadline), then start.
        if (race.engineActive) {
            auto self=shared_from_this(); const auto copy=allocation; const auto p=path;
            race.afterStop=[self,c,n,copy,p,deadline,done]() mutable { self->startPath(c,n,copy,p,deadline,std::move(done)); };
            return;
        }
        startPath(c,n,allocation,path,deadline,std::move(done));
    }
    void startPath(ac::CycleId c,ac::AttemptId n,const ac::Allocation& allocation,const ac::Path& path,ac::Millis deadline,StartDone done) {
        auto a=get(c,n);
        if (!a || a->cancelled || cancelled) { done(c,n,{ac::StartStatus::MalformedConfig}); return; }
        if (path.kind==ac::PathKind::Xray) { startXray(c,n,path,deadline,std::move(done)); return; }
        if (a->adopted) { startAdopted(c,n,deadline,std::move(done)); return; }
        startNew(c,n,allocation,deadline,std::move(done));
    }
    void startXray(ac::CycleId c,ac::AttemptId n,const ac::Path& path,ac::Millis deadline,StartDone done) {
        auto self=shared_from_this(); auto a=get(c,n);
        const auto entry=std::find_if(a->xray.begin(),a->xray.end(),[&path](const XrayEntry& e){ return e.path.id.toStdString()==path.id; });
        if (entry==a->xray.end() || !identityCurrent() || a->cancelled) { done(c,n,{ac::StartStatus::MalformedConfig}); return; }
        QJsonObject config;
        if (connection->prepareMayakXrayConnection(serverId,entry->config.root,config)!=ErrorCode::NoError ||
            !identityCurrent() || !store->markMayHaveStarted(a->identity).ok) {
            done(c,n,{ac::StartStatus::MalformedConfig}); return;
        }
        a->started=true; a->startMono=now(); a->startUtc=QDateTime::currentMSecsSinceEpoch();
        bridge->startPrepared(a->ticket,serverId,config,qMin<qint64>(deadline,a->connectBefore),[self,a,c,n,done](B::Result r) {
            a->expected=r.expected;
            done(c,n,{r.outcome==B::Outcome::Started?ac::StartStatus::Started:ac::StartStatus::NetworkError});
        });
    }
    // Hand the running backend to the adopted attempt: the service confirms control identity +
    // ticket and soft-replaces the backend (new socket, same TUN), so the normal proof below
    // sees a handshake newer than startUtc. Refusal: stop it with the recovery ticket.
    void startAdopted(ac::CycleId c,ac::AttemptId n,ac::Millis deadline,StartDone done) {
        auto self=shared_from_this(); auto a=get(c,n);
        // The allocation is already admitted to this attempt: the coordinator's normal release
        // frees it and the ledger record. Here only the backend is stopped (recovery ticket).
        const auto giveUp=[self,a,c,n,done](const QString& reason) {
            self->logNet(QStringLiteral("event=adopt_abandon reason=%1").arg(reason));
            const bool pending=self->adoption.pending; const auto recovery=self->adoption.recovery;
            self->adoption.pending=false;
            if (!pending || !a) { done(c,n,{ac::StartStatus::MalformedConfig}); return; }
            self->bridge->stopAndConfirm(recovery,self->now()+3000,[self,a,c,n,done,recovery](B::Result s) {
                if (s.outcome==B::Outcome::ConfirmedDown && recovery.same(s.ticket)) {
                    self->preflightNativeOff=true; a->started=false; a->stopped=true;
                } else {
                    // Unconfirmed: the coordinator's stop must not claim it is down, and it must
                    // retry with the authority that still owns the backend (the recovery ticket).
                    a->started=true; a->stopTicket=recovery;
                }
                done(c,n,{ac::StartStatus::MalformedConfig});
            });
        };
        if (!a || !adoption.pending || !identityCurrent() || a->cancelled || now()>=a->connectBefore) { giveUp(QStringLiteral("start_precondition")); return; }
        const auto err=subscription->applyMayakAcquireConfig(serverId,keys,a->encodedConfig,QString::fromStdString(a->candidate.publicIpv4),a->candidate.port);
        QJsonObject config; DockerContainer container;
        if (err!=ErrorCode::NoError || !identityCurrent() || connection->prepareConnection(serverId,config,container)!=ErrorCode::NoError
            || !ContainerUtils::isAwgContainer(container)) { giveUp(QStringLiteral("config")); return; }
        const auto recovery=adoption.recovery; const auto controlIdentity=adoption.controlIdentity;
        adoption.pending=false; // ownership transfer in flight: this callback owns every outcome
        a->started=true; a->startMono=now(); a->startUtc=QDateTime::currentMSecsSinceEpoch();
        logNet(QStringLiteral("event=adopt_request"));
        bridge->adopt(recovery,a->ticket,controlIdentity,config,qMin<qint64>(deadline,a->connectBefore),[self,a,c,n,done,recovery](B::Result r) {
            if (r.outcome==B::Outcome::Started) {
                a->expected=r.expected; self->preflightNativeOff=true; // no foreign backend remains
                self->logNet(QStringLiteral("event=adopt_ok"));
                done(c,n,{ac::StartStatus::Started}); return;
            }
            self->logNet(QStringLiteral("event=adopt_refused outcome=%1").arg(int(r.outcome)));
            self->bridge->stopAndConfirm(recovery,self->now()+3000,[self,a,c,n,done,recovery](B::Result s) {
                if (s.outcome==B::Outcome::ConfirmedDown && recovery.same(s.ticket)) {
                    // Down by the recovery authority: the coordinator's stop of this attempt is a no-op,
                    // and its normal release frees the allocation and the ledger record.
                    self->preflightNativeOff=true; a->started=false; a->stopped=true;
                } else a->stopTicket=recovery; // the transfer never completed: recovery still owns it
                done(c,n,{ac::StartStatus::NetworkError});
            });
        });
    }
    void startNew(ac::CycleId c,ac::AttemptId n,const ac::Allocation&,ac::Millis deadline,StartDone done) {
        auto self=shared_from_this(); auto a=get(c,n);
        if(!a || !identityCurrent() || a->cancelled || now()>=a->connectBefore) { done(c,n,{ac::StartStatus::MalformedConfig}); return; }
        const auto err=subscription->applyMayakAcquireConfig(serverId,keys,a->encodedConfig,QString::fromStdString(a->candidate.publicIpv4),a->candidate.port);
        QJsonObject config; DockerContainer container;
        if(err!=ErrorCode::NoError || !identityCurrent() || connection->prepareConnection(serverId,config,container)!=ErrorCode::NoError
           || !ContainerUtils::isAwgContainer(container) || !store->markMayHaveStarted(a->identity).ok) {
            done(c,n,{ac::StartStatus::MalformedConfig}); return;
        }
        a->started=true; a->startMono=now(); a->startUtc=QDateTime::currentMSecsSinceEpoch();
        bridge->startPrepared(a->ticket,serverId,config,qMin<qint64>(deadline,a->connectBefore),[self,a,c,n,done](B::Result r) {
            a->expected=r.expected;
            done(c,n,{r.outcome==B::Outcome::Started?ac::StartStatus::Started:ac::StartStatus::NetworkError});
        });
    }
    void verifyOwnTunnel(ac::CycleId c,ac::AttemptId n,const ac::Path&,const std::string& nonce,const std::vector<std::string>& ips,
                         ac::Millis deadline,ProofDone done) override {
        auto a=get(c,n); if(!a) { done(c,n,{}); return; }
        a->proofDone=std::move(done); a->nonce=QString::fromStdString(nonce); a->proofDeadline=deadline;
        a->egress.clear(); for(const auto& ip:ips) a->egress.append(QString::fromStdString(ip));
        a->tlsOk=false; a->probing=false; advanceProof({c,n},a);
    }
    // Xray: no peer telemetry. Proof = one probe bound to this path's own tunnel interface (as
    // reported for this ticket), started after the path started: nonce, TLS and expected egress.
    void advanceXrayProof(std::pair<ac::CycleId,ac::AttemptId> tag,const std::shared_ptr<Attempt>& a) {
        if(!a->proofDone || a->cancelled) return;
        if(now()>=a->proofDeadline || a->reset) { auto done=std::move(a->proofDone); done(tag.first,tag.second,{}); return; }
        if(!a->health.valid || !a->expected.matches(a->health)) return;
        if(!a->probing) {
            a->probing=true; a->probeStartedMono=now(); a->baselineRx=a->health.rxTotal; a->baselineTx=a->health.txTotal;
            MayakTunnelProbeRequest req; req.attemptTag=a->ticket.opaqueAttempt; req.localAddress=QHostAddress(a->health.localAddress.section('/',0,0));
            req.interfaceName=a->health.interfaceName; req.expectedEgressIpv4=a->egress; req.nonce=a->nonce;
            req.deadlineMs=int(qBound(qint64(1),qint64(a->proofDeadline-now()),qint64(8000)));
            auto self=shared_from_this();
            bridge->probe(a->ticket,req,a->proofDeadline,[self,a,tag](B::Ticket t,bool ok,MayakTunnelProbeProof proof,QString) {
                if(!a->ticket.same(t) || !a->proofDone || a->cancelled) return;
                if(!ok) { auto done=std::move(a->proofDone); done(tag.first,tag.second,{}); return; }
                a->tlsOk=true; a->proof=proof; self->advanceXrayProof(tag,a);
            });
            return;
        }
        if(!a->tlsOk) return;
        ac::ProofResult result; result.probeSucceeded=true;
        auto& e=result.evidence;
        e.certificateValid=a->proof.certificateVerified; e.nonceMatched=a->proof.nonce==a->nonce;
        e.nonce=a->nonce.toStdString(); e.observedEgressIp=a->proof.observedEgressIpv4.toStdString();
        e.rxBytesBefore=a->baselineRx; e.rxBytesAfter=a->health.rxTotal; e.counterReset=a->reset;
        e.pathId=a->path.id; e.probeStartedAt=a->probeStartedMono;
        e.interfaceBound=a->proof.attemptTag==a->ticket.opaqueAttempt && a->proof.interfaceName==a->health.interfaceName &&
            a->proof.localAddress==a->health.localAddress.section('/',0,0);
        auto done=std::move(a->proofDone); done(tag.first,tag.second,std::move(result));
    }
    void advanceProof(std::pair<ac::CycleId,ac::AttemptId> tag,const std::shared_ptr<Attempt>& a) {
        if (a->path.kind==ac::PathKind::Xray) { advanceXrayProof(tag,a); return; }
        if(!a->proofDone || a->cancelled) return;
        if(now()>=a->proofDeadline || a->reset) { auto done=std::move(a->proofDone); done(tag.first,tag.second,{}); return; }
        if(!a->health.valid || !a->expected.matches(a->health)) return;
        if(!a->probing) {
            a->probing=true; a->baselineRx=a->health.rxTotal; a->baselineTx=a->health.txTotal;
            MayakTunnelProbeRequest req; req.attemptTag=a->ticket.opaqueAttempt; req.localAddress=QHostAddress(a->health.localAddress.section('/',0,0));
            req.interfaceName=a->health.interfaceName; req.expectedEgressIpv4=a->egress; req.nonce=a->nonce;
            req.deadlineMs=int(qMax<qint64>(1,a->proofDeadline-now()));
            auto self=shared_from_this();
            bridge->probe(a->ticket,req,a->proofDeadline,[self,a,tag](B::Ticket t,bool ok,MayakTunnelProbeProof proof,QString) {
                if(!a->ticket.same(t) || !a->proofDone || a->cancelled) return;
                if(!ok) { auto done=std::move(a->proofDone); done(tag.first,tag.second,{}); return; }
                a->tlsOk=true; a->proof=proof; self->advanceProof(tag,a);
            });
        }
        if(!a->tlsOk || a->health.rxTotal<=a->baselineRx) return;
        const auto handshake=qint64(a->health.latestHandshakeEpochMs);
        // An independently established NEW activation context scopes the sample.
        // Backend timestamps may have one-second precision: reject any earlier
        // second, never convert an old handshake by stamping receipt time.
        const qint64 activationSecond=(a->startUtc/1000)*1000;
        const qint64 nowUtc=QDateTime::currentMSecsSinceEpoch();
        const bool clockSane=qAbs((nowUtc-a->startUtc)-(now()-a->startMono))<1500;
        // An adopted backend is not restarted (a new socket loses its first handshake and costs
        // seconds). Its session predates this attempt, so freshness is the live-session bound
        // instead: a handshake no older than WireGuard's reject-after-time (180 s), together with
        // the nonce/egress TLS probe through this interface and RX growth after it.
        const bool adoptedLive=a->adopted && handshake>0 && handshake<=nowUtc && nowUtc-handshake<=180000;
        const qint64 handshakeMono=adoptedLive && handshake<a->startUtc ? a->startMono-(a->startUtc-handshake)
                                                                          : a->startMono+qMax<qint64>(0,handshake-a->startUtc);
        const bool fresh=clockSane && ((handshake>=activationSecond && handshake<=nowUtc) || adoptedLive);
        ac::ProofResult result; result.probeSucceeded=fresh;
        result.evidence={a->proof.certificateVerified,a->proof.nonce==a->nonce,a->nonce.toStdString(),
            a->proof.observedEgressIpv4.toStdString(),a->expected.peerPublicKey.toStdString(),handshakeMono,
            a->baselineRx,a->health.rxTotal,a->reset,fresh};
        result.evidence.adoptedLiveSession=adoptedLive;
        auto done=std::move(a->proofDone); done(tag.first,tag.second,std::move(result));
    }
    void stopAndConfirm(ac::CycleId c,ac::AttemptId n,ac::Millis deadline,StopDone done) override {
        auto a=get(c,n); if(!a) { done(c,n,{false}); return; }
        if(!a->started) { a->stopped=true; done(c,n,{true}); return; }
        // A started backend that never got a single handshake answered (not the user's cancel):
        // this exit is unreachable from here; the next connects try it last.
        // (a->cancelled is set by the coordinator's own retry stop; the user's cancel is `cancelled`.)
        if (a->path.kind==ac::PathKind::Awg && !a->adopted && !a->health.valid && !cancelled && now()-a->startMono>=5000) {
            if (recoveryTimingStorage().noHealthMeansLocalFailure) {
                // Windows: no health = the tunnel interface never existed. Local, not the exit's fault.
                localStartFailed=true;
                logNet(QStringLiteral("event=local_start_failed waited_ms=%1").arg(now()-a->startMono));
            } else avoidCandidate(a->identity.candidateId,"no_handshake");
        }
        auto self=shared_from_this(); bridge->cancel(a->ticket);
        bridge->stopAndConfirm(a->ownTicket(),deadline,[self,a,c,n,done](B::Result r) {
            // Preserve exact observer evidence, but report this bounded call's
            // own result to the coordinator. A timed-out call must still fail;
            // a later OFF retry can use the retained evidence for reconciliation.
            const bool confirmed=self->noteNativeDown(a,r);
            done(c,n,{confirmed});
        });
    }
    void releaseAllocation(ac::CycleId c,ac::AttemptId n,const std::string& exact,BasicDone done) override {
        auto a=get(c,n);
        if(!a) { qInfo() << "MayakRelease started=false reason=attempt_missing"; return; }
        const bool allocationMatches=a->allocation==QString::fromStdString(exact);
        const bool cleanupConfirmed=!a->started || a->stopped;
        if(!allocationMatches || !cleanupConfirmed) {
            qInfo() << "MayakRelease started=false allocation_match=" << allocationMatches
                    << "cleanup_confirmed=" << cleanupConfirmed;
            return;
        }
        qInfo() << "MayakRelease started=true";
        if (!cleanupDeadline || now()>=cleanupDeadline) cleanupDeadline=now()+10000;
        a->releasePending=true; a->releaseCallbackHandled=false; a->releaseLateHandled=false;
        auto self=shared_from_this(); ad::Request req; req.action="release"; req.attemptId=a->identity.attemptId;
        req.cycleToken=a->identity.cycleToken; req.allocationId=a->allocation; req.commonPayload=common; req.deadlineUtcMs=utcDeadline(now()+2500);
        ++inFlight;
        const quint64 operation=++cleanupGeneration;
        a->releaseOperationId=operation;
        auto settled=std::make_shared<bool>(false);
        auto timedOutSeen=std::make_shared<bool>(false);
        std::weak_ptr<Session> weak=self;
        auto finish=[weak,a,c,n,done,settled,timedOutSeen,operation](ad::Response r, bool timedOut) {
            auto self=weak.lock(); if (!self) return;
            if (a->releaseOperationId!=operation) return;
            const bool first=!(*settled);
            if (!first && (timedOut || !*timedOutSeen || a->releaseLateHandled || !r.success || !r.authenticatedResponse)) return;
            if (first) *settled=true;
            if (timedOut) *timedOutSeen=true;
            else a->releaseLateHandled=true;
            if (first) { a->releaseCallbackHandled=true; a->releasePending=false; --self->inFlight; }
            if (timedOut) {
                self->cleanupPending=true; self->terminal=true;
                self->phase=QStringLiteral("failed");
                self->output(Vpn::ConnectionState::Error,self->cleanupText());
                return;
            }
            qInfo() << "MayakRelease result transport_enum=" << int(r.transportError)
                    << "authenticated=" << r.authenticatedResponse
                    << "response_valid=" << r.responseValid << "success=" << r.success;
            if(r.success && r.authenticatedResponse) {
                const auto removal=self->store->removeAfterConfirmedCleanup(a->identity);
                qInfo() << "MayakRelease ledger_remove attempted=true ok=" << removal.ok
                        << "error_enum=" << int(removal.error);
                if(removal.ok) {
                    const auto remaining=self->store->load();
                    if (!remaining.ok || !remaining.records.isEmpty()) {
                        self->cleanupPending=true;
                        if (self->cancelled) self->retryCleanup(true);
                    } else {
                        // Timely completion belongs to the coordinator. A late
                        // positive cannot resume its already terminal cycle.
                        if (first && done) done(c,n);
                        if (self->cancelled || !first) {
                            self->cleanupPending=true;
                            self->finishCleanup();
                        }
                    }
                } else {
                    self->cleanupPending=true; self->terminal=true;
                    self->phase=QStringLiteral("failed");
                    self->output(Vpn::ConnectionState::Error,QStringLiteral("Сервер подтвердил остановку; локальная запись очистки ожидает сохранения. Нажмите «Повторить отключение»."));
                }
            } else {
                qInfo() << "MayakRelease ledger_remove attempted=false reason=release_not_accepted";
                self->cleanupPending=true; self->terminal=true;
                self->phase=QStringLiteral("failed"); self->output(Vpn::ConnectionState::Error,self->cleanupText());
            }
        };
        QTimer::singleShot(2500,this,[finish] { finish({},true); });
        ad::MayakAdmissionClient::postAsync(req,transport,[finish](ad::Response response) { finish(response,false); });
    }
    void reportProven(ac::CycleId c,ac::AttemptId n,const std::string&,BasicDone done) override {
        auto a=get(c,n); if(!a) return;
        auto self=shared_from_this(); ad::Request req; req.action="proven"; req.attemptId=a->identity.attemptId;
        req.cycleToken=a->identity.cycleToken; req.allocationId=a->allocation; req.commonPayload=common; req.deadlineUtcMs=utcDeadline(now()+2500);
        ++inFlight;
        auto settled=std::make_shared<bool>(false);
        std::weak_ptr<Session> weak=self;
        auto finish=[weak,settled,c,n,done] {
            auto self=weak.lock(); if (!self || *settled) return;
            *settled=true; --self->inFlight;
            if (done && !self->terminal && !self->cancelled) done(c,n);
        };
        QTimer::singleShot(2500,this,finish);
        ad::MayakAdmissionClient::postAsync(req,transport,[finish](ad::Response) { finish(); });
    }
    void cancelOwned(ac::CycleId c,ac::AttemptId n) override {
        if (race.tag==std::make_pair(c,n)) stopRace();
        auto a=get(c,n); if(!a) return; a->cancelled=true; a->proofDone={}; bridge->cancel(a->ticket);
    }
    // ---------- Xray path race ----------
    // One xray engine with one password-protected loopback SOCKS entry per path (no tunnel, no
    // routes). Probes run in parallel through each entry; the first answers lead the order.
    void racePaths(ac::CycleId c,ac::AttemptId n,const std::vector<ac::Path>& paths,const std::vector<std::string>& egress,
                   ac::Millis deadline,RaceDone done) override {
        auto a=get(c,n);
        if (!a || cancelled || a->cancelled || !bridge->canRace() || race.engineActive || paths.size()<2) {
            logNet(QStringLiteral("event=race_skipped paths=%1").arg(paths.size()));
            done(c,n,{false,{}}); return;
        }
        struct Lane { std::string id; quint16 port=0; QString user,pass,nonce; int state=0; }; // 0 running, 1 ok, 2 failed
        auto lanes=std::make_shared<std::vector<Lane>>();
        QJsonArray inbounds,outbounds,rules;
        for (const auto& path:paths) {
            const auto entry=std::find_if(a->xray.begin(),a->xray.end(),[&path](const XrayEntry& e){ return e.path.id.toStdString()==path.id; });
            const quint16 port=freeLoopbackPort();
            if (entry==a->xray.end() || !port) continue;
            Lane lane{path.id,port,B::randomRequestId().left(16),B::randomRequestId().left(32),randomId(),0};
            const QString index=QString::number(lanes->size());
            inbounds.append(QJsonObject{{"tag","in-"+index},{"listen","127.0.0.1"},{"port",port},{"protocol","socks"},
                {"settings",QJsonObject{{"auth","password"},{"udp",false},
                    {"accounts",QJsonArray{QJsonObject{{"user",lane.user},{"pass",lane.pass}}}}}}});
            QJsonObject outbound=entry->config.clientJson.value("outbounds").toArray().first().toObject();
            outbound.insert("tag","out-"+index);
            outbounds.append(outbound);
            rules.append(QJsonObject{{"type","field"},{"inboundTag",QJsonArray{"in-"+index}},{"outboundTag","out-"+index}});
            lanes->push_back(lane);
        }
        if (lanes->size()<2) { done(c,n,{false,{}}); return; }
        // Rule 5: no access/DNS log (an empty "access" would log every destination to stdout).
        const QJsonObject config{{"log",QJsonObject{{"loglevel","warning"},{"access","none"},{"dnsLog",false}}},{"inbounds",inbounds},{"outbounds",outbounds},
            {"routing",QJsonObject{{"domainStrategy","AsIs"},{"rules",rules}}}};
        race={}; race.engineActive=true; race.requestId=randomId(); race.tag={c,n};
        const QString request=race.requestId;
        const qint64 started=now();
        auto self=shared_from_this();
        auto settled=std::make_shared<bool>(false);
        // Order: answered lanes first (answer order), then lanes still running; failed ones dropped.
        auto order=std::make_shared<std::vector<std::string>>();
        auto finish=[self,c,n,done,settled,lanes,order,request,started](bool ran) mutable {
            if (*settled) return; *settled=true;
            std::vector<std::string> result=*order;
            int failed=0;
            for (const auto& lane:*lanes) { if (lane.state==0) result.push_back(lane.id); if (lane.state==2) ++failed; }
            QStringList shown; for (const auto& id:result) shown<<QString::fromStdString(id);
            self->logNet(QStringLiteral("event=race_done ran=%1 order=%2 failed=%3 elapsed_ms=%4")
                .arg(ran ? 1 : 0).arg(shown.join(',')).arg(failed).arg(self->now()-started));
            if (self->race.requestId==request) self->stopRace();
            done(c,n,{ran,ran ? result : std::vector<std::string>{}});
        };
        const qint64 raceEnd=deadline-300; // leave the engine stop inside the coordinator's budget
        QTimer::singleShot(int(qMax<qint64>(0,raceEnd-now())),this,[finish,lanes]() mutable {
            for (auto& lane:*lanes) if (lane.state==0) lane.state=2; // no answer in time = failed
            finish(true);
        });
        bridge->raceStart(request,config,qMin<qint64>(raceEnd,now()+2500),[self,a,lanes,order,finish,request,egress,raceEnd](bool ok) mutable {
            if (self->race.requestId!=request || !self->race.engineActive) return;
            if (!ok) { self->logNet(QStringLiteral("event=race_engine_failed")); finish(false); return; }
            QStringList expected; for (const auto& ip:egress) expected<<QString::fromStdString(ip);
            for (std::size_t i=0;i<lanes->size();++i) {
                auto& lane=(*lanes)[i];
                auto* probe=new MayakTunnelProbe(self.get());
                self->race.probes.push_back(probe);
                QObject::connect(probe,&MayakTunnelProbe::finished,self.get(),[self,lanes,order,finish,i,probe,request](quint64,bool success,MayakTunnelProbeProof,QString) mutable {
                    probe->deleteLater();
                    if (self->race.requestId!=request) return;
                    auto& lane=(*lanes)[i];
                    if (lane.state!=0) return;
                    lane.state=success ? 1 : 2;
                    if (success) {
                        order->push_back(lane.id);
                        // The fastest path is known: the others keep their chance only as fallback.
                        if (order->size()==1) QTimer::singleShot(300,self.get(),[finish]() mutable { finish(true); });
                    }
                    if (std::all_of(lanes->begin(),lanes->end(),[](const auto& l){ return l.state!=0; })) finish(true);
                });
                MayakTunnelProbeRequest req; req.attemptTag=request; req.nonce=lane.nonce; req.expectedEgressIpv4=expected;
                req.socksPort=lane.port; req.socksUser=lane.user; req.socksPassword=lane.pass;
                req.deadlineMs=int(qBound(qint64(1),qint64(raceEnd-self->now()),qint64(8000)));
                probe->start(req);
            }
        });
    }
    void stopRace() {
        for (auto& probe:race.probes) if (probe) { probe->cancel(); probe->deleteLater(); }
        race.probes.clear();
        race.requestId.clear(); race.tag={0,0};
        if (!race.engineActive || race.stopping) return;
        race.stopping=true;
        auto self=shared_from_this();
        bridge->raceStop(QStringLiteral("stop"),now()+2000,[self](bool stopped) {
            self->race.stopping=false; self->race.engineActive=false;
            if (!stopped) self->logNet(QStringLiteral("event=race_stop_unconfirmed"));
            if (auto next=std::move(self->race.afterStop)) { self->race.afterStop={}; next(); }
        });
    }
    void logNet(const QString& text) const { qInfo().noquote() << QStringLiteral("MayakNet ") + text; }
    std::shared_ptr<Attempt> connectedAttempt() {
        if(!coordinator || cancelled || coordinator->status().state!=ac::State::Connected) return {};
        const auto s=coordinator->status(); return get(s.cycle,s.attempt);
    }
    void showRecovering() {
        if (rec.shown && rec.shownNoNetwork==rec.networkLost) return;
        rec.shown=true; rec.shownNoNetwork=rec.networkLost;
        // Beacon shows the verification animation; never the Connected city card.
        phase=QStringLiteral("verifying");
        output(Vpn::ConnectionState::Reconnecting, rec.networkLost ? QStringLiteral("Нет сети — ждём…")
                                                                  : QStringLiteral("Переподключение…"));
        logNet(QStringLiteral("event=ui_reconnecting no_network=%1").arg(rec.networkLost ? 1 : 0));
    }
    void onNetwork(const B::Ticket& ticket,bool available) {
        auto a=connectedAttempt();
        if (!a || !a->ticket.same(ticket) || a->cancelled) return;
        const auto& t=recoveryTimingStorage();
        if (!available) {
            if (!rec.networkLost) { rec.networkLost=true; rec.networkLostAt=now(); logNet(QStringLiteral("event=network_lost")); }
            return;
        }
        const bool wasLost=rec.networkLost;
        rec.networkLost=false; rec.networkChangedAt=now();
        // A genuinely new network earns a fresh recovery ladder, but an event caused by
        // (or racing) our own backend replacement never does: no recovery loop.
        if (!rec.lastRecoverAt || now()-rec.lastRecoverAt>=t.networkRecentMs) { rec.attempts=0; rec.nextAt=0; }
        rec.forceProbeAt=now()+t.networkSettleMs;
        if (wasLost && rec.shown) showRecovering(); // "no network" -> "reconnecting"
        logNet(QStringLiteral("event=network_validated after_loss=%1").arg(wasLost ? 1 : 0));
    }
    // The UI was hidden (Android froze this process; health was paused by the service).
    // Health age therefore says nothing about the tunnel, and a backend replaced meanwhile by
    // the service watchdog (same proof context) is one authorized generation change, not a reset.
    void onResume(const B::Ticket& ticket,bool replaced,bool available) {
        auto a=connectedAttempt();
        if (!a || !a->ticket.same(ticket) || a->cancelled) return;
        a->healthAt=now();
        if (replaced) { a->replacementAllowedUntil=now()+8000; a->rxChangedAt=now(); }
        rec.forceProbeAt=now()+(replaced ? 1500 : 500); // verify the tunnel right away
        logNet(QStringLiteral("event=ui_resume replaced=%1 no_network=%2").arg(replaced ? 1 : 0).arg(available ? 0 : 1));
        if (!available) onNetwork(ticket,false);
        else if (rec.networkLost) onNetwork(ticket,true);
    }
    void onVisibility(bool visible) {
        if (uiHidden==!visible) return;
        uiHidden=!visible;
        logNet(QStringLiteral("event=ui_%1").arg(visible ? QStringLiteral("visible") : QStringLiteral("hidden")));
        if (!visible) return;
        // Back in front: health resumes now; give it one interval before judging its age.
        if (auto a=connectedAttempt(); a && !a->cancelled) { a->healthAt=now(); lastMonitor=now(); }
    }
    void startRecover(const std::shared_ptr<Attempt>& a) {
        const auto& t=recoveryTimingStorage();
        rec.inFlight=true; rec.lastRecoverAt=now();
        const int attempt=++rec.attempts;
        a->replacementAllowedUntil=now()+t.recoverDeadlineMs+3000;
        logNet(QStringLiteral("event=recover_request attempt=%1").arg(attempt));
        const qint64 started=now();
        auto self=shared_from_this();
        bridge->recover(a->ticket,now()+t.recoverDeadlineMs,[self,a,attempt,started](B::Result r) {
            const auto& t=recoveryTimingStorage();
            self->rec.inFlight=false;
            const bool ok=r.outcome==B::Outcome::Started;
            if (!ok) a->replacementAllowedUntil=0;
            self->logNet(QStringLiteral("event=%1 attempt=%2 elapsed_ms=%3")
                .arg(ok ? QStringLiteral("recover_backend_ok") : QStringLiteral("recover_failed")).arg(attempt).arg(self->now()-started));
            const auto& backoff=t.recoverBackoffMs;
            self->rec.nextAt=self->now()+(attempt<backoff.size() ? backoff.at(attempt) : backoff.isEmpty() ? 0 : backoff.last());
            // Verify promptly; a new-generation health sample may move this earlier.
            if (ok && !self->rec.forceProbeAt) self->rec.forceProbeAt=self->now()+1500;
        });
    }
    void onMonitorResult(const std::shared_ptr<Attempt>& a,bool ok) {
        const auto& t=recoveryTimingStorage();
        if (ok) {
            if (rec.shown) {
                logNet(QStringLiteral("event=recovered outage_ms=%1 recover_attempts=%2").arg(now()-rec.outageStart).arg(rec.attempts));
                phase=QStringLiteral("connected");
                output(Vpn::ConnectionState::Connected,QStringLiteral("Подключено"),connectedLocation);
            }
            rec={}; return;
        }
        if (++rec.probeFailures==1) rec.outageStart=now();
        logNet(QStringLiteral("event=probe_failed consecutive=%1 no_network=%2").arg(rec.probeFailures).arg(rec.networkLost ? 1 : 0));
        if (rec.probeFailures>=2) showRecovering();
        const bool recentNetwork=rec.networkChangedAt && now()-rec.networkChangedAt<t.networkRecentMs;
        const qint64 rxStale=now()-a->rxChangedAt;
        // A single random failure is not enough unless the underlying network just changed.
        const bool stuck=!rec.networkLost && (recentNetwork || rec.probeFailures>=2) &&
            rxStale>=(recentNetwork ? t.stuckRxAfterNetworkMs : t.stuckRxMs);
        if (stuck && a->path.kind==ac::PathKind::Awg && bridge->canRecover() && !rec.inFlight && rec.attempts<t.recoverBackoffMs.size() && now()>=rec.nextAt) {
            showRecovering();
            startRecover(a);
        }
    }
    void monitor() {
        auto a=connectedAttempt();
        if(!a || !a->health.valid || a->probing && a->proofDone) return;
        // Hidden UI: no health arrives by design and the service watchdog owns stuck-tunnel
        // repair. A probe failure here must never turn into a full stop of a working tunnel.
        if (uiHidden) return;
        const auto& t=recoveryTimingStorage();
        // A loss without any later network event must not block recovery forever.
        if (rec.networkLost && now()-rec.networkLostAt>=t.networkLostExpiryMs) {
            rec.networkLost=false; logNet(QStringLiteral("event=network_lost_expired"));
            if (rec.shown) showRecovering();
        }
        if (rec.networkLost && now()-rec.networkLostAt>=t.noNetworkUiMs) showRecovering();
        if (monitorProbing || rec.inFlight) return;
        const bool forced=rec.forceProbeAt && now()>=rec.forceProbeAt;
        if (!forced && now()-lastMonitor<(rec.probeFailures>0 ? t.retryProbeMs : t.monitorMs)) return;
        rec.forceProbeAt=0;
        const auto s=coordinator->status();
        monitorProbing=true; lastMonitor=now(); auto self=shared_from_this();
        const auto rx=a->health.rxTotal,tx=a->health.txTotal;
        MayakTunnelProbeRequest req; req.attemptTag=a->ticket.opaqueAttempt; req.localAddress=QHostAddress(a->health.localAddress.section('/',0,0));
        req.interfaceName=a->health.interfaceName; req.expectedEgressIpv4=a->egress; req.nonce=randomId(); req.deadlineMs=int(t.probeDeadlineMs);
        bridge->probe(a->ticket,req,now()+t.probeDeadlineMs,[self,a,s,rx,tx](B::Ticket,bool ok,MayakTunnelProbeProof,QString) {
            self->monitorProbing=false; self->lastMonitor=self->now();
            if(!self->coordinator || self->cancelled || a->cancelled || self->uiHidden) return;
            const auto current=self->coordinator->status();
            if (current.state!=ac::State::Connected || current.cycle!=s.cycle || current.attempt!=s.attempt) return;
            // Idle RX or provider/API failure alone never tears down a tunnel.
            // Xray: no peer telemetry, and interface counters prove nothing (tun2socks answers TCP
            // locally on Windows; Android has none). A failed probe counts only while the network
            // is up and from the second failure in a row, so the third ends the path (2 degraded).
            const bool xray=a->path.kind==ac::PathKind::Xray;
            const bool degraded=xray ? (!ok && !self->rec.networkLost && self->rec.probeFailures>=1) :
                (a->reset || self->now()-a->healthAt>12000 ||
                (a->health.txTotal>tx && a->health.rxTotal==rx && QDateTime::currentMSecsSinceEpoch()-qint64(a->health.latestHandshakeEpochMs)>180000));
            if(!ok && degraded) {
                self->reconnectWanted=true;
                // If this ends the cycle, the next one tries another exit first.
                if (self->rec.probeFailures>=1) self->avoidCandidate(a->identity.candidateId);
            }
            self->onMonitorResult(a,ok);
            self->coordinator->onConnectedProbe(s.cycle,ok,degraded);
            if(ok) self->reconnectWanted=false;
        });
    }
};

MayakAutoConnectRuntime::MayakAutoConnectRuntime(SecureQSettings* settings,SecureServersRepository* servers,
    SecureAppSettingsRepository* app,SubscriptionController* subscription,ConnectionController* connection,
    B::Port port,QObject* parent,ad::Transport transport)
    : QObject(parent),m_settings(settings),m_servers(servers),m_app(app),m_subscription(subscription),m_connection(connection),m_port(std::move(port)),
      m_transport(transport?std::move(transport):gatewayTransport()) {}
MayakAutoConnectRuntime::~MayakAutoConnectRuntime() {
    if(m_session) { m_session->facade=nullptr; m_session->stopUser(); m_session->coordinator.reset(); }
}
MayakAutoConnectRuntime::RecoveryTiming MayakAutoConnectRuntime::recoveryTiming() { return recoveryTimingStorage(); }
void MayakAutoConnectRuntime::setRecoveryTimingForTests(const RecoveryTiming& timing) { recoveryTimingStorage()=timing; }
void MayakAutoConnectRuntime::resetFailoverMemoryForTests() { avoidedExitStorage()={}; }
void MayakAutoConnectRuntime::setSplitPrepareForTests(std::function<void(QObject*, std::function<void(bool, QString)>)> hook) {
    splitPrepareStorage()=std::move(hook);
}
bool MayakAutoConnectRuntime::manages(const QString& id) const { return m_app && m_app->isMayakManagedServer(id); }
bool MayakAutoConnectRuntime::busy() const { return m_session && (m_session->cleanupPending || !m_session->terminal || m_session->inFlight>0); }
void MayakAutoConnectRuntime::publish(Vpn::ConnectionState state,const QString& text,const QString& phase,
                                      const QVariantMap& exitLocation) {
    m_message=text;
    m_connectionPhase=phase;
    m_exitLocation = state == Vpn::ConnectionState::Connected ? exitLocation : QVariantMap{};
    emit stateChanged(state,text);
}
void MayakAutoConnectRuntime::begin(const QString& id) {
    if(m_session && m_session->cleanupPending) return;
    if(busy()) return;
    if(m_session) { m_session->facade=nullptr; m_session->coordinator.reset(); m_session.reset(); }
    m_connectionPhase=QStringLiteral("preparing");
    m_session=std::make_shared<Session>(this,id); m_session->initialize();
}
void MayakAutoConnectRuntime::cancel() { if(m_session) m_session->stopUser(); }
bool MayakAutoConnectRuntime::cleanupPending() const { return m_session && m_session->cleanupPending; }
void MayakAutoConnectRuntime::retryCleanup() { if(m_session) m_session->userRetryCleanup(); }
void MayakAutoConnectRuntime::shutdown() {
    cancel();
    QElapsedTimer elapsed; elapsed.start();
    while(busy() && elapsed.elapsed()<5000) {
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents,20);
        QThread::msleep(5);
    }
    // Unconfirmed cleanup remains encrypted for reconciliation at next startup.
}
