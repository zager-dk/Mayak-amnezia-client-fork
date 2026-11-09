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
#include <map>

namespace ac = mayak::autoconnect;
namespace ad = mayak::admission;
namespace at = mayak::attempts;
using B = MayakBackendBridge;
using amnezia::ErrorCode;
namespace {
QString randomId() { return B::randomRequestId(); }
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
    ad::Transport transport;
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
    quint64 cleanupGeneration = 0;
    QString permissionRequestId;
    qint64 preflightDeadline = 0, lastMonitor = 0;
    struct Attempt {
        at::AttemptIdentity identity;
        ac::Candidate candidate;
        QString allocation;
        QString encodedConfig;
        qint64 connectBefore = 0;
        B::Ticket ticket;
        AwgHealthContext expected;
        AwgTunnelHealth health;
        qint64 startMono = 0, startUtc = 0, healthAt = 0;
        bool started = false, stopped = false, cancelled = false, probing = false;
        bool releasePending = false, releaseCallbackHandled = false;
        bool reset = false;
        quint64 baselineRx = 0, baselineTx = 0;
        ProofDone proofDone;
        QString nonce;
        QStringList egress;
        qint64 proofDeadline = 0;
        bool tlsOk = false;
        MayakTunnelProbeProof proof;
        bool acceptNativeDown(const B::Result& result) {
            // The Ticket is immutable for this attempt. Native OFF evidence is
            // monotonic across observer, original stop and cleanup retry ingress;
            // a different operation's Unknown/Deadline cannot revoke it.
            if (result.outcome!=B::Outcome::ConfirmedDown || !ticket.same(result.ticket)) return false;
            stopped=true;
            return true;
        }
    };
    std::map<std::pair<ac::CycleId,ac::AttemptId>, std::shared_ptr<Attempt>> attempts;

    explicit Session(MayakAutoConnectRuntime* f, QString id)
        : facade(f), servers(f->m_servers), app(f->m_app), connection(f->m_connection),
          subscription(f->m_subscription), transport(f->m_transport), store(new at::MayakAttemptStore(f->m_settings)),
          bridge(new B(f->m_port)), serverId(std::move(id)), epoch(randomId()), cycleToken(randomId()) {
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
            if (coordinator) coordinator->tick();
            // Retry starts only after exact release acknowledgement and fresh fetch.
            if (reconnectWanted && coordinator && coordinator->status().state == ac::State::Failed && !inFlight) {
                const auto loaded=store->load();
                if (loaded.ok && loaded.records.isEmpty()) { reconnectWanted=false; terminal=false; coordinator->begin(); }
            }
            for (auto& [tag,a]:attempts) {
                if (a->proofDone) advanceProof(tag,a);
            }
            monitor();
        });
        connect(bridge.get(),&B::health,this,[this](B::Ticket ticket,AwgTunnelHealth h) {
            for(auto& [tag,a]:attempts) {
                if (!a->ticket.same(ticket) || !a->expected.matches(h) || !h.valid || a->cancelled) continue;
                if (a->health.valid && (h.generation!=a->health.generation || h.rxTotal<a->health.rxTotal || h.txTotal<a->health.txTotal)) a->reset=true;
                a->health=h; a->healthAt=now();
            }
        });
        connect(bridge.get(),&B::error,this,[this](const B::Result& r) {
            if (!coordinator) return;
            if (r.detail==QStringLiteral("permissionDenied")) { cancelled=true; coordinator->cancel(); }
        });
        connect(bridge.get(),&B::backendDown,this,[this](const B::Result& r) {
            for(auto& [tag,a]:attempts) a->acceptNativeDown(r);
        });
    }
    ac::Millis now() const override { return B::monotonicMillis(); }
    QString phase = QStringLiteral("preparing");
    void output(Vpn::ConnectionState state,QString text) { if (facade) facade->publish(state,text,phase); }
    bool identityCurrent() const {
        if (!facade || !servers || !app || !connection || cancelled || app->mayakSessionToken().isEmpty()) return false;
        const auto cfg=servers->apiV2Config(serverId);
        return facade->manages(serverId) && cfg && cfg->authData.toJson()==common.value("auth_data").toObject() &&
            cfg->serviceType()==common.value("service_type").toString() &&
            cfg->apiConfig.serviceProtocol==common.value("service_protocol").toString() &&
            cfg->apiConfig.userCountryCode==common.value("user_country_code").toString();
    }
    void failure(QString text) { preparing=false; terminal=true; phase=QStringLiteral("failed"); output(Vpn::ConnectionState::Error,std::move(text)); }
    void beginCoordinatorAfterPreflight() {
        if (cancelled || !identityCurrent()) {
            preparing=false; terminal=true;
            phase=cancelled ? QStringLiteral("cancelled") : QStringLiteral("idle");
            output(Vpn::ConnectionState::Disconnected,{}); return;
        }
        coordinator=std::make_unique<ac::Coordinator>(*this,*this,[weak=weak_from_this()](const ac::Status& s) {
            if(auto self=weak.lock()) self->state(s);
        });
        preparing=false;
        coordinator->begin();
    }
    void preparePermissionsAndBeginCoordinator() {
        if (cancelled || permissionPending || coordinator) return;
        if (!identityCurrent()) { failure(QStringLiteral("Сеанс Маяка изменился. Войдите снова и повторите попытку.")); return; }
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
                self->failure(QStringLiteral("Разрешение VPN не выдано. Нажмите «Включить Маяк» и разрешите подключение.")); return;
            }
            if (result!=B::PermissionResult::Ready) {
                self->failure(QStringLiteral("Не удалось подготовить разрешение VPN. Повторите попытку.")); return;
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
        preflightDeadline=now()+10000;
        bridge->inspectOwnBackend(now()+3000,[self](B::Inspection i) {
            if (i.state==B::OwnState::Off) self->reconcileNext();
            else if (i.state==B::OwnState::Active && i.recoveryTicket.valid()) {
                self->bridge->cancel(i.recoveryTicket);
                self->bridge->stopAndConfirm(i.recoveryTicket,self->now()+3000,[self](B::Result r) {
                    if(r.outcome==B::Outcome::ConfirmedDown) self->reconcileNext();
                    else self->failure(errorText(ac::ErrorCategory::StopUnconfirmed));
                });
            } else {
#ifdef Q_OS_ANDROID
                self->failure(QStringLiteral("Служба VPN Android не ответила. Закройте и снова откройте Маяк. Если ошибка повторится, проверьте обновления."));
#else
                self->failure(QStringLiteral("Служба VPN не отвечает. Перезапустите приложение; на Windows проверьте установку Маяка."));
#endif
            }
        });
        timer.start();
    }
    void reconcileNext() {
        if (cancelled) return;
        auto self=shared_from_this();
        const auto loaded=store->load();
        if (!loaded.ok) { failure(QStringLiteral("Хранилище доступа недоступно. Подключение остановлено.")); return; }
        if (!loaded.records.isEmpty()) {
            if (now()>=preflightDeadline) { failure(QStringLiteral("Завершаем прежнее подключение. Повторите попытку.")); return; }
            const auto r=loaded.records.first();
            ad::Request req; req.action="reconcile"; req.attemptId=r.identity().attemptId; req.cycleToken=r.identity().cycleToken;
            req.commonPayload=payloadFor(r); req.deadlineUtcMs=utcDeadline(preflightDeadline);
            ++inFlight;
            ad::MayakAdmissionClient::postAsync(req,transport,[self,r](ad::Response response) {
                --self->inFlight;
                if (self->cancelled) return;
                if (!response.success || !response.authenticatedResponse || !self->store->removeAfterConfirmedCleanup(r.identity()).ok) {
                    self->failure(QStringLiteral("Не удалось завершить прежний сеанс. Проверьте интернет и повторите попытку.")); return;
                }
                self->reconcileNext();
            }); return;
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
        case ac::State::Starting: phase=QStringLiteral("starting"); break;
        case ac::State::Verifying: phase=QStringLiteral("verifying"); break;
        case ac::State::Connected: phase=QStringLiteral("connected"); break;
        case ac::State::Stopping: phase=QStringLiteral("stopping"); break;
        case ac::State::Failed: phase=QStringLiteral("failed"); break;
        case ac::State::Cancelled: phase=QStringLiteral("cancelled"); break;
        }
        switch(s.state) {
        case ac::State::Fetching: case ac::State::Admitting:
            terminal=false; output(Vpn::ConnectionState::Preparing,QStringLiteral("Выбираем доступный сервер…")); break;
        case ac::State::Starting: case ac::State::Verifying:
            output(Vpn::ConnectionState::Connecting,QStringLiteral("Проверяем VPN-соединение…")); break;
        case ac::State::Connected:
            lastMonitor=now(); output(Vpn::ConnectionState::Connected,QStringLiteral("Подключено")); break;
        case ac::State::Stopping:
            output(Vpn::ConnectionState::Disconnecting,QStringLiteral("Завершаем подключение…")); break;
        case ac::State::Failed:
            terminal=true;
            if (s.error==ac::ErrorCategory::StopUnconfirmed) {
                cleanupPending=true;
                auto attempt=get(s.cycle,s.attempt);
                output(Vpn::ConnectionState::Error,attempt && attempt->stopped
                    ? QStringLiteral("Туннель остановлен; очистка доступа на сервере ожидает повтора.")
                    : QStringLiteral("Не удалось подтвердить отключение. Нажмите «Повторить отключение»."));
            } else output(Vpn::ConnectionState::Error,errorText(s.error));
            break;
        case ac::State::Cancelled: case ac::State::Idle:
            terminal=true; output(Vpn::ConnectionState::Disconnected,{}); break;
        }
    }
    void stopUser() {
        cancelled=true; reconnectWanted=false;
        if (!permissionRequestId.isEmpty()) {
            bridge->cancelPermissionPreparation(permissionRequestId);
            permissionRequestId.clear(); permissionPending=false;
        }
        for(auto& [tag,a]:attempts) { a->cancelled=true; if(a->ticket.valid()) bridge->cancel(a->ticket); }
        if(coordinator) coordinator->cancel();
        else { preparing=false; terminal=true; timer.stop(); phase=QStringLiteral("cancelled"); output(Vpn::ConnectionState::Disconnected,{}); }
    }
    void retryCleanup() {
        if (!cleanupPending || cleanupOperation || !facade) return;
        // The coordinator owns its first exact release request. Never race it
        // with reconciliation of the same encrypted attempt.
        for (const auto& [tag,attempt] : attempts)
            if (attempt->releasePending) return;
        const auto loaded=store->load();
        if (!loaded.ok || loaded.records.isEmpty()) {
            bool confirmed=false;
            for (const auto& [tag,attempt] : attempts)
                if (attempt->stopped && !attempt->allocation.isEmpty()) { confirmed=true; break; }
            if (loaded.ok && confirmed) {
                cleanupPending=false; cancelled=true; terminal=true; timer.stop();
                phase=QStringLiteral("cancelled");
                output(Vpn::ConnectionState::Disconnected,{});
            } else { phase=QStringLiteral("failed"); output(Vpn::ConnectionState::Error,QStringLiteral("Не удалось проверить сохранённую очистку. Отключение остаётся неподтверждённым.")); }
            return;
        }
        const auto record=loaded.records.first();
        if (record.mayHaveStarted()) {
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
                bridge->stopAndConfirm(attempt->ticket,now()+3000,[self,attempt,generation](B::Result result) {
                    attempt->acceptNativeDown(result);
                    if (generation!=self->cleanupGeneration) {
                        if (attempt->stopped && !self->cleanupOperation) self->retryCleanup();
                        return;
                    }
                    if (!attempt->stopped) {
                        self->cleanupOperation=false;
                        self->cleanupPending=true;
                        self->phase=QStringLiteral("failed"); self->output(Vpn::ConnectionState::Error,QStringLiteral("Не удалось подтвердить отключение. Нажмите «Повторить отключение»."));
                        return;
                    }
                    self->cleanupOperation=false;
                    self->retryCleanup();
                });
                return;
            }
        }
        // Reconcile the original encrypted record with its stored device authority.
        cleanupOperation=true;
        const quint64 generation=++cleanupGeneration;
        ad::Request request; request.action="reconcile"; request.attemptId=record.identity().attemptId;
        request.cycleToken=record.identity().cycleToken; request.commonPayload=payloadFor(record);
        request.deadlineUtcMs=utcDeadline(now()+2500);
        ++inFlight;
        auto self=shared_from_this();
        ad::MayakAdmissionClient::postAsync(request,transport,[self,record,generation](ad::Response response) {
            --self->inFlight;
            if (generation!=self->cleanupGeneration) return;
            self->cleanupOperation=false;
            if (!response.success || !response.authenticatedResponse ||
                !self->store->removeAfterConfirmedCleanup(record.identity()).ok) {
                self->cleanupPending=true;
                self->phase=QStringLiteral("failed"); self->output(Vpn::ConnectionState::Error,QStringLiteral("Туннель остановлен; очистка доступа на сервере ожидает повтора."));
                return;
            }
            self->cleanupPending=false; self->cancelled=true; self->terminal=true; self->timer.stop();
            self->phase=QStringLiteral("cancelled");
            self->output(Vpn::ConnectionState::Disconnected,{});
        });
    }
    void fetchFresh(ac::CycleId c,ac::AttemptId a,ac::Millis deadline,FetchDone done) override { fetch(c,a,deadline,0,std::move(done)); }
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
            done(c,a,ac::FetchStatus::Success,std::move(s));
        });
        watcher->setFuture(transport(QStringLiteral("%1v1/config"),ad::buildMayakConfigPayload(common),timeout));
    }
    void acquire(ac::CycleId c,ac::AttemptId n,const ac::Candidate& candidate,ac::Millis deadline,AdmissionDone done) override {
        auto self=shared_from_this();
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
        ++inFlight;
        ad::MayakAdmissionClient::postAsync(request,transport,[self,a,c,n,done](ad::Response r) mutable {
            --self->inFlight;
            if(r.authenticatedResponse && r.acquireValid && r.success) {
                a->allocation=r.acquire.allocationId; a->encodedConfig=r.acquire.encodedConfig;
                a->connectBefore=self->now()+QDateTime::currentDateTimeUtc().msecsTo(r.acquire.connectBefore);
                // Pre-send record remains sufficient for exact cleanup if this write fails.
                const bool saved=self->store->attachAllocation(a->identity,a->allocation).ok;
                done(c,n,{ac::AdmissionStatus::Admitted,{a->allocation.toStdString(), saved?a->encodedConfig.toStdString():std::string{}}}); return;
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
    std::shared_ptr<Attempt> get(ac::CycleId c,ac::AttemptId a) {
        auto i=attempts.find({c,a}); return i==attempts.end()?nullptr:i->second;
    }
    void start(ac::CycleId c,ac::AttemptId n,const ac::Allocation&,ac::Millis deadline,StartDone done) override {
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
    void verifyOwnTunnel(ac::CycleId c,ac::AttemptId n,const std::string& nonce,const std::vector<std::string>& ips,
                         ac::Millis deadline,ProofDone done) override {
        auto a=get(c,n); if(!a) { done(c,n,{}); return; }
        a->proofDone=std::move(done); a->nonce=QString::fromStdString(nonce); a->proofDeadline=deadline;
        a->egress.clear(); for(const auto& ip:ips) a->egress.append(QString::fromStdString(ip));
        a->tlsOk=false; a->probing=false; advanceProof({c,n},a);
    }
    void advanceProof(std::pair<ac::CycleId,ac::AttemptId> tag,const std::shared_ptr<Attempt>& a) {
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
        const qint64 handshakeMono=a->startMono+qMax<qint64>(0,handshake-a->startUtc);
        const bool fresh=handshake>=activationSecond && handshake<=QDateTime::currentMSecsSinceEpoch()
            && qAbs((QDateTime::currentMSecsSinceEpoch()-a->startUtc)-(now()-a->startMono))<1500;
        ac::ProofResult result; result.probeSucceeded=fresh;
        result.evidence={a->proof.certificateVerified,a->proof.nonce==a->nonce,a->nonce.toStdString(),
            a->proof.observedEgressIpv4.toStdString(),a->expected.peerPublicKey.toStdString(),handshakeMono,
            a->baselineRx,a->health.rxTotal,a->reset,fresh};
        auto done=std::move(a->proofDone); done(tag.first,tag.second,std::move(result));
    }
    void stopAndConfirm(ac::CycleId c,ac::AttemptId n,ac::Millis deadline,StopDone done) override {
        auto a=get(c,n); if(!a) { done(c,n,{false}); return; }
        if(!a->started) { a->stopped=true; done(c,n,{true}); return; }
        auto self=shared_from_this(); bridge->cancel(a->ticket);
        bridge->stopAndConfirm(a->ticket,deadline,[self,a,c,n,done](B::Result r) {
            // Preserve exact observer evidence, but report this bounded call's
            // own result to the coordinator. A timed-out call must still fail;
            // a later OFF retry can use the retained evidence for reconciliation.
            const bool confirmed=a->acceptNativeDown(r);
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
        a->releasePending=true; a->releaseCallbackHandled=false;
        auto self=shared_from_this(); ad::Request req; req.action="release"; req.attemptId=a->identity.attemptId;
        req.cycleToken=a->identity.cycleToken; req.allocationId=a->allocation; req.commonPayload=common; req.deadlineUtcMs=utcDeadline(now()+2500);
        ++inFlight;
        ad::MayakAdmissionClient::postAsync(req,transport,[self,a,c,n,done](ad::Response r) {
            if (a->releaseCallbackHandled) return;
            a->releaseCallbackHandled=true; a->releasePending=false;
            --self->inFlight;
            qInfo() << "MayakRelease result transport_enum=" << int(r.transportError)
                    << "authenticated=" << r.authenticatedResponse
                    << "response_valid=" << r.responseValid << "success=" << r.success;
            if(r.success && r.authenticatedResponse) {
                const auto removal=self->store->removeAfterConfirmedCleanup(a->identity);
                qInfo() << "MayakRelease ledger_remove attempted=true ok=" << removal.ok
                        << "error_enum=" << int(removal.error);
                if(removal.ok) {
                    self->cleanupPending=false;
                    if(done) done(c,n);
                    if(self->cancelled) {
                        self->terminal=true; self->timer.stop();
                        self->output(Vpn::ConnectionState::Disconnected,{});
                    }
                }
            } else {
                qInfo() << "MayakRelease ledger_remove attempted=false reason=release_not_accepted";
                self->cleanupPending=true; self->terminal=true;
                self->phase=QStringLiteral("failed"); self->output(Vpn::ConnectionState::Error,QStringLiteral("Туннель остановлен; очистка доступа на сервере ожидает повтора."));
            }
        });
    }
    void reportProven(ac::CycleId c,ac::AttemptId n,const std::string&,BasicDone done) override {
        auto a=get(c,n); if(!a) return;
        auto self=shared_from_this(); ad::Request req; req.action="proven"; req.attemptId=a->identity.attemptId;
        req.cycleToken=a->identity.cycleToken; req.allocationId=a->allocation; req.commonPayload=common; req.deadlineUtcMs=utcDeadline(now()+3000);
        ++inFlight; ad::MayakAdmissionClient::postAsync(req,transport,[self,c,n,done](ad::Response) { --self->inFlight; if(done) done(c,n); });
    }
    void cancelOwned(ac::CycleId c,ac::AttemptId n) override {
        auto a=get(c,n); if(!a) return; a->cancelled=true; a->proofDone={}; bridge->cancel(a->ticket);
    }
    void monitor() {
        if(!coordinator || cancelled || coordinator->status().state!=ac::State::Connected || now()-lastMonitor<10000) return;
        const auto s=coordinator->status(); auto a=get(s.cycle,s.attempt); if(!a || !a->health.valid || a->probing && a->proofDone) return;
        lastMonitor=now(); auto self=shared_from_this();
        const auto rx=a->health.rxTotal,tx=a->health.txTotal;
        MayakTunnelProbeRequest req; req.attemptTag=a->ticket.opaqueAttempt; req.localAddress=QHostAddress(a->health.localAddress.section('/',0,0));
        req.interfaceName=a->health.interfaceName; req.expectedEgressIpv4=a->egress; req.nonce=randomId(); req.deadlineMs=5000;
        bridge->probe(a->ticket,req,now()+5000,[self,a,s,rx,tx](B::Ticket,bool ok,MayakTunnelProbeProof,QString) {
            if(!self->coordinator || self->cancelled || a->cancelled) return;
            // Idle RX or provider/API failure alone never tears down a tunnel.
            const bool degraded=a->reset || self->now()-a->healthAt>12000 ||
                (a->health.txTotal>tx && a->health.rxTotal==rx && QDateTime::currentMSecsSinceEpoch()-qint64(a->health.latestHandshakeEpochMs)>180000);
            if(!ok && degraded) self->reconnectWanted=true;
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
bool MayakAutoConnectRuntime::manages(const QString& id) const { return m_app && m_app->isMayakManagedServer(id); }
bool MayakAutoConnectRuntime::busy() const { return m_session && (m_session->cleanupPending || !m_session->terminal || m_session->inFlight>0); }
void MayakAutoConnectRuntime::publish(Vpn::ConnectionState state,const QString& text,const QString& phase) {
    m_message=text;
    m_connectionPhase=phase;
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
void MayakAutoConnectRuntime::retryCleanup() { if(m_session) m_session->retryCleanup(); }
void MayakAutoConnectRuntime::shutdown() {
    cancel();
    QElapsedTimer elapsed; elapsed.start();
    while(busy() && elapsed.elapsed()<5000) {
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents,20);
        QThread::msleep(5);
    }
    // Unconfirmed cleanup remains encrypted for reconciliation at next startup.
}
