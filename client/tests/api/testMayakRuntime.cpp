#include <algorithm>
#include <QApplication>
#include <QJsonArray>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QPromise>
#include <QSet>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>
#include <QTimer>
#include <QUuid>
#include "core/utils/mayakTunnelProbe.h"
#include "core/controllers/mayakAutoConnectRuntime.h"
#include "core/controllers/mayakAutoConnectCoordinator.h"
#include "core/controllers/mayakAttemptStore.h"
#include "core/controllers/connectionController.h"
#include "core/controllers/api/subscriptionController.h"
#include "core/controllers/api/mayakAdmissionClient.h"
#include "core/models/api/apiV2ServerConfig.h"
#include "core/utils/constants/apiKeys.h"
#include "core/utils/constants/configKeys.h"
#include "ui/controllers/connectionUiController.h"

using namespace amnezia;
using B=MayakBackendBridge;
namespace mayak::diagnostics {
QStringList openSslErrorCodeTokens(const QString &errorString);
}
namespace {
QStringList capturedProbeOutput;
void collectAllProbeOutput(QtMsgType, const QMessageLogContext &, const QString &message) {
    capturedProbeOutput.append(message);
}
struct ProbeMessageCapture {
    QtMessageHandler previous = qInstallMessageHandler(collectAllProbeOutput);
    ProbeMessageCapture() { capturedProbeOutput.clear(); }
    ~ProbeMessageCapture() { qInstallMessageHandler(previous); }
    ProbeMessageCapture(const ProbeMessageCapture &) = delete;
    ProbeMessageCapture &operator=(const ProbeMessageCapture &) = delete;
};
QString guid() { return QUuid::createUuid().toString(QUuid::WithoutBraces); }
struct World : QObject {
    SecureQSettings settings{QStringLiteral("MayakRuntime-")+guid(),QStringLiteral("test"),nullptr,true};
    SecureServersRepository servers{&settings};
    SecureAppSettingsRepository app{&settings};
    SubscriptionController subscription{&servers,&app};
    ConnectionController connection{&servers,&app,nullptr};
    QString id, first=guid(), second=guid(), allocation=guid();
    QStringList events;
    int acquires=0, starts=0, releases=0, reconciles=0, stops=0;
    bool fullFirst=false, deadFirst=false, lostAcquire=false, badProof=false, holdStart=false;
    bool holdPermission=false;
    int exitLocationMode=0; // 0 valid, 1 absent, 2 bad schema, 3 candidate mismatch, 4 unknown city
    bool backendRunning=false, missingStop=false, failRelease=false, failStopOnce=false, holdNextStop=false;
    bool holdReleaseForever=false;
    bool holdReconcileForever=false, holdProvenForever=false, synchronousCleanup=false;
    bool holdInspection=false, activeInspection=false;
    B::Inspected heldInspection; QString inspectionNonce;
    int reconcileDelay=0;
    int releaseDelay=0;
    int acquireDelay=0;
    QString publicKey, selectedHost = "81.29.149.103";
    B::Ticket current;
    QList<B::Ticket> stopTickets;
    QList<QJsonObject> requestPayloads;
    QList<std::shared_ptr<QPromise<GatewayPostResult>>> heldTransportPromises, allTransportPromises;
    AwgTunnelHealth health;
    std::function<void(B::Ticket,AwgTunnelHealth)> observeHealth;
    B::Done startDone;
    QString permissionRequestId;
    B::PermissionDone heldPermissionDone;
    B::Done heldStopDone;
    QString heldStopNonce;
    std::function<void(B::Result)> observeDown;
    // Connected-state recovery fixture: a stuck transport answers no probe and no RX.
    bool tunnelDown=false, recoverHeals=true, recoverOk=true;
    int failNextProbes=0, recovers=0;
    std::function<void(B::Ticket,bool)> observeNetwork;
    std::function<void(B::Ticket,bool,bool)> observeResume;
    std::function<void(B::Ticket)> observeUserStop;
    // Cold-start adoption fixture.
    QString inspectionIdentity; // non-empty: the active inspection reports this control identity
    bool adoptOk=true; int adopts=0; QString adoptedTicket;
    qint64 adoptHandshakeAgeMs=60000; // the adopted live session's last handshake (no replacement)
    bool adoptDeadline=false;         // the service never confirms the transfer in time
    std::function<void(bool)> observeVisibility;
    std::function<void(B::Ticket)> observeFailover;
    bool silentFirst=false, singleCandidate=false;
    // Xray paths (5.1.0.21): acquire offers them when asked; the fixture backend runs either path.
    bool offerXray=false, awgSilent=false, xrayDead=false;
    int awgStarts=0, xrayStarts=0;
    QStringList startedProtocols;
    QJsonObject lastXrayConfig;
    // Race engine fixture: started engines get loopback SOCKS entries nobody serves.
    bool withRace=false, raceEngineOk=true;
    bool appExclusionFails=false; // the Windows service reports that app exclusions cannot be applied
    int raceStarts=0, raceStops=0; bool raceRunning=false;
    QJsonObject raceConfig;
    int localFailStarts=0; // Windows: the next N starts never bring the tunnel interface up (no health)
    // Windows: the service is still busy failing the adapter, so the first stop of such an
    // attempt is not confirmed in time (a later stop is).
    bool localFailStopUnconfirmed=false;
    QSet<QString> localFailTickets, localFailStopsSeen;
    QString lastAcquireCandidate() const {
        QString id;
        for (const auto& p:requestPayloads) if (p.value("action").toString()=="acquire") id=p.value("candidate_id").toString();
        return id;
    }
    std::unique_ptr<MayakAutoConnectRuntime> runtime;
    Vpn::ConnectionState state=Vpn::ConnectionState::Disconnected;
    explicit World(bool withRecover=false, bool withAdopt=true) {
        MayakAutoConnectRuntime::resetFailoverMemoryForTests(); // process-wide failover memory
        ApiV2ServerConfig cfg;
        cfg.configVersion=serverConfigUtils::ConfigSource::AmneziaGateway;
        cfg.name="Mayak test"; cfg.defaultContainer=DockerContainer::Awg;
        cfg.apiConfig.serviceType="amnezia-premium"; cfg.apiConfig.serviceProtocol="awg";
        cfg.apiConfig.userCountryCode="ru"; cfg.authData.apiKey="synthetic-device-credential";
        id=servers.addServer(guid(),cfg.toJson(),serverConfigUtils::configTypeFromJson(cfg.toJson()));
        app.setMayakSessionToken("synthetic-email-session"); app.markMayakManagedServer(id);
        B::Port port; port.owner=this;
        port.observe=[this](QObject*,auto healthCallback,auto downCallback){observeHealth=healthCallback;observeDown=downCallback;};
        port.inspect=[this](QString nonce,qint64,B::Inspected done) {
            events<<"inspect";
            if (holdInspection) { inspectionNonce=nonce; heldInspection=done; return; }
            if (activeInspection) {
                current={inspectionIdentity.isEmpty() ? guid() : QStringLiteral("recovery:")+inspectionIdentity,std::make_shared<B::StartGate>()};
                current.gate->commit(); backendRunning=true; done({B::OwnState::Active,nonce,inspectionIdentity,current}); return;
            }
            done({backendRunning?B::OwnState::Unknown:B::OwnState::Off,nonce,{},{}});
        };
        port.preparePermissions=[this](QString requestId,B::PermissionDone done) {
            permissionRequestId=requestId;
            if (holdPermission) heldPermissionDone=std::move(done);
            else done(requestId,B::PermissionResult::Ready);
        };
        port.cancelPermissionPreparation=[this](QString requestId) {
            if (requestId==permissionRequestId) heldPermissionDone={};
        };
        port.start=[this](B::Ticket ticket,QString,QJsonObject config,qint64,B::Done done) {
            ++starts; events<<"start"; current=ticket;
            const QString protocol=config.value("protocol").toString();
            startedProtocols<<protocol;
            if (protocol=="xray") {
                ++xrayStarts; lastXrayConfig=config; ticket.gate->commit(); backendRunning=true;
                AwgHealthContext expected{"xray:"+ticket.opaqueAttempt,"78726179",selectedHost+":443"};
                done({ticket,B::Outcome::Started,expected});
                health={expected.id,1,expected.peerPublicKey,expected.endpoint,"10.33.0.2/32","MayakXrayFixture",0,10,10,!xrayDead};
                QTimer::singleShot(10,this,[this,ticket] {if(observeHealth)observeHealth(ticket,health);});
                return;
            }
            ++awgStarts;
            if (appExclusionFails) mayak::split::markAppExclusionFailure();
            if(holdStart) { startDone=done; return; }
            ticket.gate->commit(); backendRunning=true;
            AwgHealthContext expected{guid(),QString(64,'a'),selectedHost+":49963"};
            done({ticket,deadFirst && starts==1?B::Outcome::Failed:B::Outcome::Started,expected});
            // localFailStarts: started, but the tunnel interface never comes up (no health at all).
            if (localFailStarts>0) { --localFailStarts; events<<"local_fail"; localFailTickets.insert(ticket.opaqueAttempt); return; }
            // silentFirst: the first exit never answers a handshake (no valid health ever).
            const bool silent=(silentFirst && selectedHost=="81.29.149.103") || awgSilent;
            health={expected.id,1,expected.peerPublicKey,expected.endpoint,"10.8.0.2","MayakFixture",quint64(QDateTime::currentMSecsSinceEpoch()),10,10,!silent};
            QTimer::singleShot(10,this,[this,ticket] {if(observeHealth)observeHealth(ticket,health);});
        };
        port.cancel=[](B::Ticket t){t.gate->cancel();};
        port.stop=[this](B::Ticket t,QString nonce,qint64,B::Done done) {
            ++stops; events<<"down"; stopTickets.append(t);
            if(localFailStopUnconfirmed && localFailTickets.contains(t.opaqueAttempt) && !localFailStopsSeen.contains(t.opaqueAttempt)) {
                localFailStopsSeen.insert(t.opaqueAttempt); events<<"down_unconfirmed"; done({t,B::Outcome::Unknown,{},nonce}); return;
            }
            if(holdNextStop) {holdNextStop=false;heldStopNonce=nonce;heldStopDone=done;return;}
            if(failStopOnce) {failStopOnce=false;done({t,B::Outcome::Unknown,{},nonce});return;}
            if(missingStop) {done({t,B::Outcome::Unknown,{},nonce});return;}
            backendRunning=false; done({t,B::Outcome::ConfirmedDown,{},nonce});
        };
        port.probe=[this](B::Ticket ticket,MayakTunnelProbeRequest request,qint64,B::Probed done) {
            events<<"probe";
            bool ok=!badProof && !tunnelDown;
            if (ok && failNextProbes>0) { --failNextProbes; ok=false; }
            done(ticket,ok,{ticket.opaqueAttempt,request.nonce,"81.29.149.103",request.interfaceName,request.localAddress.toString(),true},{});
            if (!tunnelDown) health.rxTotal+=500; // a live tunnel still carries RX on a random probe miss
            health.txTotal+=500;
            QTimer::singleShot(10,this,[this,ticket] {if(observeHealth)observeHealth(ticket,health);});
        };
        port.raceStart=[this](QString,QJsonObject config,qint64,std::function<void(bool)> done) {
            if (!withRace) { done(false); return; }
            ++raceStarts; events<<"race_start"; raceConfig=config;
            if (backendRunning) { done(false); return; } // never with a tunnel up
            raceRunning=raceEngineOk; done(raceEngineOk);
        };
        port.raceStop=[this](QString,qint64,std::function<void(bool)> done) {
            ++raceStops; events<<"race_stop"; raceRunning=false; done(true);
        };
        port.observeResume=[this](QObject*,std::function<void(B::Ticket,bool,bool)> resumed){observeResume=resumed;};
        port.observeUserStop=[this](QObject*,std::function<void(B::Ticket)> stopped){observeUserStop=stopped;};
        port.observeVisibility=[this](QObject*,std::function<void(bool)> changed){observeVisibility=changed;};
        port.observeFailover=[this](QObject*,std::function<void(B::Ticket)> requested){observeFailover=requested;};
        if (withAdopt) port.adopt=[this](B::Ticket recovery,B::Ticket fresh,QString identity,QJsonObject,QString nonce,qint64,B::Done done) {
            ++adopts; events<<"adopt"; adoptedTicket=fresh.opaqueAttempt;
            B::Result r{fresh,adoptOk && recovery.same(current) ? B::Outcome::Started : B::Outcome::Failed}; r.requestId=nonce;
            if (adoptDeadline) r.outcome=B::Outcome::Deadline;
            if (r.outcome==B::Outcome::Started) {
                // Handover without replacement: the same running backend and session continue
                // under the attempt ticket; its last handshake predates the adoption.
                AwgHealthContext expected{identity,QString(64,'a'),selectedHost+":49963"};
                r.expected=expected; current=fresh;
                health={expected.id,7,expected.peerPublicKey,expected.endpoint,"10.8.0.2","MayakFixture",
                        quint64(QDateTime::currentMSecsSinceEpoch()-adoptHandshakeAgeMs),10,10,true};
                QTimer::singleShot(10,this,[this,fresh] { if (observeHealth) observeHealth(fresh,health); });
            }
            done(r);
        };
        if (withRecover) {
            port.observeNetwork=[this](QObject*,std::function<void(B::Ticket,bool)> changed){observeNetwork=changed;};
            port.recover=[this](B::Ticket ticket,QString nonce,qint64,B::Done done) {
                ++recovers; events<<"recover";
                B::Result result{ticket,recoverOk?B::Outcome::Started:B::Outcome::Failed}; result.requestId=nonce;
                if (recoverOk) {
                    if (recoverHeals) tunnelDown=false;
                    // New backend: new generation, counters restart, same proof context.
                    health.generation+=1; health.rxTotal=0; health.txTotal=0;
                    QTimer::singleShot(10,this,[this,ticket] {if(observeHealth)observeHealth(ticket,health);});
                }
                done(result);
            };
        }
        runtime=std::make_unique<MayakAutoConnectRuntime>(&settings,&servers,&app,&subscription,&connection,port,nullptr,
            [this](const QString& path,const QJsonObject& payload,int){return transport(path,payload);});
        connection.setMayakRuntime(runtime.get());
        connect(runtime.get(),&MayakAutoConnectRuntime::stateChanged,this,[this](auto value,QString){state=value;});
    }
    ~World() {
        if (runtime) disconnect(runtime.get(),nullptr,this,nullptr); // test-local captures may already be gone
        // A cancelled fixture timer must not destroy an unfinished promise and
        // dispatch a result-less QFuture into the following test's event loop.
        // Drain synthetic transport work while this World's repositories live.
        for (int round=0;round<2;++round) {
            for (const auto& p:allTransportPromises) if (!p->future().isFinished()) {
                p->addResult({ErrorCode::NoError,QByteArrayLiteral("{}"),false}); p->finish();
            }
            QCoreApplication::processEvents();
            if (!round) runtime.reset();
        }
        settings.clearSettings();
    }
    QString config() {
        const QString serverPub=QString::fromLatin1(QByteArray(32,'p').toBase64());
        const QString psk=QString::fromLatin1(QByteArray(32,'s').toBase64());
        const QString native=QStringLiteral("[Interface]\nAddress = 10.8.0.2/32\nPrivateKey = $WIREGUARD_CLIENT_PRIVATE_KEY\n\n[Peer]\nPublicKey = %1\nPresharedKey = %2\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %3:49963\nPersistentKeepalive = 25\n").arg(serverPub,psk,selectedHost);
        // Keep the gateway's raw allocation shape: admission validates this JSON
        // before the model import substitutes the stable client private key.
        QJsonObject last{{configKey::hostName,selectedHost},{configKey::port,49963},
                         {configKey::clientPrivKey,"$WIREGUARD_CLIENT_PRIVATE_KEY"},
                         {configKey::clientPubKey,publicKey},{configKey::clientId,publicKey},
                         {configKey::serverPubKey,serverPub},{configKey::pskKey,psk},
                         {configKey::clientIp,"10.8.0.2"},{configKey::config,native},
                         {configKey::allowedIps,QJsonArray{"0.0.0.0/0","::/0"}},
                         {configKey::persistentKeepAlive,"25"},{configKey::mtu,"1280"}};
        QJsonObject awg{{configKey::port,"49963"},{"transport_proto","udp"},
                        {configKey::protocolVersion,"2"},{configKey::subnetAddress,"10.8.0.0"},
                        {configKey::subnetCidr,"24"},
                        {configKey::lastConfig,QString::fromUtf8(QJsonDocument(last).toJson(QJsonDocument::Compact))}};
        QJsonObject container{{configKey::container,"amnezia-awg2"},{QString(configKey::awg),awg}};
        QJsonObject api{{apiDefs::key::serviceType,"amnezia-premium"},{apiDefs::key::serviceProtocol,"awg"},
                        {apiDefs::key::userCountryCode,"ru"}};
        QJsonObject cfg{{configKey::configVersion,serverConfigUtils::ConfigSource::AmneziaGateway},
                        {configKey::name,"Mayak test"},{apiDefs::key::apiConfig,api},
                        {apiDefs::key::authData,QJsonObject{{apiDefs::key::apiKey,"synthetic-device-credential"}}},
                        {configKey::hostName,selectedHost},{configKey::defaultContainer,"amnezia-awg2"},
                        {configKey::containers,QJsonArray{container}},
                        {configKey::description,"Mayak runtime fixture"},
                        {configKey::dns1,"1.1.1.1"},{configKey::dns2,"1.0.0.1"}};
        return "vpn://"+QString::fromUtf8(qCompress(QJsonDocument(cfg).toJson(QJsonDocument::Compact)).toBase64(QByteArray::Base64UrlEncoding|QByteArray::OmitTrailingEquals));
    }
    QJsonObject xrayPaths() {
        QJsonArray paths;
        for (const QString fp : {QStringLiteral("firefox"),QStringLiteral("safari"),QStringLiteral("chrome")}) {
            const QJsonObject stream{{"network","xhttp"},{"security","reality"},
                {"realitySettings",QJsonObject{{"fingerprint",fp},{"serverName","example.org"},{"publicKey","pk"},{"shortId","ab"}}},
                {"xhttpSettings",QJsonObject{{"host","example.org"},{"path","/p"},{"mode","auto"}}}};
            const QJsonObject client{{"inbounds",QJsonArray{QJsonObject{{"listen","127.0.0.1"},{"port",10808},{"protocol","socks"},{"settings",QJsonObject{{"udp",true}}}}}},
                {"outbounds",QJsonArray{QJsonObject{{"protocol","vless"},
                    {"settings",QJsonObject{{"vnext",QJsonArray{QJsonObject{{"address",selectedHost},{"port",443},
                        {"users",QJsonArray{QJsonObject{{"id",guid()},{"encryption","none"}}}}}}}}},
                    {"streamSettings",stream}}}}};
            const QJsonObject xray{{"port","443"},{"transport_proto","tcp"},{"xray_fingerprint",fp},{"xray_security","reality"},
                {"xray_sni","example.org"},{"xray_transport","xhttp"},
                {"last_config",QString::fromUtf8(QJsonDocument(client).toJson(QJsonDocument::Compact))}};
            const QJsonObject root{{"config_version",2},{"name","Mayak test"},{"hostName",selectedHost},{"defaultContainer","amnezia-xray"},
                {"containers",QJsonArray{QJsonObject{{"container","amnezia-xray"},{"xray",xray}}}},{"dns1","1.1.1.1"},{"dns2","1.0.0.1"}};
            paths.append(QJsonObject{{"id","xray-"+fp},{"fingerprint",fp},{"config","vpn://"+QString::fromUtf8(
                qCompress(QJsonDocument(root).toJson(QJsonDocument::Compact)).toBase64(QByteArray::Base64UrlEncoding|QByteArray::OmitTrailingEquals))}});
        }
        return {{"schema",1},{"paths",paths}};
    }
    int failConfigCount=0; // gateway unreachable (DNS/timeout) for the next N config fetches
    QFuture<GatewayPostResult> transport(QString path,QJsonObject payload) {
        requestPayloads.append(payload);
        if(path.endsWith("config") && failConfigCount>0) {
            --failConfigCount; events<<"config_fail";
            auto promise=std::make_shared<QPromise<GatewayPostResult>>(); promise->start(); auto future=promise->future();
            allTransportPromises.append(promise);
            QTimer::singleShot(5,this,[promise]{ if (promise->future().isFinished()) return;
                promise->addResult({ErrorCode::ApiConfigDownloadError,{},false}); promise->finish(); });
            return future;
        }
        QJsonObject response; int delay=0;bool trusted=true;
        if(path.endsWith("config")) {
            publicKey=payload.value("public_key").toString();events<<"config";
            QJsonArray candidates;
            for(const auto& candidate:{first,second}) {
                if (singleCandidate && candidate==second) continue;
                candidates.append(QJsonObject{{"id",candidate},{"host",candidate==first?"81.29.149.103":"81.29.149.104"},
                {"port",49963},{"preferred",candidate==first},{"expected_egress_ips",QJsonArray{"81.29.149.103"}}});
            }
            response={{"mayak_connection",QJsonObject{{"schema",1},{"revision",14},{"expires_at",QDateTime::currentDateTimeUtc().addSecs(60).toString(Qt::ISODateWithMs)},{"candidates",candidates}}}};
        } else {
            const auto action=payload.value("action").toString();events<<action;
            if(action=="acquire") {
                publicKey=payload.value("public_key").toString();
                selectedHost=payload.value("candidate_id").toString()==first?"81.29.149.103":"81.29.149.104";
                ++acquires; delay=acquireDelay;
                if(fullFirst && acquires==1) response={{"http_status",409},{"code","FULL"},{"message","full"}};
                else { response={{"allocation_id",allocation},{"connect_before",QDateTime::currentDateTimeUtc().addSecs(30).toString(Qt::ISODateWithMs)},
                    {"config_revision",14},{"config",config()}}; trusted=!lostAcquire; }
                if (!response.contains("http_status") && offerXray && payload.value("mayak_paths").toInt()==1)
                    response.insert("xray_paths",xrayPaths());
                if (!response.contains("http_status") && payload.value("mayak_exit_location").toInt()==1
                    && exitLocationMode!=1) {
                    const QString candidate=payload.value("candidate_id").toString();
                    response.insert("exit_location",QJsonObject{{"schema",exitLocationMode==2?2:1},
                        {"candidate_id",exitLocationMode==3?guid():candidate},
                        {"city_id",exitLocationMode==4?QStringLiteral("unknown"):candidate==first?QStringLiteral("oslo"):QStringLiteral("helsinki")}});
                }
            } else if(action=="release") {++releases;delay=releaseDelay;response={{"released",!backendRunning && !failRelease}};}
            else if(action=="proven") response={{"proven",true}};
            else if(action=="reconcile") {++reconciles;delay=reconcileDelay;response={{"reconciled",!backendRunning}};}
        }
        auto promise=std::make_shared<QPromise<GatewayPostResult>>();promise->start();auto future=promise->future();
        allTransportPromises.append(promise);
        if ((payload.value("action").toString()=="release" && holdReleaseForever)
            || (payload.value("action").toString()=="reconcile" && holdReconcileForever)
            || (payload.value("action").toString()=="proven" && holdProvenForever)) {
            heldTransportPromises.append(promise);
            return future;
        }
        if (synchronousCleanup && payload.value("action").toString()!="acquire") {
            promise->addResult({ErrorCode::NoError,QJsonDocument(response).toJson(QJsonDocument::Compact),trusted}); promise->finish(); return future;
        }
        QTimer::singleShot(delay,this,[promise,response,trusted]{if (promise->future().isFinished()) return; promise->addResult({ErrorCode::NoError,QJsonDocument(response).toJson(QJsonDocument::Compact),trusted});promise->finish();});
        return future;
    }
    void seed(int count=1) {
        mayak::attempts::MayakAttemptStore store(&settings);
        for (int i=0;i<count;++i) {
            mayak::attempts::AttemptInput input{{id,guid(),guid(),guid(),first},
                {"https://mayaklight.ru/gw/",guid(),QString::fromLatin1(QByteArray(32,'k').toBase64()),
                 "synthetic-device-credential","amnezia-premium","awg","ru",{}},false,false,{}};
            if (!store.appendBeforeAcquire(input).ok) qFatal("Could not seed isolated test ledger");
        }
    }
    void drainHeld(const QByteArray& body) {
        for (const auto& p:heldTransportPromises) if (!p->future().isFinished()) {
            p->addResult({ErrorCode::NoError,body,true}); p->finish();
        }
        QCoreApplication::processEvents();
    }
    int records() {auto result=mayak::attempts::MayakAttemptStore(&settings).load();return result.ok?result.records.size():-1;}
    // A persisted attempt that started a backend and holds `allocation` (what a cold start finds).
    QString seedStarted(const QString& candidateId=QString()) {
        mayak::attempts::MayakAttemptStore store(&settings);
        mayak::attempts::AttemptIdentity identity{id,guid(),guid(),guid(),candidateId.isEmpty()?first:candidateId};
        mayak::attempts::AttemptInput input{identity,{"https://mayaklight.ru/gw/",guid(),QString::fromLatin1(QByteArray(32,'k').toBase64()),
            "synthetic-device-credential","amnezia-premium","awg","ru",{}},false,false,{}};
        if (!store.appendBeforeAcquire(input).ok || !store.attachAllocation(identity,allocation).ok || !store.markMayHaveStarted(identity).ok)
            qFatal("Could not seed started attempt");
        return identity.attemptId;
    }
};
}
namespace {
// Leave nothing in flight for the next test (sessions may outlive a World's repositories).
void settle(World& w) {
    w.runtime->cancel();
    QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
    QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
    QTest::qWait(100);
}
// Fast, test-local connected-monitor timing; restored for every other test.
struct FastRecoveryTiming {
    MayakAutoConnectRuntime::RecoveryTiming previous = MayakAutoConnectRuntime::recoveryTiming();
    FastRecoveryTiming() {
        MayakAutoConnectRuntime::RecoveryTiming t;
        t.monitorMs=250; t.retryProbeMs=120; t.probeDeadlineMs=300; t.networkSettleMs=60; t.noNetworkUiMs=60;
        t.stuckRxMs=200; t.stuckRxAfterNetworkMs=100; t.networkRecentMs=1500; t.recoverDeadlineMs=500;
        t.recoverBackoffMs={0,250,500};
        t.connectRetryMs={100,150,200};
        // The fixture's "no valid health" models a silent exit (Android semantics) unless a
        // test opts into the Windows meaning (local adapter never came up).
        t.noHealthMeansLocalFailure=false;
        t.localStartRetryMs={100,150};
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
    }
    ~FastRecoveryTiming() { MayakAutoConnectRuntime::setRecoveryTimingForTests(previous); }
    FastRecoveryTiming(const FastRecoveryTiming&) = delete;
    FastRecoveryTiming& operator=(const FastRecoveryTiming&) = delete;
};
}
// Restores the process-wide coordinator budgets even when a check fails early.
struct CoordinatorTimingGuard {
    mayak::autoconnect::Timing saved = mayak::autoconnect::Coordinator::timing();
    ~CoordinatorTimingGuard() { mayak::autoconnect::Coordinator::timing() = saved; }
};
// Restores the default (service) app-exclusion preparation.
struct SplitPrepareGuard { ~SplitPrepareGuard() { MayakAutoConnectRuntime::setSplitPrepareForTests({}); } };
class RuntimeTest : public QObject {
    Q_OBJECT
private slots:
    void acquireExitLocationMetadataIsOptionalAndBounded() {
        const auto makeBody=[](QJsonValue location) {
            QJsonObject body{{"allocation_id",guid()},
                {"connect_before",QDateTime::currentDateTimeUtc().addSecs(30).toString(Qt::ISODateWithMs)},
                {"config_revision",14},{"config","fixture"}};
            if (!location.isUndefined()) body.insert("exit_location",location);
            return QJsonDocument(body).toJson(QJsonDocument::Compact);
        };
        mayak::admission::AcquireResponse parsed;
        QVERIFY(mayak::admission::parseAcquireResponse(makeBody(QJsonObject{{"schema",1},
            {"candidate_id",guid()},{"city_id","oslo"}}),&parsed));
        QCOMPARE(parsed.exitLocationCityId,QStringLiteral("oslo"));
        QVERIFY(mayak::admission::parseAcquireResponse(makeBody(QJsonObject{{"schema",2},
            {"candidate_id",guid()},{"city_id","oslo"}}),&parsed));
        QVERIFY(parsed.exitLocationCityId.isEmpty());
        QVERIFY(mayak::admission::parseAcquireResponse(makeBody(QJsonObject{{"schema",1},
            {"candidate_id",guid()},{"city_id","other"}}),&parsed));
        QVERIFY(parsed.exitLocationCityId.isEmpty());
        QVERIFY(mayak::admission::parseAcquireResponse(makeBody(QJsonValue{}),&parsed));
        QVERIFY(parsed.exitLocationCityId.isEmpty());
    }

    void selectedExitLocationFollowsTheConnectedFailoverAttemptAndClears() {
        World w;
        w.deadFirst=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.acquires,2);
        QList<QJsonObject> acquireRequests;
        for (const auto& payload : w.requestPayloads) {
            if (payload.value("action").toString()==QStringLiteral("acquire")) acquireRequests.append(payload);
            else QVERIFY(!payload.contains(QStringLiteral("mayak_exit_location")));
        }
        QCOMPARE(acquireRequests.size(),2);
        QCOMPARE(acquireRequests.at(0).value("candidate_id").toString(),w.first);
        QCOMPARE(acquireRequests.at(1).value("candidate_id").toString(),w.second);
        for (const auto& payload : acquireRequests) {
            QVERIFY(payload.value("mayak_exit_location").isDouble());
            QCOMPARE(payload.value("mayak_exit_location").toInt(),1);
        }
        // The config bootstrap is also recorded by World::transport and must
        // not opt in; it has no admission action.
        QVERIFY(!w.requestPayloads.first().contains(QStringLiteral("action")));
        QVERIFY(!w.requestPayloads.first().contains(QStringLiteral("mayak_exit_location")));
        // Construct the read-only facade after the fixture is Connected so a
        // plain QApplication never dispatches its production Connected slot
        // that expects AmneziaApplication's network manager.
        ConnectionUiController ui(&w.connection,nullptr);
        QCOMPARE(ui.exitLocation().value("candidateId").toString(),w.second);
        QCOMPARE(ui.exitLocation().value("cityId").toString(),QStringLiteral("helsinki"));
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QVERIFY(ui.exitLocation().isEmpty());
    }

    void absentOrMismatchedExitLocationNeverBlocksConnection() {
        for (const int mode : {1,3,4}) {
            World w;
            w.exitLocationMode=mode;
            w.runtime->begin(w.id);
            QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
            QCOMPARE(w.runtime->exitLocation().value("cityId").toString(),QString());
            w.runtime->cancel();
            QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        }
    }

    void phaseSnapshotReportsEveryCoordinatorState() {
        World w;
        QStringList phases;
        QList<Vpn::ConnectionState> coarseStates;
        connect(w.runtime.get(), &MayakAutoConnectRuntime::stateChanged, &w,
                [&w, &phases, &coarseStates](Vpn::ConnectionState state, const QString&) {
            phases.append(w.runtime->connectionPhase());
            coarseStates.append(state);
        });

        w.runtime->begin(w.id);
        QCOMPARE(w.runtime->connectionPhase(), QStringLiteral("preparing"));
        QTRY_COMPARE_WITH_TIMEOUT(w.state, Vpn::ConnectionState::Connected, 5000);
        for (const auto& phase : {QStringLiteral("fetching"), QStringLiteral("admitting"),
                                  QStringLiteral("starting"), QStringLiteral("verifying"),
                                  QStringLiteral("connected")})
            QVERIFY2(phases.contains(phase), qPrintable(QStringLiteral("missing phase: ") + phase));

        const int fetching = phases.indexOf(QStringLiteral("fetching"));
        const int admitting = phases.indexOf(QStringLiteral("admitting"));
        const int starting = phases.indexOf(QStringLiteral("starting"));
        const int verifying = phases.indexOf(QStringLiteral("verifying"));
        QVERIFY(fetching >= 0 && admitting > fetching);
        QVERIFY(starting > admitting && verifying > starting);
        QCOMPARE(coarseStates.at(fetching), Vpn::ConnectionState::Preparing);
        QCOMPARE(coarseStates.at(admitting), Vpn::ConnectionState::Preparing);
        QCOMPARE(coarseStates.at(starting), Vpn::ConnectionState::Connecting);
        QCOMPARE(coarseStates.at(verifying), Vpn::ConnectionState::Connecting);

        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.runtime->connectionPhase(), QStringLiteral("cancelled"), 2000);
    }

    void heldPreflightAndIdentityDriftPreserveDisconnectedBehavior() {
        World w;
        w.holdPermission=true;
        QSignalSpy states(w.runtime.get(), &MayakAutoConnectRuntime::stateChanged);
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(bool(w.heldPermissionDone), 2000);
        QCOMPARE(w.runtime->connectionPhase(), QStringLiteral("preparing"));
        QVERIFY(!w.events.contains(QStringLiteral("config")));
        QTest::qWait(50);
        QCOMPARE(w.runtime->connectionPhase(), QStringLiteral("preparing"));
        QVERIFY(!w.events.contains(QStringLiteral("config")));

        // Remove the active identity without emitting mayakSessionChanging so
        // Ready reaches the existing identity-drift branch uncancelled.
        w.settings.clearSettings();
        auto ready=std::move(w.heldPermissionDone);
        ready(w.permissionRequestId,B::PermissionResult::Ready);
        QTRY_COMPARE_WITH_TIMEOUT(w.runtime->connectionPhase(), QStringLiteral("idle"), 2000);
        QCOMPARE(w.state, Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->message(), QString());
        QCOMPARE(w.runtime->connectionPhase(), QStringLiteral("idle"));
        QVERIFY(!w.events.contains(QStringLiteral("config")));
        const auto last=states.last();
        QCOMPARE(last.at(0).value<Vpn::ConnectionState>(), Vpn::ConnectionState::Disconnected);
        QCOMPARE(last.at(1).toString(), QString());
    }

    void newSessionResetsFailurePhaseBeforeHeldPermission() {
        World w;
        w.badProof=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,8000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("failed"));
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),2000);

        w.badProof=false;
        w.holdPermission=true;
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(bool(w.heldPermissionDone),2000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("preparing"));
        w.runtime->cancel();
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
    }

    void uiPhasePropertyNotifiesAcrossSameCoarseStates() {
        World w;
        w.badProof = true; // Exercise Verifying and terminal failure without Connected UI side effects.
        ConnectionUiController ui(&w.connection, nullptr);
        QStringList phases;
        QList<bool> inProgress;
        connect(&ui, &ConnectionUiController::connectionStateChanged, &w, [&] {
            phases.append(ui.connectionPhase());
            inProgress.append(ui.isConnectionInProgress());
        });

        QCOMPARE(w.connection.openConnection(w.id), ErrorCode::NoError);
        QCOMPARE(ui.connectionPhase(), QStringLiteral("preparing"));
        QTRY_COMPARE_WITH_TIMEOUT(w.state, Vpn::ConnectionState::Error, 8000);
        for (const auto& phase : {QStringLiteral("fetching"), QStringLiteral("admitting"),
                                  QStringLiteral("starting"), QStringLiteral("verifying")})
            QVERIFY2(phases.contains(phase), qPrintable(QStringLiteral("UI missed phase: ") + phase));

        const int fetching = phases.indexOf(QStringLiteral("fetching"));
        const int admitting = phases.indexOf(QStringLiteral("admitting"));
        const int starting = phases.indexOf(QStringLiteral("starting"));
        const int verifying = phases.indexOf(QStringLiteral("verifying"));
        QCOMPARE(inProgress.at(fetching), true);
        QCOMPARE(inProgress.at(admitting), true);
        QCOMPARE(inProgress.at(starting), true);
        QCOMPARE(inProgress.at(verifying), true);
        QVERIFY(admitting > fetching && starting > admitting && verifying > starting);
        QVERIFY(phases.contains(QStringLiteral("failed")));
    }

    void acquiredConfigMatchesFactoryContract() {
        World w;
        SubscriptionController::ProtocolData keys;
        QCOMPARE(w.subscription.getOrCreateMayakAwgProtocolData(w.id,&keys),ErrorCode::NoError);
        QVERIFY(!keys.wireGuardClientPrivKey.isEmpty());
        QVERIFY(!keys.wireGuardClientPubKey.isEmpty());
        w.publicKey=keys.wireGuardClientPubKey;
        const QString encoded=w.config();
        const QByteArray decoded=qUncompress(QByteArray::fromBase64(encoded.mid(6).toUtf8(),
                QByteArray::Base64UrlEncoding|QByteArray::OmitTrailingEquals));
        QJsonParseError error;
        const auto root=QJsonDocument::fromJson(decoded,&error).object();
        QCOMPARE(error.error,QJsonParseError::NoError);
        QCOMPARE(root.value(configKey::configVersion).toInt(),int(serverConfigUtils::ConfigSource::AmneziaGateway));
        QCOMPARE(root.value(configKey::hostName).toString(),w.selectedHost);
        QCOMPARE(root.value(configKey::defaultContainer).toString(),QString("amnezia-awg2"));
        const auto containers=root.value(configKey::containers).toArray();
        QCOMPARE(containers.size(),1);
        QCOMPARE(containers.first().toObject().value(configKey::container).toString(),QString("amnezia-awg2"));
        const auto awg=containers.first().toObject().value(configKey::awg).toObject();
        QVERIFY(awg.value(configKey::port).isString());
        QCOMPARE(awg.value(configKey::port).toString(),QString("49963"));
        const auto last=QJsonDocument::fromJson(awg.value(configKey::lastConfig).toString().toUtf8(),&error).object();
        QCOMPARE(error.error,QJsonParseError::NoError);
        QCOMPARE(last.value(configKey::hostName).toString(),w.selectedHost);
        QVERIFY(last.value(configKey::port).isDouble());
        QCOMPARE(last.value(configKey::port).toInt(),49963);
        QCOMPARE(last.value(configKey::clientPrivKey).toString(),QString("$WIREGUARD_CLIENT_PRIVATE_KEY"));
        QCOMPARE(last.value(configKey::clientPubKey).toString(),keys.wireGuardClientPubKey);
        QCOMPARE(last.value(configKey::clientId).toString(),keys.wireGuardClientPubKey);
        const QString native=last.value(configKey::config).toString();
        QVERIFY(native.contains("PrivateKey = $WIREGUARD_CLIENT_PRIVATE_KEY\n"));
        QVERIFY(native.contains(QString("Endpoint = %1:49963\n").arg(w.selectedHost)));
        QVERIFY(native.contains(QString("PublicKey = %1\n").arg(last.value(configKey::serverPubKey).toString())));
        QVERIFY(native.contains(QString("PresharedKey = %1\n").arg(last.value(configKey::pskKey).toString())));
        QCOMPARE(w.subscription.applyMayakAcquireConfig(w.id,keys,encoded,w.selectedHost,49963),ErrorCode::NoError);
        const auto applied=w.servers.apiV2Config(w.id);
        QVERIFY(applied.has_value());
        QCOMPARE(applied->defaultContainer,DockerContainer::Awg2);
        QVERIFY(applied->containers.contains(DockerContainer::Awg2));
        const auto container=applied->containers.value(DockerContainer::Awg2);
        const auto *protocol=container.getAwgProtocolConfig();
        QVERIFY(protocol && protocol->clientConfig.has_value());
        QCOMPARE(protocol->clientConfig->clientPublicKey,keys.wireGuardClientPubKey);
        QCOMPARE(protocol->clientConfig->clientPrivateKey,keys.wireGuardClientPrivKey);
        QVERIFY(protocol->clientConfig->nativeConfig.contains(QString("PrivateKey = %1\n").arg(keys.wireGuardClientPrivKey)));
    }
    void probeCloseFramingRemainsStrict() {
        const QByteArray body = R"({"args":{"mayak_nonce":"n"},"origin":"203.0.113.9"})";
        const QByteArray headers = "HTTP/1.1 200 OK\r\nContent-Length: " + QByteArray::number(body.size()) + "\r\n\r\n";
        QByteArray parsed; QString error;
        QVERIFY(MayakTunnelProbe::parseHttpResponse(headers + body, &parsed, &error));
        QCOMPARE(parsed, body);
        QVERIFY(!MayakTunnelProbe::parseHttpResponse(headers + body.chopped(1), &parsed, &error));
        QVERIFY(!MayakTunnelProbe::parseHttpResponse(headers + body + 'x', &parsed, &error));
        QVERIFY(!MayakTunnelProbe::parseHttpResponse("HTTP/1.1 402 Payment Required\r\n\r\n" + body, &parsed, &error));
        QVERIFY(!MayakTunnelProbe::parseHttpResponse("HTTP/1.1 200 OK\r\nContent-Length:", &parsed, &error));
        QVERIFY(!MayakTunnelProbe::parseHttpResponse({}, &parsed, &error));
        QVERIFY(MayakTunnelProbe::parseHttpResponse("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + body, &parsed, &error));
        QCOMPARE(parsed, body);
        QVERIFY(!MayakTunnelProbe::validateResponse(parsed, "another nonce", {"203.0.113.9"}, nullptr, &error));
        QVERIFY(!MayakTunnelProbe::validateResponse(parsed, "n", {"203.0.113.10"}, nullptr, &error));
    }
    void probeDiagnosticsAreStructuredAndRedacted() {
        ProbeMessageCapture capture;
        MayakTunnelProbe probe;
        MayakTunnelProbeRequest request;
        request.attemptTag = QStringLiteral("SECRET_ATTEMPT_TAG_5108");
        request.nonce = QStringLiteral("SECRET_NONCE_5108");
        request.interfaceName = QStringLiteral("SECRET_INTERFACE_5108");
        request.localAddress = QHostAddress(QStringLiteral("198.51.100.71"));
        request.expectedEgressIpv4 = {QStringLiteral("203.0.113.71")};
        request.deadlineMs = 1000;
        probe.start(request);

        QVERIFY(!capturedProbeOutput.isEmpty());
        const QString joined = capturedProbeOutput.join(QLatin1Char('\n'));
        QVERIFY(joined.contains(QStringLiteral("MayakTunnelProbe event=start")));
        QVERIFY(joined.contains(QStringLiteral("event=start")));
        QVERIFY(joined.contains(QStringLiteral("endpoint=1")));
        QVERIFY(joined.contains(QStringLiteral("elapsed_ms=")));
        QVERIFY(joined.contains(QStringLiteral("remaining_ms=")));
        QVERIFY(joined.contains(QStringLiteral("socket_state=")));
        QVERIFY(joined.contains(QStringLiteral("socket_error=")));
        QVERIFY(joined.contains(QStringLiteral("platform_bind_ok=")));
        QVERIFY(joined.contains(QStringLiteral("requested_local_binding_match=")));
        QVERIFY(joined.contains(QStringLiteral("fd_valid=")));
        QVERIFY(joined.contains(QStringLiteral("tls_error_count=")));
        QVERIFY(joined.contains(QStringLiteral("ssl_mode=")));
        QVERIFY(joined.contains(QStringLiteral("encrypted_bytes_written=")));
        QVERIFY(joined.contains(QStringLiteral("encrypted_bytes_to_write=")));
        QVERIFY(joined.contains(QStringLiteral("peer_verify_error=")));
        QVERIFY(joined.contains(QStringLiteral("alert_sent_level=")));
        QVERIFY(joined.contains(QStringLiteral("alert_received_type=")));
        QVERIFY(joined.contains(QStringLiteral("wire_bytes=")));
        QVERIFY(!joined.contains(QStringLiteral("SECRET_")));
        QVERIFY(!joined.contains(QStringLiteral("198.51.100.71")));
        QVERIFY(!joined.contains(QStringLiteral("203.0.113.71")));
    }
    void opensslErrorTokensAreNarrowAndRedacted() {
        const QString qtEnglish = QStringLiteral(
            "Error during SSL handshake: error:0A000086:SSL routines::certificate verify failed");
        const QString qtLocalized = QStringLiteral(
            "Ошибка TLS: error:0A00010B:SSL routines::alert handshake failure");
        QCOMPARE(mayak::diagnostics::openSslErrorCodeTokens(qtEnglish), QStringList{QStringLiteral("0A000086")});
        QCOMPARE(mayak::diagnostics::openSslErrorCodeTokens(qtLocalized), QStringList{QStringLiteral("0A00010B")});

        const QString syntheticError = QStringLiteral(
            "SECRET_HOST secret-key TLS routines:ssl3_read_bytes:error:0A00010B:SSL alert number 40; "
            "provider error:ABCDEF012345:SECRET_NONCE");
        const QStringList tokens = mayak::diagnostics::openSslErrorCodeTokens(syntheticError);
        QCOMPARE(tokens, QStringList({QStringLiteral("0A00010B"), QStringLiteral("ABCDEF012345")}));
        const QString diagnostic = tokens.join(QLatin1Char(','));
        QVERIFY(!diagnostic.contains(QStringLiteral("SECRET"), Qt::CaseInsensitive));
        QVERIFY(!diagnostic.contains(QStringLiteral("TLS routines")));
        QVERIFY(!diagnostic.contains(QStringLiteral("alert number")));
        QVERIFY(!diagnostic.contains(QStringLiteral("nonce"), Qt::CaseInsensitive));

        const QStringList invalidTokens = mayak::diagnostics::openSslErrorCodeTokens(
            QStringLiteral("error:1234567: error:0123456789ABCDEF1234: fooerror:0A000086: error:0A00008Z:"));
        QVERIFY(invalidTokens.isEmpty());

        QString manyCodes;
        QStringList expected;
        for (int i = 1; i <= 12; ++i) {
            const QString code = QStringLiteral("%1").arg(i, 8, 16, QLatin1Char('0')).toUpper();
            manyCodes += QStringLiteral("prefix error:%1: ").arg(code);
            if (i <= 8) expected.append(code);
        }
        QCOMPARE(mayak::diagnostics::openSslErrorCodeTokens(manyCodes), expected);
    }
    void ownProofAndExactRelease() {
        World w;QVERIFY(w.app.isMayakManagedServer(w.id));QVERIFY(w.app.mayakSessionToken().size());
        w.connection.openConnection(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,5000);
        QCOMPARE(w.records(),1);QVERIFY(w.connection.isConnected());
        const auto applied=w.servers.apiV2Config(w.id); QVERIFY(applied.has_value());
        QCOMPARE(applied->defaultContainer,DockerContainer::Awg2);
        QVERIFY(applied->containers.contains(DockerContainer::Awg2));
        QVERIFY(!w.connection.canInstallUpdate());
        w.connection.closeConnection();QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QCOMPARE(w.records(),0);QCOMPARE(w.releases,1);QVERIFY(w.events.indexOf("down")<w.events.indexOf("release"));
        QVERIFY(w.connection.canInstallUpdate());
    }
    void fullCandidateFallsBack() {
        World w;w.fullFirst=true;w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,5000);
        QCOMPARE(w.acquires,2);QCOMPARE(w.starts,1);w.runtime->cancel();QTRY_COMPARE(w.records(),0);
    }
    void deadCandidateStopsBeforeFallback() {
        World w;w.deadFirst=true;w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,5000);
        QCOMPARE(w.starts,2);QVERIFY(w.events.indexOf("down")<w.events.indexOf("release"));
        w.runtime->cancel();QTRY_COMPARE(w.records(),0);
    }
    void untrustedAcquireCannotStartOrSkipLedger() {
        World w;w.lostAcquire=true;w.runtime->begin(w.id);QTRY_COMPARE(w.state,Vpn::ConnectionState::Error);
        QCOMPARE(w.starts,0);QCOMPARE(w.acquires,1);QCOMPARE(w.records(),1);
        w.lostAcquire=false;w.runtime->begin(w.id);QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,5000);
        QCOMPARE(w.reconciles,1);w.runtime->cancel();QTRY_COMPARE(w.records(),0);
    }
    void cancellationCleansLateAcquire() {
        World w; ConnectionUiController ui(&w.connection,nullptr); w.acquireDelay=300;
        w.runtime->begin(w.id);QTRY_COMPARE(w.acquires,1);w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);QCOMPARE(w.starts,0);QCOMPARE(w.releases,1);
        QVERIFY(ui.exitLocation().isEmpty());
    }
    void queuedStartCannotActivateAfterCancel() {
        World w;w.holdStart=true;w.runtime->begin(w.id);QTRY_COMPARE(w.starts,1);w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);QVERIFY(!w.current.gate->commit());QVERIFY(!w.backendRunning);
    }
    void noReleaseWithoutDown() {
        World w;w.runtime->begin(w.id);QTRY_COMPARE(w.state,Vpn::ConnectionState::Connected);
        w.missingStop=true;w.runtime->cancel();QTRY_COMPARE(w.state,Vpn::ConnectionState::Error);
        QCOMPARE(w.releases,0);QCOMPARE(w.records(),1);
    }
    void failedNativeStopRetriesSameOwnerAndStaysOff() {
        World w; w.failStopOnce=true;
        QStringList phases;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,
                [&w,&phases](Vpn::ConnectionState,const QString&) { phases.append(w.runtime->connectionPhase()); });
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),1000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("failed"));
        QVERIFY(phases.contains(QStringLiteral("failed")));
        const int starts=w.starts, acquires=w.acquires;
        const int stops=w.stops;
        QVERIFY(w.backendRunning);
        w.runtime->retryCleanup(); w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),2000);
        QCOMPARE(w.starts,starts); QCOMPARE(w.acquires,acquires);
        QCOMPARE(w.stops,stops+1);
        QVERIFY(!w.backendRunning); QCOMPARE(w.records(),0);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        QVERIFY(phases.contains(QStringLiteral("cancelled")));
    }
    void serverCleanupRetryUsesExistingRecordWithoutReconnect() {
        World w; w.failRelease=true;
        QStringList phases;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,
                [&w,&phases](Vpn::ConnectionState,const QString&) { phases.append(w.runtime->connectionPhase()); });
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),1500);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("failed"));
        QVERIFY(phases.contains(QStringLiteral("failed")));
        QVERIFY(!w.backendRunning); QCOMPARE(w.records(),1);
        const int starts=w.starts, acquires=w.acquires;
        w.app.setMayakSessionToken("different-account-session");
        w.failRelease=false;
        w.runtime->retryCleanup(); w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),2000);
        QCOMPARE(w.starts,starts); QCOMPARE(w.acquires,acquires);
        QCOMPARE(w.records(),0); QVERIFY(w.reconciles>0);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        QVERIFY(phases.contains(QStringLiteral("cancelled")));
    }
    void neverFinishingReleaseSettlesAndManualRetryReconciles() {
        World w; w.holdReleaseForever=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        const int starts=w.starts, acquires=w.acquires;
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),4000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("failed"));
        QCOMPARE(w.releases,1); QCOMPARE(w.records(),1); QVERIFY(!w.backendRunning);
        w.holdReleaseForever=false;
        w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),3000);
        QCOMPARE(w.reconciles,1); QCOMPARE(w.records(),0);
        QCOMPARE(w.starts,starts); QCOMPARE(w.acquires,acquires);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        // Let the fake transport deliver a stale negative after the retry won;
        // this also drains its QFutureWatcher before the fixture is destroyed.
        for (const auto& promise:w.heldTransportPromises) {
            promise->addResult({ErrorCode::NoError,QByteArrayLiteral("{\"released\":false}"),true});
            promise->finish();
        }
        QCoreApplication::processEvents();
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
    }
    void neverProvenSettlesOnceOffAllowsNewOnAndOldReplyCannotChangeIt() {
        World w; w.holdProvenForever=true;
        w.runtime->begin(w.id); QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        QTRY_COMPARE(w.heldTransportPromises.size(),1);
        w.runtime->cancel(); QTRY_COMPARE(w.records(),0);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),3000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        w.holdProvenForever=false;
        w.runtime->begin(w.id); QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        const auto ticket=w.current;
        w.drainHeld(QByteArrayLiteral("{\"proven\":true}"));
        QTest::qWait(50);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("connected")); QVERIFY(w.current.same(ticket));
        w.runtime->cancel(); QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),3000); QCOMPARE(w.records(),0);
    }
    void latePreflightPositiveCannotResumeFailedOn() {
        World w; w.seed(); w.holdReconcileForever=true;
        w.runtime->begin(w.id); QTRY_COMPARE(w.reconciles,1);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,3000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("failed"));
        w.drainHeld(QByteArrayLiteral("{\"reconciled\":true}"));
        QTRY_COMPARE(w.records(),0); QTest::qWait(100);
        QCOMPARE(w.acquires,0); QCOMPARE(w.starts,0); QVERIFY(w.permissionRequestId.isEmpty());
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("failed")); QVERIFY(!w.runtime->busy());
        w.holdReconcileForever=false; w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.runtime->cancel(); QTRY_COMPARE(w.records(),0);
    }
    void cancelledPreflightLatePositiveOnlySettlesOldObligation() {
        World w; w.seed(); w.holdReconcileForever=true;
        w.runtime->begin(w.id); QTRY_COMPARE(w.reconciles,1); w.runtime->cancel();
        QVERIFY(w.runtime->cleanupPending());
        w.drainHeld(QByteArrayLiteral("{\"reconciled\":true}"));
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),2000);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected); QCOMPARE(w.acquires,0); QCOMPARE(w.starts,0);
        w.holdReconcileForever=false; w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.drainHeld(QByteArrayLiteral("{\"reconciled\":true}")); QTest::qWait(50);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("connected"));
        w.runtime->cancel(); QTRY_COMPARE(w.records(),0);
    }
    void stalePreflightTimeoutCannotOverwriteEarlySuccessfulCleanupRetry() {
        World w; w.seed(); w.holdReconcileForever=true;
        w.runtime->begin(w.id); QTRY_COMPARE_WITH_TIMEOUT(w.reconciles,1,500);
        QElapsedTimer originalRequest; originalRequest.start(); // old timer already exists
        w.runtime->cancel(); QVERIFY(w.runtime->cleanupPending());
        w.holdReconcileForever=false; w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),1000);
        QVERIFY(originalRequest.elapsed()<2000); // new retry won before the old 2500ms timeout
        QCOMPARE(w.reconciles,2); QCOMPARE(w.records(),0);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        QVERIFY(w.runtime->busy()); // only the original held request still owns a counter
        QSignalSpy laterStates(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged);
        QTest::qWait(int(qMax<qint64>(0,2700-originalRequest.elapsed())));
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        QVERIFY(!w.runtime->cleanupPending()); QVERIFY(!w.runtime->busy());
        mayak::attempts::MayakAttemptStore reopened(&w.settings);
        const auto ledger=reopened.load(); QVERIFY(ledger.ok); QVERIFY(ledger.records.isEmpty());
        QCOMPARE(w.settings.storedValueClass(QStringLiteral("Mayak/pendingAttempts")),
                 SecureQSettings::StoredValueClass::Encrypted);
        QCOMPARE(w.acquires,0); QCOMPARE(w.starts,0);
        for (const auto& row:laterStates) QVERIFY(row.at(0).value<Vpn::ConnectionState>()!=Vpn::ConnectionState::Error);
        // A subsequent authenticated positive can settle only its exact old
        // ledger obligation; the already retired counter must not settle twice.
        w.drainHeld(QByteArrayLiteral("{\"reconciled\":true}")); QTest::qWait(50);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        QVERIFY(!w.runtime->cleanupPending()); QVERIFY(!w.runtime->busy()); QCOMPARE(w.records(),0);
    }
    void cancelledPersistedStartedRecordCanRetryAfterPreflightTimeout() {
        World w; w.seed();
        mayak::attempts::MayakAttemptStore store(&w.settings);
        const auto identity=store.load().records.first().identity();
        QVERIFY(store.markMayHaveStarted(identity).ok);
        w.holdReconcileForever=true; w.runtime->begin(w.id); QTRY_COMPARE(w.reconciles,1);
        w.runtime->cancel(); QTest::qWait(2700);
        QVERIFY(w.runtime->cleanupPending()); QCOMPARE(w.records(),1);
        w.holdReconcileForever=false; w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),2000); QCOMPARE(w.records(),0);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        w.drainHeld(QByteArrayLiteral("{\"reconciled\":true}")); QTest::qWait(50);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled")); QCOMPARE(w.acquires,0); QCOMPARE(w.starts,0);
    }
    void oldPreflightPositiveCannotReopenAfterNewRetryNegative() {
        World w; w.seed(); w.holdReconcileForever=true;
        w.runtime->begin(w.id); QTRY_COMPARE(w.reconciles,1);
        w.runtime->cancel(); QTest::qWait(2700); w.runtime->retryCleanup();
        QTRY_COMPARE(w.reconciles,2); QCOMPARE(w.heldTransportPromises.size(),2);
        const auto old=w.heldTransportPromises.at(0), current=w.heldTransportPromises.at(1);
        old->addResult({ErrorCode::NoError,QByteArrayLiteral("{\"reconciled\":true}"),true}); old->finish();
        QTRY_COMPARE(w.records(),0);
        current->addResult({ErrorCode::NoError,QByteArrayLiteral("{\"reconciled\":false}"),true}); current->finish();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),2000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        QVERIFY(!w.runtime->cleanupPending()); QCOMPARE(w.acquires,0); QCOMPARE(w.starts,0);
    }
    void oldPreflightPositiveCannotResumeOrOverwriteNewCycle() {
        World w; w.seed(); w.holdReconcileForever=true;
        w.runtime->begin(w.id); QTRY_COMPARE(w.reconciles,1);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,3000);
        w.holdReconcileForever=false; w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        const auto ticket=w.current;
        w.drainHeld(QByteArrayLiteral("{\"reconciled\":true}")); QTest::qWait(100);
        QCOMPARE(w.state,Vpn::ConnectionState::Connected); QVERIFY(w.current.same(ticket)); QCOMPARE(w.records(),1);
        w.runtime->cancel(); QTRY_COMPARE(w.records(),0);
    }
    void cancelDuringInitialInspectionRequiresPositiveOff() {
        World w; w.holdInspection=true; w.runtime->begin(w.id);
        QTRY_VERIFY(bool(w.heldInspection)); w.runtime->cancel();
        QVERIFY(w.state!=Vpn::ConnectionState::Disconnected); QVERIFY(w.runtime->cleanupPending());
        w.runtime->begin(w.id); QCOMPARE(w.starts,0);
        w.heldInspection({B::OwnState::Off,w.inspectionNonce,{},{}});
        QTRY_VERIFY(!w.runtime->cleanupPending()); QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.starts,0); QCOMPARE(w.acquires,0); QVERIFY(w.permissionRequestId.isEmpty());
    }
    void cancelDuringRecoveryRequiresExactDown() {
        World w; w.activeInspection=true; w.holdNextStop=true; w.runtime->begin(w.id);
        QTRY_VERIFY(bool(w.heldStopDone)); w.runtime->cancel();
        QVERIFY(w.state!=Vpn::ConnectionState::Disconnected); QVERIFY(w.runtime->cleanupPending());
        const auto ticket=w.current;
        B::Ticket wrong{ticket.opaqueAttempt,std::make_shared<B::StartGate>()};
        w.heldStopDone({wrong,B::Outcome::ConfirmedDown,{},w.heldStopNonce}); QTest::qWait(50);
        QVERIFY(w.runtime->cleanupPending()); QVERIFY(w.state!=Vpn::ConnectionState::Disconnected);
        w.backendRunning=false; w.heldStopDone({ticket,B::Outcome::ConfirmedDown,{},w.heldStopNonce});
        QTRY_VERIFY(!w.runtime->cleanupPending()); QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.acquires,0); QCOMPARE(w.starts,0);
    }
    void lateReleasePositiveAfterBothDeadlinesCompletesConsistently() {
        World w; w.releaseDelay=3500;
        w.runtime->begin(w.id); QTRY_COMPARE(w.state,Vpn::ConnectionState::Connected);
        w.runtime->cancel(); QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),3000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("failed"));
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),2000);
        QCOMPARE(w.records(),0); QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled")); QVERIFY(!w.runtime->busy());
    }
    void neverStartedLateLeaseReconcileCanCompleteOffAndNewOn() {
        World w; w.acquireDelay=300; w.holdReleaseForever=true;
        w.runtime->begin(w.id); QTRY_COMPARE(w.acquires,1); w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),3500); QCOMPARE(w.starts,0); QCOMPARE(w.records(),1);
        w.holdReleaseForever=false; w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),2000); QCOMPARE(w.records(),0);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected); QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        w.runtime->begin(w.id); QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.drainHeld(QByteArrayLiteral("{\"released\":true}")); QTest::qWait(50);
        QCOMPARE(w.state,Vpn::ConnectionState::Connected); QCOMPARE(w.records(),1);
        w.runtime->cancel(); QTRY_COMPARE(w.records(),0);
    }
    void multiRecordCleanupHasOneTenSecondBudget() {
        World w; w.failRelease=true;
        w.runtime->begin(w.id); QTRY_COMPARE(w.state,Vpn::ConnectionState::Connected);
        w.runtime->cancel(); QTRY_VERIFY(w.runtime->cleanupPending());
        w.seed(6); QCOMPARE(w.records(),7); w.reconcileDelay=2250;
        QElapsedTimer elapsed; elapsed.start(); qint64 budgetTerminalAt=-1;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState state,const QString&) {
            // The coordinator may separately finish its original 3s stop
            // deadline. Observe this cleanup attempt's common deadline only.
            if (state==Vpn::ConnectionState::Error && elapsed.elapsed()>=9000 && budgetTerminalAt<0)
                budgetTerminalAt=elapsed.elapsed();
        });
        w.runtime->retryCleanup();
        QTRY_COMPARE_WITH_TIMEOUT(w.reconciles,5,10500);
        QTest::qWait(2600); // last positive arrives at 11.25s, after the shared deadline
        QVERIFY(elapsed.elapsed()<12500); QCOMPARE(w.reconciles,5);
        qInfo() << "cleanup_budget_terminal_ms=" << budgetTerminalAt;
        QVERIFY2(budgetTerminalAt>=9700 && budgetTerminalAt<=10400,qPrintable(QString::number(budgetTerminalAt)));
        QVERIFY(w.runtime->cleanupPending()); QCOMPARE(w.records(),2);
        QCOMPARE(w.acquires,1); QCOMPARE(w.starts,1);
        w.reconcileDelay=0; w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),2000); QCOMPARE(w.records(),0);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        QTest::qWait(50);
        QCOMPARE(w.records(),0); QVERIFY(!w.runtime->busy());
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
    }
    void synchronousCleanupSettlesWithoutCounterUnderflow() {
        World w; w.synchronousCleanup=true;
        w.runtime->begin(w.id); QTRY_COMPARE(w.state,Vpn::ConnectionState::Connected);
        w.runtime->cancel(); QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),3000); QCOMPARE(w.records(),0);
        w.runtime->begin(w.id); QTRY_COMPARE(w.state,Vpn::ConnectionState::Connected);
        w.runtime->cancel(); QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),3000); QCOMPARE(w.records(),0);
    }
    void tenSequentialFixtureConnectOffCyclesDrainLedger() {
        World w;
        for (int cycle=0; cycle<10; ++cycle) {
            w.runtime->begin(w.id);
            QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
            QCOMPARE(w.records(),1);
            w.failRelease=(cycle%3==1);
            for (int press=0;press<10;++press) w.runtime->cancel();
            if (w.failRelease) {
                QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),1500);
                QCOMPARE(w.records(),1);
                w.failRelease=false;
                for (int press=0;press<10;++press) w.runtime->retryCleanup();
            }
            QTRY_VERIFY_WITH_TIMEOUT(w.runtime->connectionPhase()==QStringLiteral("cancelled"),3000);
            QVERIFY(!w.runtime->busy()); QCOMPARE(w.records(),0);
        }
        QCOMPARE(w.acquires,10); QCOMPARE(w.starts,10); QCOMPARE(w.releases,10);
        QCOMPARE(w.stops,10); QCOMPARE(w.reconciles,3);
    }
    void neverFinishingReconcileSettlesAndManualRetryCompletes() {
        World w; w.failRelease=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),1500);
        w.failRelease=false; w.holdReconcileForever=true;
        w.runtime->retryCleanup();
        QTRY_COMPARE_WITH_TIMEOUT(w.reconciles,1,500);
        QTest::qWait(2700); // The phase was already failed from release; wait past this reconcile's own deadline.
        QCOMPARE(w.records(),1); QVERIFY(w.runtime->cleanupPending());
        w.holdReconcileForever=false;
        w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),2500);
        QCOMPARE(w.reconciles,2); QCOMPARE(w.records(),0);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        for (const auto& promise:w.heldTransportPromises) {
            promise->addResult({ErrorCode::NoError,QByteArrayLiteral("{\"reconciled\":false}"),true});
            promise->finish();
        }
        QCoreApplication::processEvents();
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
    }
    void directBeginCannotReplacePendingCleanup() {
        World w; w.failRelease=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),1500);
        const int configs=w.events.count("config"), acquires=w.acquires, starts=w.starts;
        QCOMPARE(w.connection.openConnection(w.id),ErrorCode::NoError);
        w.runtime->begin(w.id);
        QTest::qWait(100);
        QCOMPARE(w.events.count("config"),configs); QCOMPARE(w.acquires,acquires); QCOMPARE(w.starts,starts);
        QVERIFY(w.runtime->cleanupPending()); QCOMPARE(w.records(),1);
    }
    void exactLateNativePositiveAllowsRetryNegativeToFinishCleanup() {
        World w; w.failStopOnce=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),1000);
        w.holdNextStop=true;
        w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(bool(w.heldStopDone),1000);
        QVERIFY(w.observeDown);
        w.backendRunning=false;
        w.observeDown({w.current,B::Outcome::ConfirmedDown,{},QStringLiteral("late-native-positive")});
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),500);
        auto done=std::move(w.heldStopDone);
        done({w.current,B::Outcome::Unknown,{},w.heldStopNonce});
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),2000);
        QCOMPARE(w.reconciles,1); QCOMPARE(w.records(),0);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QVERIFY(w.stopTickets.first().same(w.stopTickets.last()));
        QCOMPARE(w.starts,1); QCOMPARE(w.acquires,1);
        done({w.current,B::Outcome::Unknown,{},w.heldStopNonce});
        QTest::qWait(50);
        QVERIFY(!w.runtime->cleanupPending()); QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
    }
    void nativeConfirmationSurvivesOriginalStopCompletion_data() {
        QTest::addColumn<bool>("deadline");
        QTest::newRow("original-unknown-after-native-positive")<<false;
        QTest::newRow("original-deadline-after-native-positive")<<true;
    }
    void nativeConfirmationSurvivesOriginalStopCompletion() {
        QFETCH(bool,deadline);
        World w;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        const auto loaded=mayak::attempts::MayakAttemptStore(&w.settings).load();
        QVERIFY(loaded.ok); QCOMPARE(loaded.records.size(),1);
        const auto original=loaded.records.first();
        QVERIFY(!original.identity().attemptId.isEmpty());
        QVERIFY(!original.identity().cycleToken.isEmpty());
        QVERIFY(!original.deviceApiKey().isEmpty());
        QVERIFY(!original.installationUuid().isEmpty());
        QVERIFY(!original.publicKey().isEmpty());
        const auto ticket=w.current;
        QStringList phases;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,
                [&w,&phases](Vpn::ConnectionState,const QString&) { phases.append(w.runtime->connectionPhase()); });
        const int configs=w.events.count("config"), starts=w.starts, acquires=w.acquires;
        w.holdNextStop=true; w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(bool(w.heldStopDone),1000);
        auto originalDone=std::move(w.heldStopDone);
        const QString nonce=w.heldStopNonce;
        QVERIFY(w.observeDown);
        w.backendRunning=false;
        w.observeDown({ticket,B::Outcome::ConfirmedDown});
        QTest::qWait(50); // Drain the real bridge observer before stop completion.
        if (!deadline) originalDone({ticket,B::Outcome::Unknown,{},nonce});
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),3500);
        // Neither an expired nor a negative bounded call may release the lease.
        QCOMPARE(w.releases,0); QCOMPARE(w.reconciles,0); QCOMPARE(w.records(),1);
        auto config=*w.servers.apiV2Config(w.id);
        config.authData.apiKey="different-synthetic-device-credential";
        w.servers.editServer(w.id,config.toJson(),serverConfigUtils::configTypeFromJson(config.toJson()));
        w.app.setMayakSessionToken("different-synthetic-account");
        w.missingStop=true; // Native owner has already gone; a restop is Unknown.
        w.runtime->begin(w.id); w.connection.openConnection(w.id);
        w.runtime->retryCleanup(); w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),2000);
        QCOMPARE(w.stops,1); QVERIFY(w.stopTickets.first().same(ticket));
        QCOMPARE(w.reconciles,1); QCOMPARE(w.records(),0);
        QCOMPARE(w.events.count("config"),configs); QCOMPARE(w.starts,starts); QCOMPARE(w.acquires,acquires);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        QJsonObject reconcile;
        for (const auto& payload:w.requestPayloads)
            if (payload.value("action")=="reconcile") reconcile=payload;
        QCOMPARE(reconcile.value("attempt_id").toString(),original.identity().attemptId);
        QCOMPARE(reconcile.value("auth_data").toObject().value("api_key").toString(),original.deviceApiKey());
        QCOMPARE(reconcile.value("installation_uuid").toString(),original.installationUuid());
        QCOMPARE(reconcile.value("public_key").toString(),original.publicKey());
        QCOMPARE(reconcile.value("service_type").toString(),original.serviceType());
        QCOMPARE(reconcile.value("service_protocol").toString(),original.serviceProtocol());
        QCOMPARE(reconcile.value("user_country_code").toString(),original.userCountryCode());
        QCOMPARE(reconcile.value("server_country_code").toString(),original.serverCountryCode());
        // Repeated old completions cannot reopen a completed OFF or stop a new ON.
        originalDone({ticket,B::Outcome::Unknown,{},nonce});
        QTest::qWait(50);
        QVERIFY(!w.runtime->cleanupPending()); QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        config.authData.apiKey=original.deviceApiKey();
        w.servers.editServer(w.id,config.toJson(),serverConfigUtils::configTypeFromJson(config.toJson()));
        w.missingStop=false; w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("connected"));
        QVERIFY(!w.current.same(ticket));
        originalDone({ticket,B::Outcome::ConfirmedDown,{},nonce});
        w.observeDown({ticket,B::Outcome::ConfirmedDown});
        QTest::qWait(50);
        QVERIFY(w.backendRunning); QCOMPARE(w.state,Vpn::ConnectionState::Connected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("connected"));
        QVERIFY(phases.contains(QStringLiteral("cancelled")));
        w.runtime->cancel(); QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,2000);
    }
    void mismatchedNativePositiveCannotConfirmCleanup() {
        World w; w.missingStop=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.runtime->cancel(); QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),1000);
        QVERIFY(w.observeDown);
        // Same opaque attempt with a different gate is a different owner.
        B::Ticket wrongGate{w.current.opaqueAttempt,std::make_shared<B::StartGate>()};
        B::Ticket wrongAttempt{guid(),w.current.gate};
        w.observeDown({wrongGate,B::Outcome::ConfirmedDown});
        w.observeDown({wrongAttempt,B::Outcome::ConfirmedDown});
        QTest::qWait(50);
        w.runtime->retryCleanup(); QTest::qWait(100);
        QVERIFY(w.runtime->cleanupPending()); QVERIFY(w.backendRunning);
        QCOMPARE(w.records(),1); QCOMPARE(w.releases,0); QCOMPARE(w.reconciles,0);
        QCOMPARE(w.acquires,1); QCOMPARE(w.starts,1);
        w.backendRunning=false; w.observeDown({w.current,B::Outcome::ConfirmedDown});
        QTest::qWait(50); w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),2000);
        QCOMPARE(w.records(),0); QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
    }
    void retryWaitsForOriginalReleaseAndOldNegativeCannotReopenCleanup() {
        World w; w.failRelease=true; w.releaseDelay=5000;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),3500);
        QCOMPARE(w.releases,1);
        w.failRelease=false;
        w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),2000);
        QCOMPARE(w.reconciles,1); QCOMPARE(w.records(),0);
        QTest::qWait(2600); // Original release arrives after its operation token was retired.
        QTest::qWait(100);
        QVERIFY(!w.runtime->cleanupPending()); QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
    }
    void badProofNeverConnected() {
        World w;w.badProof=true;QSignalSpy spy(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged);
        w.runtime->begin(w.id);QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,6000);
        for(const auto& row:spy) QVERIFY(row.at(0).value<Vpn::ConnectionState>()!=Vpn::ConnectionState::Connected);
        // A rejected proof stops/releases the first candidate before trying the second.
        QCOMPARE(w.acquires,2);QCOMPARE(w.starts,2);QVERIFY(w.events.contains("probe"));
        QCOMPARE(w.events.count("probe"),2);QCOMPARE(w.events.count("down"),2);QCOMPARE(w.releases,2);
        QStringList lifecycle;
        for(const auto& event:w.events)
            if(event=="start" || event=="probe" || event=="down" || event=="release") lifecycle<<event;
        QCOMPARE(lifecycle,QStringList({"start","probe","down","release","start","probe","down","release"}));
        QCOMPARE(w.records(),0);
    }

    // ---- Connected-state truth and Android soft recovery (5.1.0.17) ----
    void stuckTransportShowsReconnectingAndSoftRecoversWithoutRestart() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int starts=w.starts, stops=w.stops, releases=w.releases, acquires=w.acquires;
        QList<Vpn::ConnectionState> seen;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&seen](Vpn::ConnectionState s,QString){seen<<s;});
        w.tunnelDown=true;
        QTRY_VERIFY_WITH_TIMEOUT(w.recovers>=1,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,5000);
        QVERIFY(seen.contains(Vpn::ConnectionState::Reconnecting));
        QCOMPARE(w.runtime->message(),QStringLiteral("Подключено"));
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("connected"));
        QCOMPARE(w.runtime->exitLocation().value("cityId").toString(),QStringLiteral("oslo"));
        QCOMPARE(w.recovers,1);
        // No re-admission, no native stop, no release: the same ticket keeps running.
        QCOMPARE(w.starts,starts); QCOMPARE(w.stops,stops); QCOMPARE(w.releases,releases); QCOMPARE(w.acquires,acquires);
        // The requested replacement (new generation) is not treated as an autonomous reset.
        QTest::qWait(900);
        QCOMPARE(w.state,Vpn::ConnectionState::Connected); QCOMPARE(w.stops,stops); QCOMPARE(w.recovers,1);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QCOMPARE(w.records(),0);
    }

    void osNoNetworkShowsWaitingAndNeverRecovers() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops;
        QVERIFY(bool(w.observeNetwork));
        w.tunnelDown=true; w.observeNetwork(w.current,false);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Reconnecting,3000);
        QCOMPARE(w.runtime->message(),QStringLiteral("Нет сети — ждём…"));
        QTest::qWait(1000);
        QCOMPARE(w.recovers,0); QCOMPARE(w.state,Vpn::ConnectionState::Reconnecting);
        w.tunnelDown=false; w.observeNetwork(w.current,true);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,3000);
        QCOMPARE(w.recovers,0); QCOMPARE(w.stops,stops);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    void networkChangeRecoversOnFirstFailedProbe() {
        FastRecoveryTiming timing;
        auto fast=MayakAutoConnectRuntime::recoveryTiming();
        fast.stuckRxAfterNetworkMs=0; // isolate the rule: after a network change one failure suffices
        MayakAutoConnectRuntime::setRecoveryTimingForTests(fast);
        World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops;
        w.tunnelDown=true;
        const int mark=w.events.size();
        w.observeNetwork(w.current,true);
        QTRY_VERIFY_WITH_TIMEOUT(w.recovers>=1,3000);
        const QStringList after=w.events.mid(mark);
        QCOMPARE(after.mid(0,after.indexOf("recover")).count("probe"),1);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,3000);
        QCOMPARE(w.stops,stops);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    void networkLossWithoutLaterEventStopsBlockingRecovery() {
        FastRecoveryTiming timing;
        auto fast=MayakAutoConnectRuntime::recoveryTiming();
        fast.networkLostExpiryMs=500;
        MayakAutoConnectRuntime::setRecoveryTimingForTests(fast);
        World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        w.tunnelDown=true; w.observeNetwork(w.current,false);
        QTRY_COMPARE_WITH_TIMEOUT(w.runtime->message(),QStringLiteral("Нет сети — ждём…"),3000);
        QCOMPARE(w.recovers,0);
        // The same network came back silently: no validated event ever arrives.
        QTRY_VERIFY_WITH_TIMEOUT(w.recovers>=1,4000);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,3000);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    void networkEventsRacingOwnRecoveryNeverResetTheLadder() {
        FastRecoveryTiming timing; World w(true); w.recoverOk=false;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        w.tunnelDown=true;
        QTRY_VERIFY_WITH_TIMEOUT(w.recovers>=1,5000);
        // e.g. a re-established TUN reported as a "new network" right after each replacement
        for (int i=0;i<12;++i) { w.observeNetwork(w.current,true); QTest::qWait(100); }
        QVERIFY2(w.recovers<=3,qPrintable(QString::number(w.recovers)));
        w.tunnelDown=false;
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,3000);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    void singleRandomProbeMissNeverShowsReconnectingOrRecovers() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QList<Vpn::ConnectionState> seen;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&seen](Vpn::ConnectionState s,QString){seen<<s;});
        w.failNextProbes=1;
        QTRY_COMPARE_WITH_TIMEOUT(w.failNextProbes,0,3000);
        QTest::qWait(1200);
        QVERIFY(!seen.contains(Vpn::ConnectionState::Reconnecting));
        QCOMPARE(w.recovers,0); QCOMPARE(w.state,Vpn::ConnectionState::Connected);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    void failedSoftRecoveryIsBoundedByBackoff() {
        FastRecoveryTiming timing; World w(true); w.recoverOk=false;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops;
        w.tunnelDown=true;
        QTRY_COMPARE_WITH_TIMEOUT(w.recovers,3,5000);
        QTest::qWait(1200);
        QCOMPARE(w.recovers,3); QCOMPARE(w.state,Vpn::ConnectionState::Reconnecting); QCOMPARE(w.stops,stops);
        w.tunnelDown=false;
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,3000);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    void withoutRecoverPortStatusIsHonestAndNothingRestarts() {
        FastRecoveryTiming timing; World w(false); // Windows/desktop: no soft recovery port
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops, starts=w.starts;
        w.tunnelDown=true;
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Reconnecting,3000);
        QCOMPARE(w.runtime->message(),QStringLiteral("Переподключение…"));
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("verifying"));
        QVERIFY(w.runtime->exitLocation().isEmpty());
        w.tunnelDown=false;
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,3000);
        QCOMPARE(w.recovers,0); QCOMPARE(w.stops,stops); QCOMPARE(w.starts,starts);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    void unrequestedGenerationChangeKeepsExistingRestartPath() {
        FastRecoveryTiming timing; World w(false);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops;
        w.health.generation+=1; // autonomous backend replacement, never requested by the owner
        w.observeHealth(w.current,w.health);
        w.tunnelDown=true;
        QTRY_VERIFY_WITH_TIMEOUT(w.stops>stops,5000);
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.state==Vpn::ConnectionState::Disconnected || w.state==Vpn::ConnectionState::Error,8000);
    }

    // ---- UI hidden/frozen: service watchdog owns recovery, Qt learns it on resume (r3) ----
    void hiddenServiceReplacementIsAcceptedOnResume() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops, starts=w.starts, acquires=w.acquires, releases=w.releases;
        QVERIFY(bool(w.observeResume));
        // While hidden the service replaced the backend: new generation, same proof context.
        w.observeResume(w.current,true,true);
        QTest::qWait(30);
        w.health.generation+=1; w.health.rxTotal=0; w.health.txTotal=0;
        w.observeHealth(w.current,w.health);
        QTest::qWait(900);
        QCOMPARE(w.state,Vpn::ConnectionState::Connected); QCOMPARE(w.recovers,0);
        QCOMPARE(w.stops,stops); QCOMPARE(w.starts,starts); QCOMPARE(w.acquires,acquires); QCOMPARE(w.releases,releases);
        // The accepted change is not a latent reset: a later stuck transport soft-recovers
        // instead of escalating to a full restart.
        w.tunnelDown=true;
        QTRY_VERIFY_WITH_TIMEOUT(w.recovers>=1,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,5000);
        QCOMPARE(w.stops,stops); QCOMPARE(w.starts,starts);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QCOMPARE(w.records(),0);
    }

    void resumeWithoutReplacementStillGuardsGeneration() {
        FastRecoveryTiming timing; World w(false);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops;
        w.observeResume(w.current,false,true);
        QTest::qWait(30);
        w.health.generation+=1; // not announced: must stay an autonomous reset
        w.observeHealth(w.current,w.health);
        w.tunnelDown=true;
        QTRY_VERIFY_WITH_TIMEOUT(w.stops>stops,5000);
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.state==Vpn::ConnectionState::Disconnected || w.state==Vpn::ConnectionState::Error,8000);
    }

    void resumeWithoutNetworkShowsWaitingAndNeverRecovers() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops;
        w.tunnelDown=true;
        w.observeResume(w.current,false,false);
        QTRY_COMPARE_WITH_TIMEOUT(w.runtime->message(),QStringLiteral("Нет сети — ждём…"),3000);
        QTest::qWait(600);
        QCOMPARE(w.recovers,0); QCOMPARE(w.stops,stops);
        w.tunnelDown=false; w.observeNetwork(w.current,true);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,3000);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    // ---- Connect-time network failure: retry instead of an immediate error (r5) ----
    void connectNetworkFailureRetriesThenConnects() {
        FastRecoveryTiming timing; World w; w.failConfigCount=2;
        QList<Vpn::ConnectionState> seen; QStringList texts;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState s,QString t){seen<<s;texts<<t;});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.events.count("config_fail"),2);
        QVERIFY(!seen.contains(Vpn::ConnectionState::Error));
        QVERIFY(texts.contains(QStringLiteral("Нет связи с сервером Маяка — повторяем…")));
        QCOMPARE(w.acquires,1); QCOMPARE(w.starts,1);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QCOMPARE(w.records(),0);
    }

    // ---- Windows: the local tunnel adapter does not come up (WinTun after an update) ----
    static void useWindowsHealthMeaning() {
        auto t=MayakAutoConnectRuntime::recoveryTiming(); t.noHealthMeansLocalFailure=true;
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
    }
    void localAdapterFailureRetriesLaterWithoutBlamingExit() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        World w; w.localFailStarts=2; // both exits of the first cycle: no interface
        QList<Vpn::ConnectionState> seen; QStringList texts;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState s,QString t){seen<<s;texts<<t;});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,40000);
        QCOMPARE(w.events.count("local_fail"),2);
        QVERIFY(!seen.contains(Vpn::ConnectionState::Error));
        QVERIFY(std::any_of(texts.cbegin(),texts.cend(),[](const QString& t){
            return t.startsWith(QStringLiteral("VPN-адаптер Windows не запустился — повторим через")); }));
        // No exit was marked as failed: the retry cycle starts with the server's first choice.
        QCOMPARE(w.lastAcquireCandidate(),w.first);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
    }
    void localAdapterFailureGivesUpWithRebootAdvice() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        World w; w.localFailStarts=1000;
        QString last;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState,QString t){last=t;});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,90000);
        QCOMPARE(last,QStringLiteral("VPN-адаптер Windows не запускается. Перезагрузите компьютер и включите Маяк снова."));
        QCOMPARE(w.starts,6); // 2 exits x (first cycle + 2 retries of localStartRetryMs)
        QTest::qWait(500);
        QCOMPARE(w.starts,6); // bounded: no further cycles
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
    }
    void localAdapterFailureOnOneExitStillConnectsInSameCycle() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        World w; w.localFailStarts=1; // first exit: no interface; second exit connects normally
        QStringList texts;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState,QString t){texts<<t;});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,25000);
        QCOMPARE(w.starts,2);
        QCOMPARE(w.lastAcquireCandidate(),w.second);
        QVERIFY(std::none_of(texts.cbegin(),texts.cend(),[](const QString& t){ return t.startsWith(QStringLiteral("VPN-адаптер")); }));
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        // The exit was not blamed: the next connect starts with the server's first choice again.
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.lastAcquireCandidate(),w.first);
        settle(w);
    }
    // Real 5.1.0.19 case: the service blocks ~16 s failing WinTun, so the 3 s stop is unconfirmed.
    void localAdapterFailureWithUnconfirmedStopRestartsAndConnects() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        World w; w.localFailStarts=1; w.localFailStopUnconfirmed=true;
        QList<Vpn::ConnectionState> seen; QStringList texts;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState s,QString t){seen<<s;texts<<t;});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,40000);
        QCOMPARE(w.events.count("local_fail"),1);
        QCOMPARE(w.events.count("down_unconfirmed"),1);
        QVERIFY(!seen.contains(Vpn::ConnectionState::Error));
        QVERIFY(std::any_of(texts.cbegin(),texts.cend(),[](const QString& t){
            return t.startsWith(QStringLiteral("VPN-адаптер Windows не запустился — повторим через")); }));
        QVERIFY(w.reconciles>=1); // the unconfirmed attempt was released exactly before the restart
        QCOMPARE(w.lastAcquireCandidate(),w.first); // the exit was not blamed
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
    }
    void localAdapterUnconfirmedStopPauseIsCancelledByUser() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        auto t=MayakAutoConnectRuntime::recoveryTiming(); t.localStartRetryMs={60000};
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
        World w; w.localFailStarts=1000; w.localFailStopUnconfirmed=true;
        QString last;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState,QString t){last=t;});
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(last.startsWith(QStringLiteral("VPN-адаптер Windows не запустился — повторим через 60 с")),40000);
        QVERIFY(w.runtime->busy());
        const int starts=w.starts;
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTest::qWait(300);
        QCOMPARE(w.starts,starts); // no restart after the user's OFF
        QVERIFY(!w.runtime->busy());
    }
    // Review 5120 #1: the UI path of the main button during the pause is retryCleanup(), not cancel().
    void localAdapterUnconfirmedStopPauseUserRetryCleanupDoesNotReconnect() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        auto t=MayakAutoConnectRuntime::recoveryTiming(); t.localStartRetryMs={60000};
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
        World w; w.localFailStarts=1000; w.localFailStopUnconfirmed=true;
        QString last;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState,QString t){last=t;});
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(last.startsWith(QStringLiteral("VPN-адаптер Windows не запустился — повторим через 60 с")),40000);
        QVERIFY(w.runtime->cleanupPending());
        const int starts=w.starts;
        w.runtime->retryCleanup();            // what ConnectionController::closeConnection() calls
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTest::qWait(300);
        QCOMPARE(w.starts,starts);            // no new session after the user's OFF
        QVERIFY(!w.runtime->busy());
    }
    void localAdapterUnconfirmedStopRestartsAreBoundedAcrossSessions() {
        FastRecoveryTiming timing; useWindowsHealthMeaning(); // localStartRetryMs = {100,150}
        World w; w.localFailStarts=1000; w.localFailStopUnconfirmed=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,60000);
        QCOMPARE(w.events.count("local_fail"),3); // first session + 2 restarts, then the cleanup prompt
        QVERIFY(w.runtime->cleanupPending());
        const int starts=w.starts;
        QTest::qWait(500);
        QCOMPARE(w.starts,starts);
        w.runtime->retryCleanup();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        // A new user connect starts with a fresh retry budget.
        w.localFailStarts=0;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        settle(w);
    }
    void windowsHealthMeaningIsThePlatformDefault() {
        const MayakAutoConnectRuntime::RecoveryTiming defaults;
#ifdef Q_OS_WINDOWS
        QVERIFY(defaults.noHealthMeansLocalFailure);
#else
        QVERIFY(!defaults.noHealthMeansLocalFailure);
#endif
        QCOMPARE(defaults.localStartRetryMs,(QList<qint64>{30000,60000,120000,240000,300000}));
    }
    void localAdapterRetryIsCancelledByUser() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        auto t=MayakAutoConnectRuntime::recoveryTiming(); t.localStartRetryMs={60000};
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
        World w; w.localFailStarts=1000;
        QString last;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState,QString t){last=t;});
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(last.startsWith(QStringLiteral("VPN-адаптер Windows не запустился — повторим через 60 с")),40000);
        QCOMPARE(w.state,Vpn::ConnectionState::Preparing);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        const int starts=w.starts;
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTest::qWait(300);
        QCOMPARE(w.starts,starts);
        QVERIFY(!w.runtime->busy());
    }

    void connectNetworkFailureGivesUpAfterBoundedRetries() {
        FastRecoveryTiming timing; World w; w.failConfigCount=100;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,10000);
        QCOMPARE(w.events.count("config_fail"),4); // first try + 3 retries (connectRetryMs size)
        QCOMPARE(w.acquires,0); QCOMPARE(w.starts,0); QCOMPARE(w.records(),0);
        QTest::qWait(500);
        QCOMPARE(w.events.count("config_fail"),4);
        QVERIFY(!w.runtime->busy());
    }

    // ---- Cold-start adoption of the running backend (r6) ----
    void adoptRunningTunnelOnColdStartWithoutStop() {
        FastRecoveryTiming timing; World w(true);
        const QString attempt=w.seedStarted();
        w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running");
        QStringList texts;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&texts](Vpn::ConnectionState,QString t){texts<<t;});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        // Never stopped, never reconciled, no new native start: the same attempt continues.
        QVERIFY(!w.events.contains("down")); QVERIFY(!w.events.contains("reconcile"));
        QCOMPARE(w.adopts,1); QCOMPARE(w.starts,0); QCOMPARE(w.acquires,1);
        QCOMPARE(w.adoptedTicket,attempt);
        bool sameAttempt=false;
        for (const auto& p:w.requestPayloads) if (p.value("action").toString()=="acquire") sameAttempt=p.value("attempt_id").toString()==attempt;
        QVERIFY(sameAttempt);
        QVERIFY(texts.contains(QStringLiteral("Проверяем подключение…")));
        QVERIFY(!texts.contains(QStringLiteral("Выбираем доступный сервер…")));
        QCOMPARE(w.records(),1);
        QCOMPARE(w.runtime->exitLocation().value("cityId").toString(),QStringLiteral("oslo"));
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QVERIFY(w.events.contains("down")); QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
    }

    void adoptRefusedStopsWithRecoveryThenConnectsFresh() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running"); w.adoptOk=false;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.adopts,1);
        const int adopt=w.events.indexOf("adopt"), down=w.events.indexOf("down");
        QVERIFY(adopt>=0 && down>adopt);               // refused -> stopped with the recovery ticket
        QVERIFY(w.events.indexOf("release",down)>down); // the adopted attempt's allocation is released
        QCOMPARE(w.starts,1);                           // then a normal fresh start
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
    }

    void adoptRejectedByServerStopsReconcilesAndContinues() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running"); w.fullFirst=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.adopts,0);
        const int down=w.events.indexOf("down");
        QVERIFY(down>0); QVERIFY(w.events.indexOf("reconcile",down)>down);
        QCOMPARE(w.starts,1); QCOMPARE(w.acquires,2);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
    }

    void adoptCandidateAbsentFallsBackToFreshConnect() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(guid()); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.adopts,0);
        const int down=w.events.indexOf("down");
        QVERIFY(down>w.events.indexOf("config")); QVERIFY(w.events.indexOf("reconcile",down)>down);
        QCOMPARE(w.starts,1);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    void withoutAdoptPortColdStartKeepsStopAndReconcile() {
        FastRecoveryTiming timing; World w(true,false); // Windows: no adoption port
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.adopts,0);
        const int down=w.events.indexOf("down");
        QVERIFY(down>=0 && down<w.events.indexOf("reconcile") && w.events.indexOf("reconcile")<w.events.indexOf("config"));
        QCOMPARE(w.starts,1);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    void cancelDuringAdoptionStopsBackendAndReleases() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running"); w.acquireDelay=800;
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(w.acquires==1,5000);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_VERIFY_WITH_TIMEOUT(w.events.contains("down"),5000);
        QTRY_VERIFY_WITH_TIMEOUT(w.events.contains("reconcile"),5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QCOMPARE(w.adopts,0); QCOMPARE(w.starts,0);
        QTest::qWait(1200); // the delayed acquire reply arrives after cancel and must change nothing
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected); QCOMPARE(w.adopts,0); QCOMPARE(w.records(),0);
    }

    // ---- r8: independent review fixes ----
    void adoptProvesLiveSessionWithoutReplacement() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running");
        w.adoptHandshakeAgeMs=90000; // older than the attempt, inside the live-session window
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.adopts,1); QCOMPARE(w.starts,0); QVERIFY(!w.events.contains("down"));
        settle(w);
    }

    void adoptRejectsStaleSessionHandshake() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running");
        w.adoptHandshakeAgeMs=200000; // beyond WireGuard's 180 s: not a live session
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,15000);
        QCOMPARE(w.adopts,1); QVERIFY(w.starts>=1);
        QVERIFY(w.events.indexOf("down")>=0 && w.events.indexOf("down")<w.events.lastIndexOf("start"));
        settle(w);
    }

    void adoptTransferUnconfirmedStopsWithRecoveryTicket() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running");
        w.adoptDeadline=true; w.failStopOnce=true; // transfer not confirmed, first recovery stop unconfirmed
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,15000);
        QCOMPARE(w.adopts,1);
        // Until the adopted backend is confirmed down, every stop uses the authority that owns it.
        QVERIFY(w.stopTickets.size()>=2);
        QVERIFY(w.stopTickets.at(0).opaqueAttempt.startsWith(QStringLiteral("recovery:")));
        QVERIFY(w.stopTickets.at(1).opaqueAttempt.startsWith(QStringLiteral("recovery:")));
        settle(w);
    }

    void cancelDuringAdoptionReportsDisconnectedOnlyAfterStop() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running"); w.acquireDelay=800;
        bool sawDisconnected=false;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&sawDisconnected](Vpn::ConnectionState s,QString) {
            if (s==Vpn::ConnectionState::Disconnected) sawDisconnected=true;
        });
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(w.acquires==1,5000);
        w.holdNextStop=true; // the adopted backend's stop is still in flight when the user cancels
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(!w.heldStopNonce.isEmpty(),5000);
        QTest::qWait(300);
        QVERIFY(!sawDisconnected); QVERIFY(w.runtime->busy());
        w.backendRunning=false;
        w.heldStopDone({w.stopTickets.last(),B::Outcome::ConfirmedDown,{},w.heldStopNonce});
        QTRY_VERIFY_WITH_TIMEOUT(sawDisconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
    }

    // ---- r9: failover to another exit when the current one stops working ----
    void deadConnectedExitReconnectsToAnotherExitFirst() {
        FastRecoveryTiming timing; World w(false);
        QStringList texts;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&texts](Vpn::ConnectionState,QString t){texts<<t;});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.lastAcquireCandidate(),w.first);
        const int stops=w.stops;
        w.health.generation+=1; // own telemetry reset + failing probes: the exit is dead
        w.observeHealth(w.current,w.health);
        w.tunnelDown=true;
        QTRY_VERIFY_WITH_TIMEOUT(w.stops>stops,8000);
        w.tunnelDown=false; // the other exit works
        QTRY_VERIFY_WITH_TIMEOUT(w.lastAcquireCandidate()==w.second,10000);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.lastAcquireCandidate(),w.second);
        QVERIFY(texts.contains(QStringLiteral("Сервер не отвечает — переподключаемся…")));
        settle(w);
    }

    void serviceFailoverRequestWhileHiddenSwitchesExit() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.lastAcquireCandidate(),w.first);
        QVERIFY(bool(w.observeFailover)); QVERIFY(bool(w.observeVisibility));
        w.observeVisibility(false);
        const int stops=w.stops, acquires=w.acquires;
        w.observeFailover(w.current);
        QTRY_VERIFY_WITH_TIMEOUT(w.stops>stops,5000);
        QTRY_VERIFY_WITH_TIMEOUT(w.acquires>acquires && w.state==Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.lastAcquireCandidate(),w.second);
        settle(w);
    }

    void silentExitIsTriedLastOnNextConnect() {
        FastRecoveryTiming timing; World w(true);
        w.silentFirst=true; // e.g. Vienna unreachable from this network: no handshake answered
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,25000);
        QCOMPARE(w.lastAcquireCandidate(),w.second);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        const int acquires=w.acquires;
        w.runtime->begin(w.id); // a new connect (new session) remembers the silent exit
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.acquires,acquires+1);
        QCOMPARE(w.lastAcquireCandidate(),w.second);
        settle(w);
    }

    void hiddenFailoverWithSingleExitKeepsTunnel() {
        FastRecoveryTiming timing; World w(true);
        w.singleCandidate=true; // no other exit: taking the dead tunnel down would only leak
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        w.observeVisibility(false);
        const int stops=w.stops, acquires=w.acquires;
        w.observeFailover(w.current);
        QTest::qWait(500);
        QCOMPARE(w.stops,stops); QCOMPARE(w.acquires,acquires); QCOMPARE(w.state,Vpn::ConnectionState::Connected);
        settle(w);
    }

    void failoverRequestForAnotherTicketIsIgnored() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops;
        w.observeFailover({guid(),std::make_shared<B::StartGate>()});
        QTest::qWait(400);
        QCOMPARE(w.stops,stops); QCOMPARE(w.state,Vpn::ConnectionState::Connected);
        settle(w);
    }

    // ---- r9: reviewer notes 7 and 8 ----
    void adoptionPermissionDeniedStillStopsAdoptedBackend() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running"); w.holdPermission=true;
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(bool(w.heldPermissionDone),5000);
        auto done=w.heldPermissionDone; w.heldPermissionDone={};
        done(w.permissionRequestId,B::PermissionResult::Denied);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,5000);
        QVERIFY(w.events.contains("down")); QVERIFY(w.events.contains("reconcile"));
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        QCOMPARE(w.adopts,0); QCOMPARE(w.starts,0);
    }

    void adoptionGiveUpWithUnconfirmedStopSaysSo() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(guid()); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running"); w.missingStop=true;
        QStringList texts;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&texts](Vpn::ConnectionState,QString t){texts<<t;});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,8000);
        QCOMPARE(texts.last(),QStringLiteral("Не удалось завершить прежнее подключение. Нажмите «Включить Маяк» ещё раз."));
        QVERIFY(!texts.contains(QStringLiteral("Нет связи с сервером Маяка — повторяем…")));
        QCOMPARE(w.starts,0);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        QTest::qWait(200);
    }

    void hiddenUiProbeFailuresNeverStopTunnel() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QVERIFY(bool(w.observeVisibility));
        const int stops=w.stops, starts=w.starts;
        w.observeVisibility(false);
        w.tunnelDown=true; // e.g. a network switch while the UI is hidden: no health, probes fail
        QTest::qWait(1500);
        QCOMPARE(w.stops,stops); QCOMPARE(w.starts,starts); QCOMPARE(w.state,Vpn::ConnectionState::Connected);
        w.tunnelDown=false; // the service watchdog repaired it meanwhile
        w.observeVisibility(true);
        QTest::qWait(700);
        QCOMPARE(w.stops,stops); QCOMPARE(w.starts,starts); QCOMPARE(w.state,Vpn::ConnectionState::Connected);
        settle(w);
    }

    // ---- Stop outside the app (notification/tile "Disconnect") is the user's stop (r7) ----
    void systemUiDisconnectIsHonouredAsUserStop() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int starts=w.starts, acquires=w.acquires;
        QVERIFY(bool(w.observeUserStop));
        w.tunnelDown=true; // the service already took the tunnel down
        w.observeUserStop(w.current);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTest::qWait(1200);
        // Never recovered, never reconnected, stays off.
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.recovers,0); QCOMPARE(w.starts,starts); QCOMPARE(w.acquires,acquires);
        QVERIFY(!w.runtime->busy());
    }

    // ---------- 5.1.0.21 «4 пути» ----------
    void xrayPathConnectsOnTheSameAllocationWhenAwgIsSilent() {
        FastRecoveryTiming timing;
        CoordinatorTimingGuard timingGuard; auto& t=mayak::autoconnect::Coordinator::timing(); t.awgVerifyMs=400;
        World w; w.singleCandidate=true; w.offerXray=true; w.awgSilent=true;
        w.app.setMayakConnectionMethod("auto");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.runtime->exitLocation().value("pathId").toString(),QStringLiteral("xray-firefox"));
        QCOMPARE(w.awgStarts,1); QCOMPARE(w.xrayStarts,1);
        // Rule 5: the started Xray client never logs destinations.
        {
            const auto client=QJsonDocument::fromJson(w.lastXrayConfig.value("xray_config_data").toObject()
                .value("config").toString().toUtf8()).object();
            QCOMPARE(client.value("log").toObject().value("access").toString(),QStringLiteral("none"));
            QCOMPARE(client.value("log").toObject().value("dnsLog").toBool(true),false);
        }
        QCOMPARE(w.acquires,1);           // one place on the exit for every path
        QCOMPARE(w.releases,0);           // switching paths never releases it
        int acquireWithPaths=0, proven=0;
        for (const auto& p:w.requestPayloads) {
            if (p.value("action").toString()=="acquire" && p.value("mayak_paths").isDouble() && p.value("mayak_paths").toInt()==1) ++acquireWithPaths;
            if (p.value("action").toString()=="proven") ++proven;
        }
        QCOMPARE(acquireWithPaths,1); QCOMPARE(proven,1);
        settle(w);
        QCOMPARE(w.releases,1);
        // Path memory: this network now starts with Xray (AWG stays the fallback).
        w.startedProtocols.clear();
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.startedProtocols.value(0),QStringLiteral("xray"));
        settle(w);
    }
    void onlyAwgNeverStartsXray() {
        FastRecoveryTiming timing;
        CoordinatorTimingGuard timingGuard; auto& t=mayak::autoconnect::Coordinator::timing(); t.awgVerifyMs=400;
        World w; w.singleCandidate=true; w.offerXray=true; w.awgSilent=true;
        w.app.setMayakConnectionMethod("awg");
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(w.state==Vpn::ConnectionState::Error || w.runtime->message().contains(QStringLiteral("повторяем")),10000);
        QCOMPARE(w.xrayStarts,0);
        settle(w);
    }
    void onlyXrayNeverStartsAwg() {
        FastRecoveryTiming timing;
        World w; w.singleCandidate=true; w.offerXray=true;
        w.app.setMayakConnectionMethod("xray");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.awgStarts,0); QCOMPARE(w.xrayStarts,1);
        QCOMPARE(w.runtime->exitLocation().value("pathId").toString(),QStringLiteral("xray-firefox"));
        settle(w);
    }
    void appExclusionsArePreparedBeforeAnyTunnelStarts() {
        FastRecoveryTiming timing; SplitPrepareGuard prepareGuard;
        int prepares=0; QString answer=QStringLiteral("amnezia_active");
        MayakAutoConnectRuntime::setSplitPrepareForTests([&](QObject* ctx, std::function<void(bool, QString)> done) {
            ++prepares; QTimer::singleShot(20, ctx, [done, &answer] { done(true, answer); });
        });
        World w; w.singleCandidate=true;
        w.app.setAppsSplitTunnelingEnabled(true);
        w.app.setAppsRouteMode(amnezia::AppsRouteMode::VpnAllExceptApps);
        w.app.setVpnApps(amnezia::AppsRouteMode::VpnAllExceptApps, {InstalledAppInfo{QStringLiteral("Bank"), {}, QStringLiteral("C:/bank.exe")}});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,10000);
        QVERIFY(w.runtime->message().contains(QStringLiteral("AmneziaVPN")));
        QCOMPARE(prepares,1); QCOMPARE(w.starts,0); QCOMPARE(w.acquires,0);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        answer=QStringLiteral("ok");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(prepares,2);
        settle(w);
    }
    void appExclusionPrepareIsSkippedWithoutExclusions() {
        FastRecoveryTiming timing; SplitPrepareGuard prepareGuard;
        int prepares=0;
        MayakAutoConnectRuntime::setSplitPrepareForTests([&](QObject*, std::function<void(bool, QString)> done) { ++prepares; done(true, QStringLiteral("ok")); });
        World w; w.singleCandidate=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(prepares,0);
        settle(w);
    }
    void appExclusionFailureEndsWithClearErrorAndNoXrayFallback() {
        FastRecoveryTiming timing;
        CoordinatorTimingGuard timingGuard; auto& t=mayak::autoconnect::Coordinator::timing(); t.awgVerifyMs=2000;
        World w; w.singleCandidate=true; w.offerXray=true; w.awgSilent=true; w.appExclusionFails=true;
        w.app.setMayakConnectionMethod("auto");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,10000);
        QVERIFY(w.runtime->message().contains(QStringLiteral("исключения программ")));
        QCOMPARE(w.xrayStarts,0);          // no silent fallback to a path without app exclusions
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        // A later connect is a new session: an old failure does not block it.
        w.appExclusionFails=false; w.awgSilent=false; w.app.setMayakConnectionMethod("awg");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        settle(w);
    }
    void connectedXrayEndsOnlyAfterThreeFailedProbes() {
        FastRecoveryTiming timing;
        World w; w.singleCandidate=true; w.offerXray=true;
        w.app.setMayakConnectionMethod("xray");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int starts=w.xrayStarts;
        w.failNextProbes=2; // two misses in a row: the same tunnel stays
        QTest::qWait(1500);
        QCOMPARE(w.xrayStarts,starts);
        w.tunnelDown=true;  // a dead path is ended and started again
        QTRY_VERIFY_WITH_TIMEOUT(w.xrayStarts>starts,10000);
        w.tunnelDown=false;
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,15000);
        settle(w);
    }
    void onlyXrayWithoutPathsIsAClearError() {
        FastRecoveryTiming timing;
        World w; w.singleCandidate=true; w.offerXray=false;
        w.app.setMayakConnectionMethod("xray");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,10000);
        QVERIFY(w.runtime->message().contains(QStringLiteral("Способ подключения")) || w.runtime->message().contains(QStringLiteral("способ подключения")));
        QCOMPARE(w.starts,0);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
    }
    void deadXrayPathsFallBackToTheNextPathThenError() {
        FastRecoveryTiming timing;
        CoordinatorTimingGuard timingGuard; auto& t=mayak::autoconnect::Coordinator::timing(); t.xrayVerifyMs=300;
        World w; w.singleCandidate=true; w.offerXray=true; w.xrayDead=true;
        w.app.setMayakConnectionMethod("xray");
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(w.xrayStarts>=3,10000);
        QTRY_VERIFY_WITH_TIMEOUT(w.state!=Vpn::ConnectionState::Connecting,10000);
        QVERIFY(w.state!=Vpn::ConnectionState::Connected);
        QCOMPARE(w.acquires>=1,true);
        settle(w);
    }

    void raceWithoutAnswersDropsXrayAndNeverOverlapsATunnel() {
        FastRecoveryTiming timing;
        World w; w.singleCandidate=true; w.offerXray=true; w.withRace=true;
        w.app.setMayakConnectionMethod("xray");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,15000);
        QCOMPARE(w.raceStarts,1); QCOMPARE(w.raceStops,1);
        QCOMPARE(w.xrayStarts,0); // nobody answered through the race entries: no tunnel was started
        // The engine config: one password-protected loopback entry and one outbound per path.
        const auto inbounds=w.raceConfig.value("inbounds").toArray();
        QCOMPARE(inbounds.size(),3);
        for (const auto& v:inbounds) {
            const auto in=v.toObject();
            QCOMPARE(in.value("listen").toString(),QStringLiteral("127.0.0.1"));
            QCOMPARE(in.value("settings").toObject().value("auth").toString(),QStringLiteral("password"));
        }
        QCOMPARE(w.raceConfig.value("outbounds").toArray().size(),3);
        QCOMPARE(w.raceConfig.value("routing").toObject().value("rules").toArray().size(),3);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
    }
    void raceEngineFailureFallsBackToServerOrder() {
        FastRecoveryTiming timing;
        World w; w.singleCandidate=true; w.offerXray=true; w.withRace=true; w.raceEngineOk=false;
        w.app.setMayakConnectionMethod("xray");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,15000);
        QCOMPARE(w.runtime->exitLocation().value("pathId").toString(),QStringLiteral("xray-firefox"));
        QVERIFY(!w.raceRunning);
        settle(w);
    }

    void cancelDuringConnectRetryWaitDisconnects() {
        FastRecoveryTiming timing;
        auto slow=MayakAutoConnectRuntime::recoveryTiming(); slow.connectRetryMs={5000};
        MayakAutoConnectRuntime::setRecoveryTimingForTests(slow);
        World w; w.failConfigCount=100;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.runtime->message(),QStringLiteral("Нет связи с сервером Маяка — повторяем…"),5000);
        QVERIFY(w.runtime->busy());
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,3000);
        QVERIFY(!w.runtime->busy());
        const int fails=w.events.count("config_fail");
        QTest::qWait(400);
        QCOMPARE(w.events.count("config_fail"),fails);
        QCOMPARE(w.acquires,0); QCOMPARE(w.records(),0);
    }
};
int main(int argc,char** argv) {
    QTemporaryDir temp; if(!temp.isValid())return 2;
    QSettings::setDefaultFormat(QSettings::IniFormat);QSettings::setPath(QSettings::IniFormat,QSettings::UserScope,temp.path());
    QSettings::setPath(QSettings::IniFormat,QSettings::SystemScope,temp.path());
    QApplication app(argc,argv);RuntimeTest test;return QTest::qExec(&test,argc,argv);
}
#include "testMayakRuntime.moc"
