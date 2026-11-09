#include <QApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QPromise>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>
#include <QTimer>
#include <QUuid>
#include "core/utils/mayakTunnelProbe.h"
#include "core/controllers/mayakAutoConnectRuntime.h"
#include "core/controllers/mayakAttemptStore.h"
#include "core/controllers/connectionController.h"
#include "core/controllers/api/subscriptionController.h"
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
    bool backendRunning=false, missingStop=false, failRelease=false, failStopOnce=false, holdNextStop=false;
    int releaseDelay=0;
    int acquireDelay=0;
    QString publicKey, selectedHost = "81.29.149.103";
    B::Ticket current;
    QList<B::Ticket> stopTickets;
    QList<QJsonObject> requestPayloads;
    AwgTunnelHealth health;
    std::function<void(B::Ticket,AwgTunnelHealth)> observeHealth;
    B::Done startDone;
    QString permissionRequestId;
    B::PermissionDone heldPermissionDone;
    B::Done heldStopDone;
    QString heldStopNonce;
    std::function<void(B::Result)> observeDown;
    std::unique_ptr<MayakAutoConnectRuntime> runtime;
    Vpn::ConnectionState state=Vpn::ConnectionState::Disconnected;
    World() {
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
            events<<"inspect"; done({backendRunning?B::OwnState::Unknown:B::OwnState::Off,nonce,{},{}});
        };
        port.preparePermissions=[this](QString requestId,B::PermissionDone done) {
            permissionRequestId=requestId;
            if (holdPermission) heldPermissionDone=std::move(done);
            else done(requestId,B::PermissionResult::Ready);
        };
        port.cancelPermissionPreparation=[this](QString requestId) {
            if (requestId==permissionRequestId) heldPermissionDone={};
        };
        port.start=[this](B::Ticket ticket,QString,QJsonObject,qint64,B::Done done) {
            ++starts; events<<"start"; current=ticket;
            if(holdStart) { startDone=done; return; }
            ticket.gate->commit(); backendRunning=true;
            AwgHealthContext expected{guid(),QString(64,'a'),selectedHost+":49963"};
            done({ticket,deadFirst && starts==1?B::Outcome::Failed:B::Outcome::Started,expected});
            health={expected.id,1,expected.peerPublicKey,expected.endpoint,"10.8.0.2","MayakFixture",quint64(QDateTime::currentMSecsSinceEpoch()),10,10,true};
            QTimer::singleShot(10,this,[this,ticket] {if(observeHealth)observeHealth(ticket,health);});
        };
        port.cancel=[](B::Ticket t){t.gate->cancel();};
        port.stop=[this](B::Ticket t,QString nonce,qint64,B::Done done) {
            ++stops; events<<"down"; stopTickets.append(t);
            if(holdNextStop) {holdNextStop=false;heldStopNonce=nonce;heldStopDone=done;return;}
            if(failStopOnce) {failStopOnce=false;done({t,B::Outcome::Unknown,{},nonce});return;}
            if(missingStop) {done({t,B::Outcome::Unknown,{},nonce});return;}
            backendRunning=false; done({t,B::Outcome::ConfirmedDown,{},nonce});
        };
        port.probe=[this](B::Ticket ticket,MayakTunnelProbeRequest request,qint64,B::Probed done) {
            events<<"probe";
            done(ticket,!badProof,{ticket.opaqueAttempt,request.nonce,"81.29.149.103",request.interfaceName,request.localAddress.toString(),true},{});
            health.rxTotal+=500; health.txTotal+=500;
            QTimer::singleShot(10,this,[this,ticket] {if(observeHealth)observeHealth(ticket,health);});
        };
        runtime=std::make_unique<MayakAutoConnectRuntime>(&settings,&servers,&app,&subscription,&connection,port,nullptr,
            [this](const QString& path,const QJsonObject& payload,int){return transport(path,payload);});
        connection.setMayakRuntime(runtime.get());
        connect(runtime.get(),&MayakAutoConnectRuntime::stateChanged,this,[this](auto value,QString){state=value;});
    }
    ~World() {runtime.reset();settings.clearSettings();}
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
    QFuture<GatewayPostResult> transport(QString path,QJsonObject payload) {
        requestPayloads.append(payload);
        QJsonObject response; int delay=0;bool trusted=true;
        if(path.endsWith("config")) {
            publicKey=payload.value("public_key").toString();events<<"config";
            QJsonArray candidates;
            for(const auto& candidate:{first,second}) candidates.append(QJsonObject{{"id",candidate},{"host",candidate==first?"81.29.149.103":"81.29.149.104"},
                {"port",49963},{"preferred",candidate==first},{"expected_egress_ips",QJsonArray{"81.29.149.103"}}});
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
            } else if(action=="release") {++releases;delay=releaseDelay;response={{"released",!backendRunning && !failRelease}};}
            else if(action=="proven") response={{"proven",true}};
            else if(action=="reconcile") {++reconciles;response={{"reconciled",!backendRunning}};}
        }
        auto promise=std::make_shared<QPromise<GatewayPostResult>>();promise->start();auto future=promise->future();
        QTimer::singleShot(delay,this,[promise,response,trusted]{promise->addResult({ErrorCode::NoError,QJsonDocument(response).toJson(QJsonDocument::Compact),trusted});promise->finish();});
        return future;
    }
    int records() {auto result=mayak::attempts::MayakAttemptStore(&settings).load();return result.ok?result.records.size():-1;}
};
}
class RuntimeTest : public QObject {
    Q_OBJECT
private slots:
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
        World w;w.acquireDelay=300;w.runtime->begin(w.id);QTRY_COMPARE(w.acquires,1);w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);QCOMPARE(w.starts,0);QCOMPARE(w.releases,1);
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
        w.runtime->retryCleanup();
        QTest::qWait(150);
        QCOMPARE(w.reconciles,0);
        QTest::qWait(2600);
        QVERIFY(w.runtime->cleanupPending()); QCOMPARE(w.reconciles,0);
        w.failRelease=false; w.releaseDelay=0;
        w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),2000);
        QCOMPARE(w.reconciles,1); QCOMPARE(w.records(),0);
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
};
int main(int argc,char** argv) {
    QTemporaryDir temp; if(!temp.isValid())return 2;
    QSettings::setDefaultFormat(QSettings::IniFormat);QSettings::setPath(QSettings::IniFormat,QSettings::UserScope,temp.path());
    QSettings::setPath(QSettings::IniFormat,QSettings::SystemScope,temp.path());
    QApplication app(argc,argv);RuntimeTest test;return QTest::qExec(&test,argc,argv);
}
#include "testMayakRuntime.moc"
