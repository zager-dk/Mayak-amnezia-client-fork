#include <QtTest>
#include <QTcpServer>
#include <QSslSocket>
#include <QSslConfiguration>
#include <QSslKey>
#include <QFile>
#include <QSignalSpy>
#include <QTimer>
#include <QUrlQuery>
#include <QNetworkInterface>
#ifdef Q_OS_WIN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif
#include "mayakTunnelProbe.h"
Q_DECLARE_METATYPE(MayakTunnelProbeProof)

namespace {
QStringList probeMessages;
QStringList socketWarnings;
void collectMessages(QtMsgType type, const QMessageLogContext &, const QString &message) {
    if (type == QtWarningMsg && (message.contains("QSocket") || message.contains("QAbstractSocket"))) socketWarnings.append(message);
    if (message.startsWith(QStringLiteral("MayakTunnelProbe "))) probeMessages.append(message);
}
struct Capture {
    QtMessageHandler previous = qInstallMessageHandler(collectMessages);
    Capture() { probeMessages.clear(); socketWarnings.clear(); }
    ~Capture() { qInstallMessageHandler(previous); }
};
QByteArray fixtureFile(const QString &name) {
    QFile file(qEnvironmentVariable("MAYAK_LOCAL_TLS_FIXTURE_DIR") + QLatin1Char('/') + name);
    if (!file.open(QIODevice::ReadOnly)) qFatal("Could not read local TLS fixture");
    return file.readAll();
}
struct TrustScope {
    QSslConfiguration original = QSslConfiguration::defaultConfiguration();
    explicit TrustScope(bool trusted = true) {
        auto config = original;
        if (trusted) {
            auto certificates = config.caCertificates();
            certificates.append(QSslCertificate(fixtureFile("ca.pem")));
            config.setCaCertificates(certificates);
        }
        QSslConfiguration::setDefaultConfiguration(config);
    }
    ~TrustScope() { QSslConfiguration::setDefaultConfiguration(original); }
};
class LocalEcho final : public QTcpServer {
public:
    QString scenario;
    QList<QByteArray> requests;
    int connections = 0;
    quint16 clientPort = 0;
    QHostAddress clientAddress;
    explicit LocalEcho(QString mode) : scenario(std::move(mode)) {}
protected:
    void incomingConnection(qintptr fd) override {
        ++connections;
        auto *socket = new QSslSocket(this);
        if (!socket->setSocketDescriptor(fd)) qFatal("Fixture socket adoption failed");
        clientPort = socket->peerPort();
        clientAddress = socket->peerAddress();
        connect(socket, &QSslSocket::disconnected, socket, &QObject::deleteLater);
        if (scenario == "prehandshake-close") { socket->abort(); return; }
        const QString certificate = scenario == "wrong-host" ? "wrong-host" : "server";
        socket->setLocalCertificate(QSslCertificate(fixtureFile(certificate + ".pem")));
        socket->setPrivateKey(QSslKey(fixtureFile(certificate + "-key.pem"), QSsl::Rsa));
        socket->setPeerVerifyMode(QSslSocket::VerifyNone); // fixture server does not require a client certificate
        auto request = std::make_shared<QByteArray>();
        auto sent = std::make_shared<bool>(false);
        connect(socket, &QSslSocket::readyRead, this, [this, socket, request, sent] {
            *request += socket->readAll();
            if (*sent || !request->contains("\r\n\r\n")) return;
            *sent = true;
            requests.append(*request);
            const auto parts = request->split(' ');
            const QString nonce = parts.size() > 1 ? QUrlQuery(QUrl::fromEncoded(parts.at(1))).queryItemValue("mayak_nonce", QUrl::FullyDecoded) : QString();
            QJsonObject args{{"mayak_nonce", scenario == "wrong-nonce" ? QString("wrong") : nonce}};
            QByteArray body = QJsonDocument(QJsonObject{{"args", args}, {"origin", scenario == "wrong-egress" ? "203.0.113.10" : "203.0.113.9"}}).toJson(QJsonDocument::Compact);
            if (scenario == "duplicate-json") body = "{\"args\":{},\"args\":{\"mayak_nonce\":\"" + nonce.toUtf8() + "\"},\"origin\":\"203.0.113.9\"}";
            QByteArray wire = "HTTP/1.1 200 OK\r\nContent-Length: " + QByteArray::number(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
            if (scenario == "valid-close-delimited") wire = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + body;
            if (scenario == "valid-chunked" || scenario == "truncated-chunk" || scenario == "bad-chunk") {
                wire = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + QByteArray::number(body.size(), 16) + "\r\n" + body + "\r\n0\r\n\r\n";
                if (scenario == "truncated-chunk") wire.chop(3);
                if (scenario == "bad-chunk") wire.replace("\r\n0\r\n\r\n", "\r\nQ\r\n\r\n");
            }
            if (scenario == "empty") wire.clear();
            if (scenario == "truncated-head") wire = "HTTP/1.1 200 OK\r\nContent-Length:";
            if (scenario == "short-length") wire.chop(1);
            if (scenario == "extra-length") wire += 'x';
            if (scenario == "oversized") wire = "HTTP/1.1 200 OK\r\n\r\n" + QByteArray(65537, 'x');
            if (scenario == "402") wire.replace("200 OK", "402 Payment Required");
            if (scenario == "valid-fragmented") {
                socket->write(wire.left(13));
                QTimer::singleShot(10, socket, [socket, wire] { socket->write(wire.mid(13, wire.size() - 20)); });
                QTimer::singleShot(25, socket, [socket, wire] { socket->write(wire.right(7)); socket->disconnectFromHost(); });
            } else {
                const int delay = scenario == "delayed" ? 200 : 0;
                QTimer::singleShot(delay, socket, [socket, wire] { socket->write(wire); socket->disconnectFromHost(); });
            }
        });
        socket->startServerEncryption();
    }
};
MayakTunnelProbeRequest requestFor(const LocalEcho &server, int deadline = 1000) {
    MayakTunnelProbeRequest request;
    request.attemptTag = "local-test-attempt";
    request.nonce = "local nonce + & /";
    for (const auto &iface : QNetworkInterface::allInterfaces()) {
        for (const auto &entry : iface.addressEntries()) {
            if (entry.ip() == QHostAddress(QHostAddress::LocalHost)) request.interfaceName = iface.name();
        }
    }
    request.localAddress = QHostAddress::LocalHost;
    request.expectedEgressIpv4 = {"203.0.113.9"};
    request.deadlineMs = deadline;
    request.testHost = "localhost";
    request.testPort = server.serverPort();
    return request;
}
}
class LocalTlsProbeTests : public QObject {
    Q_OBJECT
private slots:
    void initTestCase() { QVERIFY(QSslSocket::supportsSsl()); qRegisterMetaType<MayakTunnelProbeProof>(); }
    void normalAndRejectedClose_data() {
        QTest::addColumn<QString>("scenario"); QTest::addColumn<bool>("success");
        for (const auto &name : {"valid-length", "valid-fragmented", "valid-unread-at-close", "valid-close-delimited", "valid-chunked"})
            QTest::newRow(name) << QString(name) << true;
        for (const auto &name : {"wrong-nonce", "wrong-egress", "untrusted-cert", "wrong-host", "prehandshake-close", "empty", "truncated-head", "short-length", "extra-length", "truncated-chunk", "bad-chunk", "oversized", "402", "duplicate-json", "transport-error", "fatal-alert", "certificate-error-after-body"})
            QTest::newRow(name) << QString(name) << false;
    }
    void normalAndRejectedClose() {
        QFETCH(QString, scenario); QFETCH(bool, success);
        Capture capture;
        TrustScope trust(scenario != "untrusted-cert");
        LocalEcho server(scenario); QVERIFY(server.listen(QHostAddress::LocalHost));
        MayakTunnelProbe probe; QSignalSpy finished(&probe, &MayakTunnelProbe::finished);
        const auto request = requestFor(server);
        const quint64 generation = probe.start(request);
        auto *socket = probe.findChild<QSslSocket *>(); QVERIFY(socket);
        const qintptr boundFd = socket->socketDescriptor();
        const quint16 boundPort = socket->localPort();
        QVERIFY(boundFd >= 0); QVERIFY(boundPort > 0);
        QCOMPARE(socket->localAddress(), request.localAddress);
        bool connectedIdentity = false, encryptedIdentity = false, earlyRead = false;
        connect(socket, &QSslSocket::connected, &probe, [&] {
            connectedIdentity = socket->socketDescriptor() == boundFd && socket->localPort() == boundPort && socket->localAddress() == request.localAddress;
        });
        connect(socket, &QSslSocket::encrypted, &probe, [&] {
            encryptedIdentity = socket->socketDescriptor() == boundFd && socket->localPort() == boundPort && socket->localAddress() == request.localAddress;
        });
        connect(socket, &QSslSocket::readyRead, &probe, [&] { if (!socket->isEncrypted()) earlyRead = true; });
        int remoteErrors = 0; int disconnected = 0; bool injected = false;
        QStringList closeEvents;
        connect(socket, &QSslSocket::errorOccurred, &probe, [&](auto error) {
            if (error == QAbstractSocket::RemoteHostClosedError) { ++remoteErrors; closeEvents.append("remote_close"); }
        });
        connect(socket, &QSslSocket::disconnected, &probe, [&] { ++disconnected; closeEvents.append("disconnected"); });
        if (scenario == "valid-unread-at-close") {
            // Leave all decrypted data unread: the completion handler must drain
            // it at disconnected even when no readyRead handler consumed bytes.
            QObject::disconnect(socket, &QSslSocket::readyRead, nullptr, nullptr);
        }
        if (scenario == "transport-error" || scenario == "fatal-alert" || scenario == "certificate-error-after-body") {
            connect(socket, &QSslSocket::readyRead, &probe, [&, socket] {
                if (injected) return;
                injected = true;
                // Deterministic event-order regression: a complete network body
                // must not be promoted while a failed-attempt retry is queued.
                if (scenario == "transport-error") socket->errorOccurred(QAbstractSocket::NetworkError);
                else if (scenario == "fatal-alert") socket->alertReceived(QSsl::AlertLevel::Fatal, QSsl::AlertType::InternalError, {});
                else socket->sslErrors(QList<QSslError>{QSslError(QSslError::CertificateUntrusted)});
            });
        }
        QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 2500);
        QCOMPARE(finished.first().at(0).toULongLong(), generation);
        QCOMPARE(finished.first().at(1).toBool(), success);
        QTest::qWait(35); QCOMPARE(finished.count(), 1); QCOMPARE(server.connections, 1);
        if (success) {
            // This Qt/OpenSSL backend can emit RemoteHostClosedError twice for
            // the same close_notify. There must still be exactly one proof.
            QVERIFY(connectedIdentity); QVERIFY(encryptedIdentity); QVERIFY(!earlyRead);
            QCOMPARE(server.clientPort, boundPort); QCOMPARE(server.clientAddress, request.localAddress);
            QVERIFY(socketWarnings.isEmpty());
            QVERIFY(remoteErrors >= 1); QCOMPARE(disconnected, 1); QCOMPARE(server.requests.size(), 1);
            QCOMPARE(closeEvents.last(), QString("disconnected"));
            const auto proof = qvariant_cast<MayakTunnelProbeProof>(finished.first().at(2));
            QVERIFY(proof.certificateVerified); QCOMPARE(proof.nonce, request.nonce); QCOMPARE(proof.attemptTag, request.attemptTag);
            QCOMPARE(proof.observedEgressIpv4, QString("203.0.113.9")); QCOMPARE(proof.localAddress, QString("127.0.0.1"));
            QCOMPARE(proof.interfaceName, request.interfaceName);
            const QByteArray get = "GET /get?mayak_nonce=" + QUrl::toPercentEncoding(request.nonce) + " HTTP/1.1\r\n";
            const QByteArray expected = get + "Host: localhost\r\nUser-Agent: MayakVPN/5.1\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n";
            QCOMPARE(server.requests.first(), expected);
            const QString logs = probeMessages.join('\n');
            QVERIFY(logs.contains("socket_error=1")); QVERIFY(logs.contains("event=finish_ok"));
            QVERIFY(!logs.contains("endpoint=2"));
            if (scenario == "valid-unread-at-close") QVERIFY(!logs.contains("event=first_ready_read"));
        }
        if (scenario == "transport-error" || scenario == "fatal-alert" || scenario == "certificate-error-after-body") QVERIFY(injected);
    }
    void boundSocketStaysQuietBeforeDnsAndKeepsIdentity() {
        Capture capture; TrustScope trust;
        LocalEcho server("valid-length"); QVERIFY(server.listen(QHostAddress::LocalHost));
        MayakTunnelProbe probe; QSignalSpy finished(&probe, &MayakTunnelProbe::finished);
        auto request = requestFor(server); request.testConnectDelayMs = 150;
        probe.start(request);
        auto *socket = probe.findChild<QSslSocket *>(); QVERIFY(socket);
        const auto fd = socket->socketDescriptor(); const auto port = socket->localPort();
        QCOMPARE(socket->state(), QAbstractSocket::BoundState);
        int earlyReads = 0;
        connect(socket, &QSslSocket::readyRead, &probe, [&] { if (!socket->isEncrypted()) ++earlyReads; });
        QTest::qWait(75);
        QCOMPARE(socket->state(), QAbstractSocket::BoundState); QCOMPARE(socket->socketDescriptor(), fd);
        QCOMPARE(socket->localPort(), port); QCOMPARE(earlyReads, 0); QCOMPARE(server.connections, 0);
        QVERIFY(socketWarnings.isEmpty());
        QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 2000);
        QVERIFY(finished.first().at(1).toBool()); QCOMPARE(earlyReads, 0);
        QCOMPARE(server.clientPort, port); QCOMPARE(server.clientAddress, request.localAddress);
        QVERIFY(socketWarnings.isEmpty());
    }
    void cancelledBoundSocketNeverStartsDnsOrConnect() {
        LocalEcho server("valid-length"); QVERIFY(server.listen(QHostAddress::LocalHost));
        MayakTunnelProbe probe; QSignalSpy finished(&probe, &MayakTunnelProbe::finished);
        auto request = requestFor(server); request.testConnectDelayMs = 100;
        probe.start(request); probe.cancel();
        QTest::qWait(160); QCOMPARE(finished.count(), 0); QCOMPARE(server.connections, 0);
    }
    void replacedBoundSocketCannotConnect() {
        LocalEcho server("valid-length"); QVERIFY(server.listen(QHostAddress::LocalHost));
        MayakTunnelProbe probe; QSignalSpy finished(&probe, &MayakTunnelProbe::finished);
        auto request = requestFor(server); request.testConnectDelayMs = 100;
        probe.start(request);
        auto *socket = probe.findChild<QSslSocket *>(); QVERIFY(socket);
        const auto originalPort = socket->localPort();
        socket->abort();
        // Reserve the original source port so descriptor-number reuse cannot
        // disguise a replacement engine with a different source identity.
        QTcpServer reserve; QVERIFY(reserve.listen(QHostAddress::LocalHost, originalPort));
        QVERIFY(socket->bind(QHostAddress::LocalHost, 0)); QVERIFY(socket->localPort() != originalPort);
        QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 1000);
        QVERIFY(!finished.first().at(1).toBool()); QCOMPARE(server.connections, 0);
        QCOMPARE(finished.first().at(3).toString(), QString("bound socket identity changed"));
    }
    void bindingFailureNeverConnects_data() {
        QTest::addColumn<bool>("wrongInterface");
        QTest::newRow("missing-interface") << true;
        QTest::newRow("source-not-on-interface") << false;
    }
    void bindingFailureNeverConnects() {
        QFETCH(bool, wrongInterface);
        LocalEcho server("valid-length"); QVERIFY(server.listen(QHostAddress::LocalHost));
        MayakTunnelProbe probe; QSignalSpy finished(&probe, &MayakTunnelProbe::finished);
        auto request = requestFor(server);
        if (wrongInterface) request.interfaceName = "MAYAK_MISSING_INTERFACE";
        else request.localAddress = QHostAddress("192.0.2.231");
        probe.start(request);
        QCOMPARE(finished.count(), 1); QVERIFY(!finished.first().at(1).toBool());
        QTest::qWait(50); QCOMPARE(server.connections, 0); QVERIFY(server.requests.isEmpty());
    }
#ifdef Q_OS_WIN
    void changedInterfaceOptionCannotSendGet_data() {
        QTest::addColumn<bool>("beforeTcp");
        QTest::newRow("before-connect") << true;
        QTest::newRow("before-GET") << false;
    }
    void changedInterfaceOptionCannotSendGet() {
        QFETCH(bool, beforeTcp);
        TrustScope trust;
        LocalEcho server("valid-length"); QVERIFY(server.listen(QHostAddress::LocalHost));
        MayakTunnelProbe probe; QSignalSpy finished(&probe, &MayakTunnelProbe::finished);
        auto request = requestFor(server); request.testConnectDelayMs = beforeTcp ? 75 : 0;
        probe.start(request);
        auto *socket = probe.findChild<QSslSocket *>(); QVERIFY(socket);
        DWORD index = 0; int size = sizeof(index);
        QCOMPARE(::getsockopt(SOCKET(socket->socketDescriptor()), IPPROTO_IP, IP_UNICAST_IF, reinterpret_cast<char *>(&index), &size), 0);
        QCOMPARE(index, DWORD(QNetworkInterface::interfaceFromName(request.interfaceName).index()));
        bool changed = false;
        auto clearInterface = [&] {
            DWORD unbound = 0;
            changed = ::setsockopt(SOCKET(socket->socketDescriptor()), IPPROTO_IP, IP_UNICAST_IF, reinterpret_cast<const char *>(&unbound), sizeof(unbound)) == 0;
        };
        if (beforeTcp) clearInterface();
        else connect(socket, &QSslSocket::connected, &probe, clearInterface);
        QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 2000);
        QVERIFY(changed); QVERIFY(!finished.first().at(1).toBool()); QVERIFY(server.requests.isEmpty());
        QCOMPARE(finished.first().at(3).toString(), QString("bound socket identity changed"));
    }
#endif
    void cancellationAndReplacementIsolateLateClose() {
        TrustScope trust;
        LocalEcho oldServer("delayed"); QVERIFY(oldServer.listen(QHostAddress::LocalHost));
        LocalEcho newServer("valid-length"); QVERIFY(newServer.listen(QHostAddress::LocalHost));
        MayakTunnelProbe probe; QSignalSpy finished(&probe, &MayakTunnelProbe::finished);
        const auto oldGeneration = probe.start(requestFor(oldServer));
        QTRY_COMPARE_WITH_TIMEOUT(oldServer.requests.size(), 1, 1000);
        probe.cancel();
        auto replacement = requestFor(newServer); replacement.nonce = "replacement nonce";
        const auto newGeneration = probe.start(replacement); QVERIFY(newGeneration > oldGeneration);
        QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 2000);
        QVERIFY(finished.first().at(1).toBool()); QCOMPARE(finished.first().at(0).toULongLong(), newGeneration);
        QCOMPARE(qvariant_cast<MayakTunnelProbeProof>(finished.first().at(2)).nonce, replacement.nonce);
        QTest::qWait(250); QCOMPARE(finished.count(), 1);
    }
    void deadlineRejectsLateBytes() {
        TrustScope trust;
        LocalEcho server("delayed"); QVERIFY(server.listen(QHostAddress::LocalHost));
        MayakTunnelProbe probe; QSignalSpy finished(&probe, &MayakTunnelProbe::finished);
        probe.start(requestFor(server, 80));
        QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 1500);
        QVERIFY(!finished.first().at(1).toBool());
        QCOMPARE(finished.first().at(3).toString(), QString("probe deadline exceeded"));
        QTest::qWait(250); QCOMPARE(finished.count(), 1);
    }
    void queuedFailureCannotAffectReplacement() {
        TrustScope trust;
        LocalEcho oldServer("valid-length"); QVERIFY(oldServer.listen(QHostAddress::LocalHost));
        LocalEcho newServer("valid-fragmented"); QVERIFY(newServer.listen(QHostAddress::LocalHost));
        MayakTunnelProbe probe; QSignalSpy finished(&probe, &MayakTunnelProbe::finished);
        probe.start(requestFor(oldServer));
        auto *oldSocket = probe.findChild<QSslSocket *>(); QVERIFY(oldSocket);
        bool replaced = false; quint64 replacementGeneration = 0;
        connect(oldSocket, &QSslSocket::readyRead, &probe, [&, oldSocket] {
            if (replaced) return;
            replaced = true;
            // Queue user cancellation before the failure queues its retry. This
            // exercises the event-loop boundary without deleting a QSslSocket
            // reentrantly inside that socket's own TLS readyRead implementation.
            QTimer::singleShot(0, &probe, [&] {
                probe.cancel();
                auto replacement = requestFor(newServer); replacement.nonce = "fresh-after-error";
                replacementGeneration = probe.start(replacement);
            });
            oldSocket->errorOccurred(QAbstractSocket::NetworkError);
        });
        QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 2000);
        QVERIFY(replaced); QVERIFY(finished.first().at(1).toBool());
        QCOMPARE(finished.first().at(0).toULongLong(), replacementGeneration);
        QCOMPARE(qvariant_cast<MayakTunnelProbeProof>(finished.first().at(2)).nonce, QString("fresh-after-error"));
        QTest::qWait(100); QCOMPARE(finished.count(), 1);
    }
    void publicFinishedCanCancel() {
        TrustScope trust;
        LocalEcho server("valid-fragmented"); QVERIFY(server.listen(QHostAddress::LocalHost));
        MayakTunnelProbe probe; QSignalSpy finished(&probe, &MayakTunnelProbe::finished);
        int callbacks = 0;
        connect(&probe, &MayakTunnelProbe::finished, &probe, [&](quint64, bool ok, const MayakTunnelProbeProof &, const QString &) {
            ++callbacks;
            QVERIFY(ok);
            probe.cancel();
        });
        probe.start(requestFor(server));
        QTRY_COMPARE_WITH_TIMEOUT(callbacks, 1, 2000);
        QTest::qWait(100); QCOMPARE(finished.count(), 1);
    }
    void publicFinishedCanDeleteOwnerLater() {
        TrustScope trust;
        LocalEcho server("valid-fragmented"); QVERIFY(server.listen(QHostAddress::LocalHost));
        auto *owner = new QObject;
        auto *probe = new MayakTunnelProbe(owner);
        QPointer<QObject> ownerGuard(owner);
        int callbacks = 0;
        connect(probe, &MayakTunnelProbe::finished, this, [&](quint64, bool ok, const MayakTunnelProbeProof &, const QString &) {
            ++callbacks;
            QVERIFY(ok);
            owner->deleteLater();
        });
        probe->start(requestFor(server));
        QTRY_COMPARE_WITH_TIMEOUT(callbacks, 1, 2000);
        QTRY_VERIFY(ownerGuard.isNull());
        QTest::qWait(100); QCOMPARE(callbacks, 1);
    }
};
QTEST_GUILESS_MAIN(LocalTlsProbeTests)
#include "localTlsProbeTests.moc"
