#include "mayakTunnelProbe.h"
#include "mayakTunnelInterfaceResolver.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QHostAddress>
#include <QHostInfo>
#include <QNetworkProxy>
#include <QSslSocket>
#include <QTimer>
#include <QElapsedTimer>
#include <QDebug>
#include <QRegularExpression>
#include <QUrl>
#include <QUrlQuery>
#include <QNetworkInterface>
#include <QSharedPointer>
#include <QSet>
#include <QStringDecoder>
#include <functional>
#include <algorithm>
#ifdef Q_OS_ANDROID
#  include <QCoreApplication>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#endif

#ifdef Q_OS_WIN
#  define NOMINMAX
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <mstcpip.h>
#endif
#ifdef Q_OS_ANDROID
#  include <QJniObject>
#endif

namespace {
constexpr qsizetype MaxResponse = 64 * 1024;
const QStringList Hosts{QStringLiteral("httpbingo.org"), QStringLiteral("httpbin.org")};

bool validIpv4(const QString &text) {
    QHostAddress ip;
    return ip.setAddress(text) && ip.protocol() == QAbstractSocket::IPv4Protocol && ip.toString() == text;
}

class JsonObjectKeyScanner {
public:
    explicit JsonObjectKeyScanner(const QByteArray &source) : m_source(source) {}
    bool hasUniqueKeys() {
        if (m_source.size() > MaxResponse) return false;
        skipSpace();
        const bool valid = scanValue(0);
        skipSpace();
        return valid && m_pos == m_source.size();
    }
private:
    // Bound recursion before entering a container, independently of Qt's parser.
    static constexpr unsigned MaxDepth = 64;
    void skipSpace() {
        while (m_pos < m_source.size() && (m_source.at(m_pos) == ' ' || m_source.at(m_pos) == '\t' ||
               m_source.at(m_pos) == '\r' || m_source.at(m_pos) == '\n')) ++m_pos;
    }
    bool scanString(QByteArray *token) {
        if (m_pos >= m_source.size() || m_source.at(m_pos) != '"') return false;
        const qsizetype start = m_pos++;
        while (m_pos < m_source.size()) {
            const char c = m_source.at(m_pos++);
            if (c == '"') {
                const QByteArray encoded = m_source.mid(start, m_pos - start);
                QStringDecoder utf8(QStringDecoder::Utf8);
                const QString decoded = utf8.decode(encoded);
                if (utf8.hasError()) return false;
                if (token) *token = encoded;
                return true;
            }
            if (static_cast<unsigned char>(c) < 0x20) return false;
            if (c == '\\') {
                if (m_pos >= m_source.size()) return false;
                const char escape = m_source.at(m_pos++);
                if (escape == 'u') {
                    unsigned code;
                    if (!scanHexCodeUnit(&code)) return false;
                    if (code >= 0xd800 && code <= 0xdbff) {
                        if (m_source.mid(m_pos, 2) != "\\u") return false;
                        m_pos += 2;
                        if (!scanHexCodeUnit(&code) || code < 0xdc00 || code > 0xdfff) return false;
                    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
                } else if (escape != '"' && escape != '\\' && escape != '/' && escape != 'b' &&
                           escape != 'f' && escape != 'n' && escape != 'r' && escape != 't') return false;
            }
        }
        return false;
    }
    bool scanHexCodeUnit(unsigned *code) {
        if (m_source.size() - m_pos < 4) return false;
        *code = 0;
        for (unsigned i = 0; i < 4; ++i) {
            const char c = m_source.at(m_pos++);
            unsigned digit;
            if (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            else return false;
            *code = *code * 16 + digit;
        }
        return true;
    }
    bool scanValue(unsigned depth) {
        skipSpace();
        if (m_pos >= m_source.size()) return false;
        if (m_source.at(m_pos) == '{' || m_source.at(m_pos) == '[') {
            if (depth >= MaxDepth) return false;
            return m_source.at(m_pos) == '{' ? scanObject(depth + 1) : scanArray(depth + 1);
        }
        if (m_source.at(m_pos) == '"') return scanString(nullptr);
        const qsizetype start = m_pos;
        while (m_pos < m_source.size()) {
            const char c = m_source.at(m_pos);
            if (c == ',' || c == ']' || c == '}' || c == ' ' || c == '\t' || c == '\r' || c == '\n') break;
            ++m_pos;
        }
        return m_pos > start;
    }
    bool scanArray(unsigned depth) {
        ++m_pos;
        skipSpace();
        if (m_pos < m_source.size() && m_source.at(m_pos) == ']') { ++m_pos; return true; }
        for (;;) {
            if (!scanValue(depth)) return false;
            skipSpace();
            if (m_pos >= m_source.size()) return false;
            if (m_source.at(m_pos) == ']') { ++m_pos; return true; }
            if (m_source.at(m_pos++) != ',') return false;
        }
    }
    bool scanObject(unsigned depth) {
        ++m_pos;
        QSet<QString> keys;
        skipSpace();
        if (m_pos < m_source.size() && m_source.at(m_pos) == '}') { ++m_pos; return true; }
        for (;;) {
            QByteArray token;
            if (!scanString(&token)) return false;
            const auto decoded = QJsonDocument::fromJson("[" + token + "]");
            if (!decoded.isArray() || decoded.array().size() != 1) return false;
            const QString key = decoded.array().first().toString();
            if (keys.contains(key)) return false;
            keys.insert(key);
            skipSpace();
            if (m_pos >= m_source.size() || m_source.at(m_pos++) != ':') return false;
            if (!scanValue(depth)) return false;
            skipSpace();
            if (m_pos >= m_source.size()) return false;
            if (m_source.at(m_pos) == '}') { ++m_pos; return true; }
            if (m_source.at(m_pos++) != ',') return false;
            skipSpace();
        }
    }
    const QByteArray &m_source;
    qsizetype m_pos = 0;
};

bool responseNonceMatches(const QByteArray &body, const QString &nonce, QString *returned) {
    if (!JsonObjectKeyScanner(body).hasUniqueKeys()) return false;
    QJsonParseError parseError{};
    const auto doc = QJsonDocument::fromJson(body, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) return false;
    const auto args = doc.object().value("args");
    const auto value = args.isObject() ? args.toObject().value("mayak_nonce") : QJsonValue();
    QString result;
    if (value.isString()) result = value.toString();
    else if (value.isArray() && value.toArray().size() == 1 && value.toArray().first().isString())
        result = value.toArray().first().toString();
    if (returned) *returned = result;
    return result == nonce;
}

bool responseEgressMatches(const QByteArray &body, const QStringList &expected, QString *observed) {
    if (!JsonObjectKeyScanner(body).hasUniqueKeys()) return false;
    QJsonParseError parseError{};
    const auto doc = QJsonDocument::fromJson(body, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) return false;
    const QString origin = doc.object().value("origin").toString();
    const QString first = origin.section(',', 0, 0).trimmed();
    if (!validIpv4(first) || !expected.contains(first)) return false;
    if (observed) *observed = first;
    return true;
}

bool parseHttp(const QByteArray &wire, QByteArray *body, QString *error) {
    if (wire.size() > MaxResponse) { *error = "response exceeds 64 KiB"; return false; }
    const qsizetype split = wire.indexOf("\r\n\r\n");
    if (split < 0 || split > 8192) { *error = "malformed or oversized HTTP headers"; return false; }
    const QByteArray head = wire.left(split);
    const QList<QByteArray> lines = head.split('\n');
    if (lines.isEmpty()) { *error = "missing HTTP status"; return false; }
    const auto statusParts = lines.first().trimmed().split(' ');
    if (statusParts.size() < 2 || statusParts.at(0) != "HTTP/1.1" || statusParts.at(1) != "200") { *error = "HTTP status is not 200"; return false; }
    bool haveLength = false;
    qsizetype length = -1;
    bool transferEncoding = false;
    for (qsizetype i = 1; i < lines.size(); ++i) {
        QByteArray line = lines.at(i);
        if (line.endsWith('\r')) line.chop(1);
        const qsizetype colon = line.indexOf(':');
        if (colon <= 0) { *error = "malformed HTTP header"; return false; }
        const QByteArray name = line.left(colon).trimmed().toLower();
        qsizetype valueStart = colon + 1, valueEnd = line.size();
        while (valueStart < valueEnd && (line.at(valueStart) == ' ' || line.at(valueStart) == '\t')) ++valueStart;
        while (valueEnd > valueStart && (line.at(valueEnd - 1) == ' ' || line.at(valueEnd - 1) == '\t')) --valueEnd;
        const QByteArray value = line.mid(valueStart, valueEnd - valueStart);
        if (name == "content-length") {
            if (value.isEmpty() || haveLength) { *error = "invalid Content-Length"; return false; }
            qsizetype n = 0;
            for (const char c : value) {
                if (c < '0' || c > '9' || n > (MaxResponse - (c - '0')) / 10) {
                    *error = "invalid Content-Length"; return false;
                }
                n = n * 10 + (c - '0');
            }
            haveLength = true; length = n;
        } else if (name == "transfer-encoding") {
            if (value.toLower() != "chunked" || transferEncoding) { *error = "unsupported transfer encoding"; return false; }
            transferEncoding = true;
        }
    }
    if (haveLength && transferEncoding) { *error = "ambiguous HTTP framing"; return false; }
    const QByteArray payload = wire.mid(split + 4);
    if (!haveLength && !transferEncoding) { *body = payload; return true; } // caller invokes only after close
    if (haveLength) {
        if (payload.size() != length) { *error = "incomplete or trailing HTTP body"; return false; }
        *body = payload; return true;
    }
    QByteArray decoded;
    qsizetype pos = 0;
    for (;;) {
        const qsizetype eol = payload.indexOf("\r\n", pos);
        if (eol < 0) { *error = "malformed chunk size"; return false; }
        const QByteArray sizeText = payload.mid(pos, eol - pos);
        if (sizeText.isEmpty() || sizeText.contains(';')) { *error = "invalid chunk extension"; return false; }
        for (const char c : sizeText) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                *error = "invalid chunk size"; return false;
            }
        }
        bool ok = false; const qulonglong size = sizeText.toULongLong(&ok, 16);
        if (!ok || size > qulonglong(MaxResponse) || decoded.size() + qsizetype(size) > MaxResponse) { *error = "invalid or oversized chunk"; return false; }
        pos = eol + 2;
        if (!size) {
            if (payload.mid(pos) != "\r\n") { *error = "invalid chunk trailer"; return false; }
            *body = decoded; return true;
        }
        if (size > qulonglong(payload.size() - pos) || payload.mid(pos + qsizetype(size), 2) != "\r\n") { *error = "truncated chunk"; return false; }
        decoded += payload.mid(pos, qsizetype(size)); pos += qsizetype(size) + 2;
    }
}
}

namespace mayak::diagnostics {
QStringList openSslErrorCodeTokens(const QString &errorString) {
    static const QRegularExpression tokenPattern(QStringLiteral("(?:^|[^A-Za-z0-9])error:([0-9A-Fa-f]{8,16}):"));
    QStringList codes;
    auto matches = tokenPattern.globalMatch(errorString);
    while (matches.hasNext() && codes.size() < 8) codes.append(matches.next().captured(1).toUpper());
    return codes;
}
}

MayakTunnelProbe::MayakTunnelProbe(QObject *parent) : QObject(parent) {}

bool MayakTunnelProbe::parseHttpResponse(const QByteArray &wire, QByteArray *body, QString *error) {
    return parseHttp(wire, body, error);
}

class ProbeRun final : public QObject {
public:
    ProbeRun(MayakTunnelProbe *owner, quint64 generation, MayakTunnelProbeRequest request)
        : QObject(owner), m_owner(owner), m_generation(generation), m_request(std::move(request)),
          m_deadline(new QTimer(this)), m_bindRetry(new QTimer(this)) {
        m_elapsed.start();
        m_deadline->setSingleShot(true);
        connect(m_deadline, &QTimer::timeout, this, [this] { finish(false, {}, "probe deadline exceeded"); });
        m_bindRetry->setSingleShot(true);
        connect(m_bindRetry, &QTimer::timeout, this, [this] {
            if (m_finished || !m_sourceBindWaiting) return;
            m_sourceBindWaiting = false;
            if (m_elapsed.elapsed() >= m_request.deadlineMs) {
                finish(false, {}, "probe deadline exceeded");
                return;
            }
            if (!interfaceIdentityMatches()) {
                finish(false, {}, "AWG interface identity changed during source bind wait");
                return;
            }
            openNextEndpoint(true);
        });
    }

    void start() {
        if (!m_request.attemptTag.isEmpty() && !m_request.nonce.isEmpty() && m_request.nonce.size() <= 128 &&
            !m_request.interfaceName.isEmpty() && !m_request.expectedEgressIpv4.isEmpty() &&
            m_request.deadlineMs >= 1 && m_request.deadlineMs <= 8000 &&
            m_request.localAddress.protocol() == QAbstractSocket::IPv4Protocol) {
            for (const auto &ip : m_request.expectedEgressIpv4)
                if (!validIpv4(ip)) { finish(false, {}, "invalid expected egress IPv4"); return; }
        } else {
            finish(false, {}, "invalid probe request"); return;
        }
        m_elapsed.restart();
        logStage(QStringLiteral("start"));
        m_deadline->start(m_request.deadlineMs);
        openNextEndpoint();
    }

private:
    void finish(bool ok, MayakTunnelProbeProof proof, const QString &error) {
        if (m_finished) return;
        logStage(ok ? QStringLiteral("finish_ok") : QStringLiteral("finish_error"),
                 QStringLiteral("http_parse_ok=%1 nonce_ok=%2 egress_ok=%3")
                     .arg(m_parseOk).arg(m_nonceOk).arg(m_egressOk));
        m_finished = true;
        m_deadline->stop();
        m_bindRetry->stop();
        m_sourceBindWaiting = false;
        if (m_socket) m_socket->abort();
        QPointer<ProbeRun> alive(this);
        if (m_owner) emit m_owner->finished(m_generation, ok, proof, error);
        if (alive) alive->deleteLater();
    }

    void logStage(const QString &event, const QString &extra = {}) const {
        const qint64 elapsed = m_elapsed.isValid() ? m_elapsed.elapsed() : 0;
        const qint64 remaining = qMax<qint64>(0, qint64(m_request.deadlineMs) - elapsed);
        const int state = m_socket ? int(m_socket->state()) : m_lastSocketState;
        const int socketError = m_socket ? int(m_socket->error()) : m_lastSocketError;
        const int mode = m_socket ? int(m_socket->mode()) : m_lastMode;
        const qint64 encryptedQueue = m_socket ? m_socket->encryptedBytesToWrite() : 0;
        qInfo().noquote() << QStringLiteral("MayakTunnelProbe event=%1 endpoint=%2 elapsed_ms=%3 remaining_ms=%4 socket_state=%5 socket_error=%6 ssl_mode=%7 encrypted_bytes_written=%8 encrypted_bytes_to_write=%9 peer_verify_error=%10 alert_sent_level=%11 alert_sent_type=%12 alert_received_level=%13 alert_received_type=%14 platform_bind_ok=%15 requested_local_binding_match=%16 fd_valid=%17 tls_error_count=%18 wire_bytes=%19 %20")
              .arg(event).arg(m_endpointIndex).arg(elapsed).arg(remaining).arg(state).arg(socketError)
              .arg(mode).arg(m_encryptedBytesWritten).arg(encryptedQueue).arg(m_peerVerifyError)
              .arg(m_alertSentLevel).arg(m_alertSentType).arg(m_alertReceivedLevel).arg(m_alertReceivedType)
              .arg(m_binderOk).arg(m_localMatch).arg(m_fdValid).arg(m_tlsErrorCount).arg(m_wire.size()).arg(extra);
    }

    void failAttempt(int attempt, const QString &reason) {
        if (m_finished || attempt != m_attempt) return;
        if (m_hostIndex < hostCount()) openNextEndpoint();
        else finish(false, {}, reason.isEmpty() ? QStringLiteral("all HTTPS echo endpoints failed") : reason);
    }

    void scheduleRetry(int attempt, const QString &reason) {
        if (m_finished || attempt != m_attempt || m_attemptRejected) return;
        // A failed TLS/transport attempt must not become a proof if its
        // disconnected signal arrives before this queued retry is delivered.
        m_attemptRejected = true;
        // The queued retry is owned by this run. Destroying/cancelling the run
        // removes the callback together with its timer and socket.
        QTimer::singleShot(0, this, [this, attempt, reason] { failAttempt(attempt, reason); });
    }

    void openNextEndpoint(bool retrySourceBind = false) {
        if (m_finished) return;
        ++m_attempt; // Invalidate events from the socket being abandoned before aborting it.
        const int attempt = m_attempt;
        if (m_socket) {
            auto *old = m_socket.data();
            m_socket.clear();
            old->disconnect(this);
            old->abort();
            old->deleteLater();
        }
        if (!retrySourceBind && hostCount() <= m_hostIndex) { finish(false, {}, "all HTTPS echo endpoints failed"); return; }
        const QString host = retrySourceBind ? m_currentHost : hostAt(m_hostIndex++);
        if (!retrySourceBind) m_currentHost = host;
        m_endpointIndex = m_hostIndex;
        m_wire.clear();
        m_tlsErrorCount = 0;
        m_peerVerifyError = -1;
        m_alertSentLevel = m_alertSentType = -1;
        m_alertReceivedLevel = m_alertReceivedType = -1;
        m_encryptedBytesWritten = 0;
        m_lastMode = int(QSslSocket::UnencryptedMode);
        m_firstReadLogged = false;
        m_tlsEstablished = false;
        m_attemptRejected = false;
        m_responseCompleted = false;
        m_socket = new QSslSocket(this);
        m_socket->setProxy(QNetworkProxy::NoProxy);
        m_socket->setPeerVerifyMode(QSslSocket::VerifyPeer);
        auto *socket = m_socket.data();
        connect(socket, &QSslSocket::hostFound, this, [this, attempt] {
            if (!m_finished && attempt == m_attempt) logStage(QStringLiteral("host_found"));
        });
        connect(socket, &QSslSocket::connected, this, [this, attempt] {
            if (m_finished || attempt != m_attempt || m_attemptRejected) return;
            if (!boundIdentityMatches()) {
                scheduleRetry(attempt, "bound socket identity changed"); return;
            }
            logStage(QStringLiteral("tcp_connected"));
        });
        connect(socket, &QSslSocket::encrypted, this, [this, attempt, host] {
            if (m_finished || attempt != m_attempt || m_attemptRejected || !m_socket || !m_socket->isEncrypted()) return;
            if (!boundIdentityMatches()) {
                scheduleRetry(attempt, "bound socket identity changed"); return;
            }
            m_tlsEstablished = true;
            logStage(QStringLiteral("tls_encrypted"));
            const QByteArray path = QByteArray("/get?mayak_nonce=") + QUrl::toPercentEncoding(m_request.nonce);
            m_socket->write("GET " + path + " HTTP/1.1\r\nHost: " + host.toUtf8() +
                            "\r\nUser-Agent: MayakVPN/5.1\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n");
        });
        connect(socket, &QSslSocket::readyRead, this, [this, attempt] {
            if (m_finished || attempt != m_attempt || !m_socket) return;
            m_wire += m_socket->readAll();
            if (!m_firstReadLogged) {
                m_firstReadLogged = true;
                logStage(QStringLiteral("first_ready_read"));
            }
            if (m_wire.size() > MaxResponse) failAttempt(attempt, "response exceeds 64 KiB");
        });
        connect(socket, &QSslSocket::disconnected, this, [this, attempt] {
            if (m_finished || attempt != m_attempt || m_attemptRejected || m_responseCompleted) return;
            m_responseCompleted = true;
            logStage(QStringLiteral("disconnected"));
            // QSslSocket can report RemoteHostClosedError before disconnected.
            // Drain remaining plaintext only after TLS has finished processing
            // the close, then validate the complete response exactly once.
            if (m_socket) m_wire += m_socket->readAll();
            if (!m_tlsEstablished || m_tlsErrorCount != 0 || m_peerVerifyError != -1) {
                failAttempt(attempt, "TLS session was not verified"); return;
            }
            QByteArray body; QString error; QString egress;
            m_parseOk = parseHttp(m_wire, &body, &error);
            m_nonceOk = false;
            m_egressOk = false;
            if (m_parseOk) {
                m_nonceOk = responseNonceMatches(body, m_request.nonce, nullptr);
                m_egressOk = responseEgressMatches(body, m_request.expectedEgressIpv4, &egress);
                if (!MayakTunnelProbe::validateResponse(body, m_request.nonce, m_request.expectedEgressIpv4, &egress, &error)) {
                    failAttempt(attempt, error); return;
                }
            } else {
                failAttempt(attempt, error); return;
            }
            MayakTunnelProbeProof proof;
            proof.attemptTag = m_request.attemptTag; proof.nonce = m_request.nonce;
            proof.observedEgressIpv4 = egress; proof.interfaceName = m_request.interfaceName;
            proof.localAddress = m_request.localAddress.toString(); proof.certificateVerified = true;
            finish(true, proof, {});
        });
        connect(socket, &QSslSocket::sslErrors, this, [this, attempt](const QList<QSslError> &errors) {
            if (m_finished || attempt != m_attempt) return;
            m_tlsErrorCount = errors.size();
            QStringList codes;
            codes.reserve(errors.size());
            for (const auto &error : errors) codes.append(QString::number(int(error.error())));
            logStage(QStringLiteral("tls_errors"), QStringLiteral("tls_error_codes=%1").arg(codes.join(QLatin1Char(','))));
            scheduleRetry(attempt, "TLS certificate verification failed");
        });
        connect(socket, &QSslSocket::errorOccurred, this, [this, attempt](QAbstractSocket::SocketError error) {
            if (m_finished || attempt != m_attempt) return;
            // QSslSocket may emit synchronously from bind(). That error belongs
            // to the source-bind decision below, never to endpoint failover.
            if (m_sourceBindInProgress || m_sourceBindWaiting) return;
            m_lastSocketError = int(error);
            const QString socketError = m_socket ? m_socket->errorString() : QStringLiteral("socket failed");
            const auto opensslCodes = mayak::diagnostics::openSslErrorCodeTokens(socketError);
            const QString tokenField = opensslCodes.isEmpty() ? QString() :
                QStringLiteral("openssl_error_codes=%1").arg(opensslCodes.join(QLatin1Char(',')));
            logStage(QStringLiteral("socket_error"), tokenField);
            // Peer EOF is the expected HTTP Connection: close completion.
            // Retrying here can discard a valid response before disconnected
            // drains the final TLS bytes. Other errors remain fail-closed.
            if (error == QAbstractSocket::RemoteHostClosedError && m_tlsEstablished) return;
            scheduleRetry(attempt, socketError);
        });
        connect(socket, &QSslSocket::stateChanged, this, [this, attempt](QAbstractSocket::SocketState state) {
            if (!m_finished && attempt == m_attempt) {
                m_lastSocketState = int(state);
                logStage(QStringLiteral("state_changed"));
            }
        });
        connect(socket, &QSslSocket::modeChanged, this, [this, attempt](QSslSocket::SslMode mode) {
            if (m_finished || attempt != m_attempt) return;
            m_lastMode = int(mode);
            logStage(QStringLiteral("ssl_mode_changed"));
        });
        connect(socket, &QSslSocket::encryptedBytesWritten, this, [this, attempt](qint64 bytes) {
            if (m_finished || attempt != m_attempt) return;
            m_encryptedBytesWritten += bytes;
        });
        connect(socket, &QSslSocket::peerVerifyError, this, [this, attempt](const QSslError &error) {
            if (m_finished || attempt != m_attempt) return;
            m_peerVerifyError = int(error.error());
            logStage(QStringLiteral("peer_verify_error"));
        });
        connect(socket, &QSslSocket::alertSent, this,
                [this, attempt](QSsl::AlertLevel level, QSsl::AlertType type, const QString &) {
            if (m_finished || attempt != m_attempt) return;
            m_alertSentLevel = int(level); m_alertSentType = int(type);
            logStage(QStringLiteral("tls_alert_sent"));
            if (level == QSsl::AlertLevel::Fatal) scheduleRetry(attempt, "fatal TLS alert");
        });
        connect(socket, &QSslSocket::alertReceived, this,
                [this, attempt](QSsl::AlertLevel level, QSsl::AlertType type, const QString &) {
            if (m_finished || attempt != m_attempt) return;
            m_alertReceivedLevel = int(level); m_alertReceivedType = int(type);
            logStage(QStringLiteral("tls_alert_received"));
            if (level == QSsl::AlertLevel::Fatal) scheduleRetry(attempt, "fatal TLS alert");
        });
        // Let Qt create and own the TCP engine. Unlike descriptor adoption,
        // TCP bind does not enable a read notifier before DNS/connect begins.
        // Failure is terminal; there is no unbound/global-network fallback.
        m_binderOk = m_localMatch = m_fdValid = false;
        m_boundFd = -1;
        m_boundPort = 0;
#ifdef Q_OS_WIN
        mayak::tunnel::InterfaceIdentity resolvedIdentity;
        if (!mayak::tunnel::resolveInterface(
                mayak::tunnel::interfaceCandidates(QNetworkInterface::allInterfaces()),
                m_request.interfaceName, m_request.localAddress, &resolvedIdentity)) {
            finish(false, {}, "AWG interface identity is missing, ambiguous, or does not own the source address"); return;
        }
        if (retrySourceBind) {
            if (resolvedIdentity != m_boundInterfaceIdentity) {
                finish(false, {}, "AWG interface identity changed during source bind wait"); return;
            }
        } else {
            m_boundInterfaceIdentity = resolvedIdentity;
        }
        m_boundInterfaceIndex = m_boundInterfaceIdentity.index;
#else
        const auto iface = QNetworkInterface::interfaceFromName(m_request.interfaceName);
        m_boundInterfaceIndex = iface.index();
#endif
        if (!interfaceIdentityMatches()) {
            finish(false, {}, "AWG interface identity changed before source bind"); return;
        }
        m_sourceBindInProgress = true;
#ifdef MAYAK_TUNNEL_PROBE_TESTING
        const bool injectedBindFailure = m_testSourceBindFailures > 0;
        if (injectedBindFailure) --m_testSourceBindFailures;
        if (injectedBindFailure)
            emit m_socket->errorOccurred(QAbstractSocket::SocketError(m_request.testSourceBindError));
        const bool sourceBound = !injectedBindFailure && m_socket->bind(m_request.localAddress, 0);
        const int bindError = injectedBindFailure ? m_request.testSourceBindError : int(m_socket->error());
#else
        const bool sourceBound = m_socket->bind(m_request.localAddress, 0);
        const int bindError = int(m_socket->error());
#endif
        m_sourceBindInProgress = false;
        if (!sourceBound) {
#ifdef Q_OS_WIN
            if (bindError == int(QAbstractSocket::SocketAddressNotAvailableError)) {
                m_sourceBindWaiting = true;
#ifdef MAYAK_TUNNEL_PROBE_TESTING
                m_testIdentityDriftDuringBindWait = m_request.testIdentityDriftDuringBindWait;
#endif
                logStage(QStringLiteral("source_bind_wait"), QStringLiteral("socket_error=%1").arg(bindError));
                const qint64 remaining = qint64(m_request.deadlineMs) - m_elapsed.elapsed();
                if (remaining <= 0) { finish(false, {}, "probe deadline exceeded"); return; }
                int delay = 50;
#ifdef MAYAK_TUNNEL_PROBE_TESTING
                delay = qMax(1, m_request.testBindRetryIntervalMs);
#endif
                m_bindRetry->start(int(qMin<qint64>(delay, remaining)));
                return;
            }
#endif
            logStage(QStringLiteral("source_bind_failed"), QStringLiteral("socket_error=%1").arg(bindError));
            finish(false, {}, "AWG interface/address bind failed"); return;
        }
        m_sourceBindWaiting = false;
        m_boundFd = m_socket->socketDescriptor();
        m_boundPort = m_socket->localPort();
        if (!sourceIdentityMatches()) {
            finish(false, {}, "source address bind failed"); return;
        }
#ifdef Q_OS_WIN
        // IP_UNICAST_IF is set on the already-bound Qt-owned socket, before
        // connect. Windows sets this option in network order and gets it in
        // host order; source and option retention are checked independently.
        const DWORD index = htonl(DWORD(m_boundInterfaceIndex));
        if (::setsockopt(SOCKET(m_boundFd), IPPROTO_IP, IP_UNICAST_IF,
                         reinterpret_cast<const char *>(&index), sizeof(index)) != 0) {
            finish(false, {}, "strict Windows AWG socket binding failed"); return;
        }
        m_binderOk = true;
#elif defined(Q_OS_ANDROID)
        const auto context = QNativeInterface::QAndroidApplication::context();
        m_binderOk = QJniObject::callStaticMethod<jboolean>(
            "ru/mayaklight/vpn/MayakProbeSocketBinder", "bindSocket",
            "(Landroid/content/Context;ILjava/lang/String;Ljava/lang/String;)Z",
            context.object<jobject>(), jint(m_boundFd),
            QJniObject::fromString(m_request.localAddress.toString()).object<jstring>(),
            QJniObject::fromString(m_request.interfaceName).object<jstring>());
        if (!m_binderOk) {
            finish(false, {}, "strict Android VPN socket binding failed"); return;
        }
#else
        finish(false, {}, "strict interface binding unsupported on this platform"); return;
#endif
        if (!boundIdentityMatches()) {
            finish(false, {}, "bound socket identity changed"); return;
        }
        logStage(QStringLiteral("platform_bound"));
        logStage(QStringLiteral("connect_requested"));
#ifdef MAYAK_TUNNEL_PROBE_TESTING
        const quint16 port = m_request.testPort ? m_request.testPort : quint16(443);
        if (m_request.testConnectDelayMs > 0) {
            QTimer::singleShot(m_request.testConnectDelayMs, this, [this, attempt, host, port] {
                if (m_finished || attempt != m_attempt || m_attemptRejected) return;
                if (!boundIdentityMatches()) { scheduleRetry(attempt, "bound socket identity changed"); return; }
                m_socket->connectToHostEncrypted(host, port, QIODevice::ReadWrite, QAbstractSocket::IPv4Protocol);
            });
            return;
        }
#else
        constexpr quint16 port = 443;
#endif
        // Keep hostname verification/SNI and async DNS; the bound engine is
        // IPv4, so Qt must not replace it while selecting another protocol.
        m_socket->connectToHostEncrypted(host, port, QIODevice::ReadWrite, QAbstractSocket::IPv4Protocol);
    }

    bool interfaceIdentityMatches() const {
#ifdef MAYAK_TUNNEL_PROBE_TESTING
        if (m_testIdentityDriftDuringBindWait) return false;
#endif
#ifdef Q_OS_WIN
        mayak::tunnel::InterfaceIdentity current;
        return mayak::tunnel::resolveInterface(
                   mayak::tunnel::interfaceCandidates(QNetworkInterface::allInterfaces()),
                   m_request.interfaceName, m_request.localAddress, &current) &&
               current == m_boundInterfaceIdentity && current.index == m_boundInterfaceIndex;
#else
        const auto iface = QNetworkInterface::interfaceFromName(m_request.interfaceName);
        if (!iface.isValid() || m_boundInterfaceIndex <= 0 || iface.index() != m_boundInterfaceIndex) return false;
        for (const auto &entry : iface.addressEntries())
            if (entry.ip() == m_request.localAddress) return true;
        return false;
#endif
    }

    bool sourceIdentityMatches() {
        m_fdValid = m_socket && m_boundFd >= 0 && m_socket->socketDescriptor() == m_boundFd;
        m_localMatch = false;
#if defined(Q_OS_WIN) || defined(Q_OS_ANDROID)
        sockaddr_in local{};
#  ifdef Q_OS_WIN
        int size = sizeof(local);
        const bool valid = m_fdValid && ::getsockname(SOCKET(m_boundFd), reinterpret_cast<sockaddr *>(&local), &size) == 0;
#  else
        socklen_t size = sizeof(local);
        const bool valid = m_fdValid && ::getsockname(int(m_boundFd), reinterpret_cast<sockaddr *>(&local), &size) == 0;
#  endif
        m_fdValid = valid && size == sizeof(local) && local.sin_family == AF_INET;
        m_localMatch = m_fdValid && m_boundPort != 0 && ntohs(local.sin_port) == m_boundPort &&
                       ntohl(local.sin_addr.s_addr) == m_request.localAddress.toIPv4Address() &&
                       m_socket->localAddress() == m_request.localAddress && m_socket->localPort() == m_boundPort;
#endif
        return m_fdValid && m_localMatch;
    }

    bool boundIdentityMatches() {
        if (!sourceIdentityMatches() || !interfaceIdentityMatches() || !m_binderOk) return false;
#ifdef Q_OS_WIN
        DWORD index = 0;
        int size = sizeof(index);
        return ::getsockopt(SOCKET(m_boundFd), IPPROTO_IP, IP_UNICAST_IF,
                            reinterpret_cast<char *>(&index), &size) == 0 &&
               size == sizeof(index) && index == DWORD(m_boundInterfaceIndex);
#else
        // Android's binder validates the unique VPN Network/link identity
        // before connect. Retain that exact fd and source throughout TLS.
        return true;
#endif
    }

    int hostCount() const {
#ifdef MAYAK_TUNNEL_PROBE_TESTING
        if (!m_request.testHost.isEmpty()) return 1;
#endif
        return Hosts.size();
    }
    QString hostAt(int index) const {
#ifdef MAYAK_TUNNEL_PROBE_TESTING
        if (!m_request.testHost.isEmpty()) return m_request.testHost;
#endif
        return Hosts.at(index);
    }

    QPointer<MayakTunnelProbe> m_owner;
    const quint64 m_generation;
    const MayakTunnelProbeRequest m_request;
    QTimer *m_deadline;
    QTimer *m_bindRetry;
    QPointer<QSslSocket> m_socket;
    QByteArray m_wire;
    int m_hostIndex = 0;
    QString m_currentHost;
#ifdef MAYAK_TUNNEL_PROBE_TESTING
    int m_testSourceBindFailures = m_request.testSourceBindFailures;
    bool m_testIdentityDriftDuringBindWait = false;
#endif
    int m_attempt = 0;
    bool m_finished = false;
    bool m_sourceBindInProgress = false;
    bool m_sourceBindWaiting = false;
    mutable QElapsedTimer m_elapsed;
    int m_endpointIndex = 0;
    int m_lastSocketState = int(QAbstractSocket::UnconnectedState);
    int m_lastSocketError = int(QAbstractSocket::UnknownSocketError);
    int m_lastMode = int(QSslSocket::UnencryptedMode);
    int m_tlsErrorCount = 0;
    int m_peerVerifyError = -1;
    int m_alertSentLevel = -1;
    int m_alertSentType = -1;
    int m_alertReceivedLevel = -1;
    int m_alertReceivedType = -1;
    qint64 m_encryptedBytesWritten = 0;
    qintptr m_boundFd = -1;
    quint16 m_boundPort = 0;
    int m_boundInterfaceIndex = 0;
#ifdef Q_OS_WIN
    mayak::tunnel::InterfaceIdentity m_boundInterfaceIdentity;
#endif
    bool m_binderOk = false;
    bool m_localMatch = false;
    bool m_fdValid = false;
    bool m_firstReadLogged = false;
    bool m_tlsEstablished = false;
    bool m_attemptRejected = false;
    bool m_responseCompleted = false;
    bool m_parseOk = false;
    bool m_nonceOk = false;
    bool m_egressOk = false;
};

quint64 MayakTunnelProbe::start(const MayakTunnelProbeRequest &request) {
    cancel();
    const quint64 gen = ++m_generation;
    auto *run = new ProbeRun(this, gen, request);
    m_run = run;
    run->start();
    return gen;
}

void MayakTunnelProbe::cancel() {
    ++m_generation;
    if (m_run) delete m_run.data();
    m_run.clear();
}

bool MayakTunnelProbe::validateResponse(const QByteArray &body, const QString &nonce,
                                        const QStringList &expected, QString *observed, QString *error) {
    QJsonParseError parseError{};
    if (!JsonObjectKeyScanner(body).hasUniqueKeys()) { *error = "duplicate or malformed JSON object key"; return false; }
    const auto doc = QJsonDocument::fromJson(body, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) { *error = "invalid JSON response"; return false; }
    const QJsonObject obj = doc.object();
    const auto args = obj.value("args");
    const auto nonceValue = args.isObject() ? args.toObject().value("mayak_nonce") : QJsonValue();
    QString returnedNonce;
    if (nonceValue.isString()) returnedNonce = nonceValue.toString();
    else if (nonceValue.isArray() && nonceValue.toArray().size() == 1 && nonceValue.toArray().first().isString()) returnedNonce = nonceValue.toArray().first().toString();
    if (returnedNonce != nonce) { *error = "nonce mismatch"; return false; }
    const QString origin = obj.value("origin").toString();
    const QString first = origin.section(',', 0, 0).trimmed();
    if (!validIpv4(first) || !expected.contains(first)) { *error = "unexpected or invalid observed egress"; return false; }
    if (observed) *observed = first;
    return true;
}
