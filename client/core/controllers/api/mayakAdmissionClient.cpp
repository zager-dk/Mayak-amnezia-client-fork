#include "mayakAdmissionClient.h"

#include <QFutureWatcher>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QRegularExpression>
#include <QSet>
#include <cmath>
#include <utility>

#include "core/controllers/gatewayController.h"

namespace mayak::admission {
namespace {
constexpr qsizetype maxBodyBytes = 64 * 1024;
constexpr int maxString = 1024;

bool isGuid(const QString &s)
{
    static const QRegularExpression re(QStringLiteral("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"));
    return re.match(s).hasMatch();
}

bool isIpv4(const QString &s)
{
    const QStringList parts = s.split(QLatin1Char('.'));
    if (parts.size() != 4) return false;
    for (const QString &part : parts) {
        if (part.isEmpty() || (part.size() > 1 && part.startsWith(QLatin1Char('0')))) return false;
        for (const QChar ch : part) {
            if (ch.unicode() < '0' || ch.unicode() > '9') return false;
        }
        bool ok = false;
        const uint n = part.toUInt(&ok);
        if (!ok || n > 255) return false;
    }
    return true;
}

bool isPublicIpv4(const QString &s)
{
    if (!isIpv4(s)) return false;
    const QStringList p = s.split(QLatin1Char('.'));
    const int a = p.at(0).toInt(), b = p.at(1).toInt();
    if (a == 0 || a == 10 || a == 127 || a >= 224) return false;
    if (a == 100 && b >= 64 && b <= 127) return false;
    if (a == 169 && b == 254) return false;
    if (a == 172 && b >= 16 && b <= 31) return false;
    const int c = p.at(2).toInt();
    if (a == 192 && (b == 0 || b == 168 || (b == 88 && c == 99))) return false;
    if (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100))) return false;
    if (a == 203 && b == 0 && c == 113) return false;
    return true;
}

bool parseObject(const QByteArray &bytes, QJsonObject *object)
{
    if (bytes.isEmpty() || bytes.size() > maxBodyBytes) return false;
    QJsonParseError error;
    const auto doc = QJsonDocument::fromJson(bytes, &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject()) return false;
    *object = doc.object();
    return true;
}

bool boundedString(const QJsonValue &v, int max, QString *out)
{
    if (!v.isString()) return false;
    const QString s = v.toString();
    if (s.isEmpty() || s.size() > max || s.trimmed() != s) return false;
    *out = s;
    return true;
}

void bridge(QFuture<GatewayPostResult> source, Response response, Completion completion,
            QSharedPointer<GatewayController> owner)
{
    auto *watcher = new QFutureWatcher<GatewayPostResult>;
    QObject::connect(watcher, &QFutureWatcherBase::finished, watcher,
                     [watcher, response, completion, owner]() mutable {
        const auto result = watcher->result();
        response.transportError = result.error;
        response.body = result.body;
        response.authenticatedResponse = result.authenticatedResponse;
        AdmissionError parsed;
        response.isError = parseAdmissionError(result.body, result.authenticatedResponse, &parsed);
        if (response.isError) response.error = parsed;
        else if (result.authenticatedResponse && result.error == amnezia::ErrorCode::NoError && result.body.size() <= maxBodyBytes) {
            QJsonObject obj;
            if (parseObject(result.body, &obj)) {
                if (response.action == QStringLiteral("acquire") && obj.contains(QStringLiteral("allocation_id"))) {
                    response.acquireValid = parseAcquireResponse(result.body, &response.acquire);
                    response.responseValid = response.acquireValid;
                    response.success = response.acquireValid;
                } else {
                    const QString key = response.action == QStringLiteral("proven") ? QStringLiteral("proven")
                                        : response.action == QStringLiteral("release") ? QStringLiteral("released")
                                        : response.action == QStringLiteral("reconcile") ? QStringLiteral("reconciled") : QString();
                    if (!key.isEmpty() && obj.value(key).isBool()) {
                        response.responseValid = true;
                        response.success = obj.value(key).toBool();
                    }
                }
            }
        }
        if (completion) completion(response);
        watcher->deleteLater();
        Q_UNUSED(owner); // intentionally retained through tagged result publication
    });
    watcher->setFuture(source);
}
} // namespace

bool isValidAttemptId(const QString &attemptId)
{
    static const QRegularExpression re(QStringLiteral("^[A-Za-z0-9_-]{16,128}$"));
    return re.match(attemptId).hasMatch();
}

int boundedTimeoutMsecs(qint64 deadlineUtcMs, int maximumTimeoutMsecs)
{
    if (maximumTimeoutMsecs <= 0) return 0;
    const qint64 remaining = deadlineUtcMs - QDateTime::currentMSecsSinceEpoch();
    if (remaining <= 0) return 0;
    return static_cast<int>(qMin<qint64>(remaining, qMin(maximumTimeoutMsecs, 300000)));
}

bool parseConnectionCapability(const QByteArray &responseBody, const QDateTime &nowUtc, ConnectionCapability *out,
                               QString *failure)
{
    auto fail = [failure](const QString &reason) { if (failure) *failure = reason; return false; };
    QJsonObject root;
    if (!out || !parseObject(responseBody, &root)) return fail(QStringLiteral("invalid or oversized response"));
    *out = ConnectionCapability{};
    const QJsonValue capabilityValue = root.value(QStringLiteral("mayak_connection"));
    if (!capabilityValue.isObject()) return fail(QStringLiteral("missing mayak_connection capability"));
    const QJsonObject obj = capabilityValue.toObject();
    if (!obj.value(QStringLiteral("schema")).isDouble() || obj.value(QStringLiteral("schema")).toInt(-1) != 1)
        return fail(QStringLiteral("unsupported schema"));
    const QJsonValue revision = obj.value(QStringLiteral("revision"));
    if (!revision.isDouble() || revision.toDouble() < 1 || revision.toDouble() > 9007199254740991.0
        || std::floor(revision.toDouble()) != revision.toDouble()) return fail(QStringLiteral("invalid revision"));
    QString expiry;
    if (!boundedString(obj.value(QStringLiteral("expires_at")), 40, &expiry)) return fail(QStringLiteral("invalid expiry"));
    const QDateTime expiresAt = QDateTime::fromString(expiry, Qt::ISODate).toUTC();
    if (!expiresAt.isValid() || expiresAt <= nowUtc.toUTC() || expiresAt > nowUtc.toUTC().addDays(31))
        return fail(QStringLiteral("expired or implausible expiry"));
    const QJsonValue candidatesValue = obj.value(QStringLiteral("candidates"));
    if (!candidatesValue.isArray() || candidatesValue.toArray().isEmpty() || candidatesValue.toArray().size() > 3)
        return fail(QStringLiteral("invalid candidate list"));
    QSet<QString> ids;
    QSet<QString> hosts;
    QList<Candidate> candidates;
    for (const QJsonValue &value : candidatesValue.toArray()) {
        if (!value.isObject()) return fail(QStringLiteral("invalid candidate"));
        const QJsonObject c = value.toObject(); Candidate candidate;
        if (!boundedString(c.value(QStringLiteral("id")), 36, &candidate.id) || !isGuid(candidate.id)
            || ids.contains(candidate.id.toLower())) return fail(QStringLiteral("invalid or duplicate candidate id"));
        ids.insert(candidate.id.toLower());
        if (!boundedString(c.value(QStringLiteral("host")), 15, &candidate.host) || !isPublicIpv4(candidate.host))
            return fail(QStringLiteral("invalid candidate host"));
        if (hosts.contains(candidate.host)) return fail(QStringLiteral("duplicate candidate host"));
        hosts.insert(candidate.host);
        const QJsonValue port = c.value(QStringLiteral("port"));
        if (!port.isDouble() || port.toDouble() < 1 || port.toDouble() > 65535 || std::floor(port.toDouble()) != port.toDouble())
            return fail(QStringLiteral("invalid candidate port"));
        candidate.port = static_cast<quint16>(port.toInt());
        if (!c.value(QStringLiteral("preferred")).isBool()) return fail(QStringLiteral("invalid preferred flag"));
        candidate.preferred = c.value(QStringLiteral("preferred")).toBool();
        const QJsonValue egress = c.value(QStringLiteral("expected_egress_ips"));
        if (!egress.isArray() || egress.toArray().isEmpty() || egress.toArray().size() > 3) return fail(QStringLiteral("invalid egress list"));
        QSet<QString> ips;
        for (const QJsonValue &ipValue : egress.toArray()) {
            QString ip;
            if (!boundedString(ipValue, 15, &ip) || !isPublicIpv4(ip) || ips.contains(ip)) return fail(QStringLiteral("invalid egress IP"));
            ips.insert(ip); candidate.expectedEgressIps.push_back(ip);
        }
        candidates.push_back(candidate);
    }
    out->schema = 1; out->revision = static_cast<qint64>(revision.toDouble()); out->expiresAt = expiresAt; out->candidates = candidates;
    return true;
}

bool parseAcquireResponse(const QByteArray &responseBody, AcquireResponse *out, QString *failure)
{
    auto fail = [failure](const QString &reason) { if (failure) *failure = reason; return false; };
    QJsonObject obj;
    if (!out || !parseObject(responseBody, &obj)) return fail(QStringLiteral("invalid or oversized response"));
    *out = AcquireResponse{};
    if (!boundedString(obj.value(QStringLiteral("allocation_id")), 36, &out->allocationId) || !isGuid(out->allocationId))
        return fail(QStringLiteral("invalid allocation id"));
    QString date;
    if (!boundedString(obj.value(QStringLiteral("connect_before")), 40, &date)) return fail(QStringLiteral("invalid connect_before"));
    out->connectBefore = QDateTime::fromString(date, Qt::ISODate).toUTC();
    const QJsonValue revision = obj.value(QStringLiteral("config_revision"));
    const QDateTime now = QDateTime::currentDateTimeUtc();
    if (!out->connectBefore.isValid() || out->connectBefore <= now || out->connectBefore > now.addDays(1)
        || !revision.isDouble() || revision.toDouble() < 1 || revision.toDouble() > 9007199254740991.0
        || std::floor(revision.toDouble()) != revision.toDouble()) return fail(QStringLiteral("invalid revision or deadline"));
    if (!boundedString(obj.value(QStringLiteral("config")), 32768, &out->encodedConfig)) return fail(QStringLiteral("invalid config"));
    out->configRevision = static_cast<qint64>(revision.toDouble());
    return true;
}

bool parseAdmissionError(const QByteArray &responseBody, bool trustedEncryptedResponse, AdmissionError *out)
{
    if (!trustedEncryptedResponse || !out) return false;
    QJsonObject obj;
    if (!parseObject(responseBody, &obj) || !obj.contains(QStringLiteral("http_status"))) return false;
    const auto status = obj.value(QStringLiteral("http_status"));
    if (!status.isDouble() || status.toInt() < 400 || status.toInt() > 599) return false;
    AdmissionError result; result.httpStatus = status.toInt();
    if (!boundedString(obj.value(QStringLiteral("message")), maxString, &result.message)) return false;
    const auto code = obj.value(QStringLiteral("code"));
    if (code.isString()) {
        result.code = code.toString();
        static const QSet<QString> known{QStringLiteral("FULL"), QStringLiteral("NOT_READY"), QStringLiteral("DISABLED"),
                                          QStringLiteral("REVOKED"), QStringLiteral("ACCOUNT_EXPIRED"), QStringLiteral("INVALID_REQUEST"),
                                          QStringLiteral("no_ready_exit"), QStringLiteral("provisioning")};
        if (!known.contains(result.code)) return false;
    }
    if (obj.contains(QStringLiteral("retry_after_ms"))) {
        const auto retry = obj.value(QStringLiteral("retry_after_ms"));
        if (!retry.isDouble() || retry.toInt(-1) < 0 || retry.toInt() > 300000) return false;
        result.retryAfterMs = retry.toInt();
    }
    result.terminal = result.code == QStringLiteral("REVOKED") || result.code == QStringLiteral("ACCOUNT_EXPIRED");
    *out = result;
    return true;
}

QJsonObject buildPayload(const Request &request, bool *valid)
{
    bool ok = isValidAttemptId(request.attemptId) && request.commonPayload.contains(QStringLiteral("auth_data"))
              && request.commonPayload.contains(QStringLiteral("installation_uuid"))
              && request.commonPayload.contains(QStringLiteral("public_key"));
    ok = ok && request.commonPayload.value(QStringLiteral("auth_data")).isObject()
         && request.commonPayload.value(QStringLiteral("installation_uuid")).isString()
         && !request.commonPayload.value(QStringLiteral("installation_uuid")).toString().isEmpty()
         && request.commonPayload.value(QStringLiteral("public_key")).isString()
         && !request.commonPayload.value(QStringLiteral("public_key")).toString().isEmpty();
    const bool actionValid = request.action == QStringLiteral("acquire") || request.action == QStringLiteral("proven")
                             || request.action == QStringLiteral("release") || request.action == QStringLiteral("reconcile");
    ok = ok && actionValid;
    if (request.action == QStringLiteral("acquire")) ok = ok && isGuid(request.candidateId);
    if (request.action == QStringLiteral("proven") || request.action == QStringLiteral("release")) ok = ok && isGuid(request.allocationId);
    if (valid) *valid = ok;
    if (!ok) return {};
    QJsonObject payload = request.commonPayload;
    payload.remove(QStringLiteral("action"));
    payload.remove(QStringLiteral("attempt_id"));
    payload.remove(QStringLiteral("candidate_id"));
    payload.remove(QStringLiteral("allocation_id"));
    payload.insert(QStringLiteral("action"), request.action);
    payload.insert(QStringLiteral("attempt_id"), request.attemptId);
    if (request.action == QStringLiteral("acquire")) payload.insert(QStringLiteral("candidate_id"), request.candidateId);
    if (request.action == QStringLiteral("proven") || request.action == QStringLiteral("release"))
        payload.insert(QStringLiteral("allocation_id"), request.allocationId);
    return payload;
}

QJsonObject buildMayakConfigPayload(QJsonObject commonPayload, bool *valid)
{
    const bool ok = commonPayload.contains(QStringLiteral("auth_data"))
                    && commonPayload.contains(QStringLiteral("installation_uuid"))
                    && commonPayload.contains(QStringLiteral("public_key"));
    if (valid) *valid = ok;
    if (!ok) return {};
    commonPayload.insert(QStringLiteral("mayak_auto_connect"), 1);
    return commonPayload;
}

void MayakAdmissionClient::postAsync(const Request &request, const Transport &transport, Completion completion)
{
    bool valid = false;
    const QJsonObject payload = buildPayload(request, &valid);
    Response response; response.action = request.action; response.cycleToken = request.cycleToken; response.attemptId = request.attemptId;
    const qint64 remaining = request.deadlineUtcMs - QDateTime::currentMSecsSinceEpoch();
    if (!valid || !transport) {
        response.transportError = amnezia::ErrorCode::ApiConfigEmptyError;
        if (completion) completion(response);
        return;
    }
    if (remaining <= 0) {
        response.transportError = amnezia::ErrorCode::ApiConfigTimeoutError;
        if (completion) completion(response);
        return;
    }
    const int timeoutMsecs = boundedTimeoutMsecs(request.deadlineUtcMs, 300000);
    auto source = transport(QStringLiteral("%1v1/admission"), payload, timeoutMsecs);
    bridge(source, response, std::move(completion), {});
}

void MayakAdmissionClient::postAsync(const Request &request, const GatewayFactory &gatewayFactory,
                                     int maximumTimeoutMsecs, Completion completion)
{
    bool valid = false;
    const QJsonObject payload = buildPayload(request, &valid);
    Response response; response.action = request.action; response.cycleToken = request.cycleToken; response.attemptId = request.attemptId;
    const int timeoutMsecs = boundedTimeoutMsecs(request.deadlineUtcMs, maximumTimeoutMsecs);
    if (!valid || !gatewayFactory) {
        response.transportError = amnezia::ErrorCode::ApiConfigEmptyError;
        if (completion) completion(response);
        return;
    }
    if (timeoutMsecs <= 0) {
        response.transportError = amnezia::ErrorCode::ApiConfigTimeoutError;
        if (completion) completion(response);
        return;
    }
    // Each request gets a controller configured with its remaining deadline. The bridge retains
    // that controller through result publication, including a late successful acquire.
    const QSharedPointer<GatewayController> gateway = gatewayFactory(timeoutMsecs);
    if (!gateway) {
        response.transportError = amnezia::ErrorCode::ApiConfigTimeoutError;
        if (completion) completion(response);
        return;
    }
    auto future = gateway->postAuthenticatedAsync(QStringLiteral("%1v1/admission"), payload);
    bridge(future, response, std::move(completion), gateway);
}

} // namespace mayak::admission
