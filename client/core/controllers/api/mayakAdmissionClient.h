#ifndef MAYAKADMISSIONCLIENT_H
#define MAYAKADMISSIONCLIENT_H

#include <QDateTime>
#include <QFuture>
#include <QJsonObject>
#include <QPair>
#include <QString>
#include <QStringList>
#include <QSharedPointer>
#include <functional>

#include "core/utils/errorCodes.h"
#include "core/controllers/gatewayController.h"

namespace mayak {
namespace admission {

struct Candidate {
    QString id;
    QString host;
    quint16 port = 0;
    bool preferred = false;
    QStringList expectedEgressIps;
};

struct ConnectionCapability {
    int schema = 0;
    qint64 revision = 0;
    QDateTime expiresAt;
    QList<Candidate> candidates;
};

struct AdmissionError {
    int httpStatus = 0;
    QString message;
    QString code;
    int retryAfterMs = -1;
    bool terminal = false;
};

// One Xray path to the SAME exit as the AWG allocation (server field xray_paths, schema 1).
// Shape only; the config is bound to the candidate host by decodeXrayPathConfig().
struct XrayPath {
    QString id;            // "xray-<fingerprint>"
    QString fingerprint;   // uTLS fingerprint of this path
    QString encodedConfig; // vpn:// key with exactly one amnezia-xray container
};

// Validated content of one path, bound to the admitted candidate host.
struct XrayPathConfig {
    QJsonObject root;       // decoded vpn:// root (config_version 2)
    QJsonObject container;  // the single amnezia-xray container
    QJsonObject clientJson; // parsed last_config (xray client JSON)
};

struct AcquireResponse {
    QString allocationId;
    QDateTime connectBefore;
    qint64 configRevision = 0;
    QString encodedConfig;
    // Optional display-only metadata. Empty values mean unknown and never
    // affect validation of the VPN allocation/configuration above.
    QString exitLocationCandidateId;
    QString exitLocationCityId;
    // Optional Xray paths (request field mayak_paths=1). A malformed list never invalidates the
    // AWG allocation above: it is dropped and xrayPathsRejected tells why (for the log only).
    QList<XrayPath> xrayPaths;
    bool xrayPathsOffered = false;
    QString xrayPathsRejected;
};

struct Response {
    amnezia::ErrorCode transportError = amnezia::ErrorCode::NoError;
    QByteArray body;
    bool authenticatedResponse = false;
    QString action;
    QString cycleToken; // opaque caller token, preserved byte-for-byte as QString
    QString attemptId;
    bool isError = false;
    AdmissionError error;
    AcquireResponse acquire;
    bool acquireValid = false;
    bool responseValid = false;
    bool success = false;
    bool resumeAllocation = false; // copied from Request
};

struct Request {
    QString action; // acquire, proven, release, reconcile
    QString attemptId;
    QString cycleToken;
    QString candidateId;
    QString allocationId;
    QJsonObject commonPayload; // auth_data, installation_uuid and public_key
    qint64 deadlineUtcMs = 0;
    // Idempotent re-acquire of an existing allocation (cold-start adoption): the server returns
    // that allocation's original connect_before, which may already be in the past.
    bool resumeAllocation = false;
    // acquire only: ask for the Xray paths of the same exit (mayak_paths=1).
    bool requestPaths = false;
};

using Transport = std::function<QFuture<GatewayPostResult>(const QString &, const QJsonObject &, int)>;
using GatewayFactory = std::function<QSharedPointer<GatewayController>(int boundedTimeoutMsecs)>;
using Completion = std::function<void(Response)>;

bool parseConnectionCapability(const QByteArray &responseBody, const QDateTime &nowUtc, ConnectionCapability *out,
                               QString *failure = nullptr);
bool parseAcquireResponse(const QByteArray &responseBody, AcquireResponse *out, QString *failure = nullptr,
                          bool allowPastConnectBefore = false);
// Strict shape of xray_paths: schema 1, 1..4 unique paths, id "xray-<fp>", known fingerprint, vpn:// config.
bool parseXrayPaths(const QJsonValue &value, QList<XrayPath> *out, QString *failure = nullptr);
// Decodes one path and checks it targets exactly candidateHost with the path's fingerprint.
bool decodeXrayPathConfig(const XrayPath &path, const QString &candidateHost, XrayPathConfig *out,
                          QString *failure = nullptr);
bool isKnownXrayFingerprint(const QString &fingerprint);
bool parseAdmissionError(const QByteArray &responseBody, bool trustedEncryptedResponse, AdmissionError *out);
bool isValidAttemptId(const QString &attemptId);
QJsonObject buildPayload(const Request &request, bool *valid = nullptr);
QJsonObject buildMayakConfigPayload(QJsonObject commonPayload, bool *valid = nullptr);
int boundedTimeoutMsecs(qint64 deadlineUtcMs, int maximumTimeoutMsecs);

class MayakAdmissionClient
{
public:
    // No cancellation handle is exposed: a stale operation still completes with its original
    // cycle/attempt tags so the caller can clean up a late successful acquire.
    static void postAsync(const Request &request, const Transport &transport, Completion completion);
    static void postAsync(const Request &request, const GatewayFactory &gatewayFactory,
                          int maximumTimeoutMsecs, Completion completion);
};

} // namespace admission
} // namespace mayak

#endif // MAYAKADMISSIONCLIENT_H
