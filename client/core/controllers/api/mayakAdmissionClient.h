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

struct AcquireResponse {
    QString allocationId;
    QDateTime connectBefore;
    qint64 configRevision = 0;
    QString encodedConfig;
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
};

struct Request {
    QString action; // acquire, proven, release, reconcile
    QString attemptId;
    QString cycleToken;
    QString candidateId;
    QString allocationId;
    QJsonObject commonPayload; // auth_data, installation_uuid and public_key
    qint64 deadlineUtcMs = 0;
};

using Transport = std::function<QFuture<GatewayPostResult>(const QString &, const QJsonObject &, int)>;
using GatewayFactory = std::function<QSharedPointer<GatewayController>(int boundedTimeoutMsecs)>;
using Completion = std::function<void(Response)>;

bool parseConnectionCapability(const QByteArray &responseBody, const QDateTime &nowUtc, ConnectionCapability *out,
                               QString *failure = nullptr);
bool parseAcquireResponse(const QByteArray &responseBody, AcquireResponse *out, QString *failure = nullptr);
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
