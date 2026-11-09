#ifndef GATEWAYCONTROLLER_H
#define GATEWAYCONTROLLER_H

#include <QByteArray>
#include <QFuture>
#include <QDeadlineTimer>
#include <QJsonObject>
#include <QObject>
#include <QPair>
#include <QString>
#include <QStringList>

#include "core/utils/errorCodes.h"

#include "agw.h"

class SecureAppSettingsRepository;

struct GatewayPostResult
{
    amnezia::ErrorCode error = amnezia::ErrorCode::ApiConfigDownloadError;
    QByteArray body;
    bool authenticatedResponse = false; // AGW_OK: response decryption and validation succeeded
};

class GatewayController : public QObject
{
    Q_OBJECT

public:
    explicit GatewayController(const QString &gatewayEndpoint, const bool isDevEnvironment, const int requestTimeoutMsecs,
                               const bool isStrictKillSwitchEnabled, SecureAppSettingsRepository *appSettingsRepository,
                               QObject *parent = nullptr);
    ~GatewayController() override;

    amnezia::ErrorCode post(const QString &endpoint, const QJsonObject apiPayload, QByteArray &responseBody);
    QFuture<QPair<amnezia::ErrorCode, QByteArray>> postAsync(const QString &endpoint, const QJsonObject apiPayload);
    QFuture<GatewayPostResult> postAuthenticatedAsync(const QString &endpoint, const QJsonObject apiPayload);

private:
    bool prepareRequest(int maxPreparationMsecs, const QDeadlineTimer *totalDeadline = nullptr);
    QStringList requestHosts() const;

    QPair<amnezia::ErrorCode, QByteArray> executePost(const QString &endpoint, const QJsonObject &apiPayload);
    GatewayPostResult executePostDetailed(const QString &endpoint, const QJsonObject &apiPayload, int timeoutOverrideMsecs = 0,
                                          const QDeadlineTimer *totalDeadline = nullptr);
    static amnezia::ErrorCode mapResultCode(const int code, const QByteArray &responseBody);
    void persistState();

    QString m_gatewayEndpoint;
    int m_requestTimeoutMsecs = 0;
    QDeadlineTimer m_requestDeadline;
    bool m_isStrictKillSwitchEnabled = false;
    SecureAppSettingsRepository *m_appSettingsRepository = nullptr;

    agw_client_handle m_client = 0;
    bool m_publicKeyMissing = false;
    QByteArray m_lastPersistedState;
};

#endif // GATEWAYCONTROLLER_H
