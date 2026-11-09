#pragma once

#include <QObject>
#include <QNetworkAccessManager>
#include <QJsonObject>
#include <QSet>
#include <QUrl>
#include <QFuture>
#include <functional>

#include "core/controllers/api/subscriptionController.h"

class ImportUiController;
class SecureAppSettingsRepository;
class ServersController;

class MayakSubscriptionProvisioner : public QObject
{
public:
    using Completion = std::function<void(ErrorCode)>;
    using IsCurrent = std::function<bool()>;
    using QObject::QObject;
    virtual void provision(const QString &serverId, IsCurrent isCurrent, Completion completion) = 0;
};

class GatewayMayakProvisioner final : public MayakSubscriptionProvisioner
{
public:
    using GatewayConfigRequest = std::function<QFuture<SubscriptionController::GatewayConfigResult>(const QString &)>;
    GatewayMayakProvisioner(SubscriptionController *subscriptionController, ServersController *serversController,
                            QObject *parent = nullptr);
    GatewayMayakProvisioner(SubscriptionController *subscriptionController, ServersController *serversController,
                            QObject *parent, GatewayConfigRequest request);
    void provision(const QString &serverId, IsCurrent isCurrent, Completion completion) override;
private:
    SubscriptionController *m_subscriptionController;
    ServersController *m_serversController;
    GatewayConfigRequest m_request;
};

class MayakInviteUiController final : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool busy READ busy NOTIFY stateChanged)
    Q_PROPERTY(bool hasSession READ hasSession NOTIFY stateChanged)
    Q_PROPERTY(bool accountMetadataKnown READ accountMetadataKnown NOTIFY stateChanged)
    Q_PROPERTY(bool accountHasPassword READ accountHasPassword NOTIFY stateChanged)
    Q_PROPERTY(QString accountEmail READ accountEmail NOTIFY stateChanged)
    Q_PROPERTY(bool requiresFreshInvite READ requiresFreshInvite NOTIFY stateChanged)
    Q_PROPERTY(QString message READ message NOTIFY stateChanged)
public:
    MayakInviteUiController(SecureAppSettingsRepository *settings, ImportUiController *importer,
                            ServersController *serversController, MayakSubscriptionProvisioner *provisioner,
                            QNetworkAccessManager *network = nullptr, QUrl apiRoot = {}, QObject *parent = nullptr);
    bool busy() const { return m_busy; }
    bool hasSession() const;
    bool accountMetadataKnown() const { return m_accountMetadataKnown; }
    bool accountHasPassword() const { return m_accountHasPassword; }
    QString accountEmail() const { return m_accountEmail; }
    bool requiresFreshInvite() const { return m_requiresFreshInvite; }
    QString message() const { return m_message; }
    Q_INVOKABLE void acceptInvite(const QString &invite);
    Q_INVOKABLE void registerAccount(const QString &invite, const QString &email, const QString &password);
    Q_INVOKABLE void login(const QString &email, const QString &password);
    Q_INVOKABLE void bindCredentials(const QString &email, const QString &password);
    Q_INVOKABLE void logout();
    Q_INVOKABLE void cancelPendingRequests();
    Q_INVOKABLE void retrySetup();
    Q_INVOKABLE void refreshAccount();
signals:
    void stateChanged();
    void setupFinished();
private:
    void requestAppKey();
    void continueWithAppKey(const QString &key);
    QString findServerForApiKey(const QString &apiKey) const;
    void startProvisioning(const QString &serverId);
    void onProvisioningFinished(const QString &serverId, ErrorCode error);
    void setMessage(const QString &message);
    void trackReply(QNetworkReply *reply);
    void invalidatePendingRequests();
    void postAuthentication(const QString &path, const QJsonObject &payload);
    void updateAccountMetadata(const QJsonObject &account);
    void clearAccountMetadata();
    static QString parseInvite(const QString &invite);
    SecureAppSettingsRepository *m_settings;
    ImportUiController *m_importer;
    ServersController *m_serversController;
    MayakSubscriptionProvisioner *m_provisioner;
    QNetworkAccessManager *m_network;
    QUrl m_apiRoot;
    bool m_busy = false;
    bool m_importStarted = false;
    bool m_requiresFreshInvite = false;
    bool m_accountMetadataKnown = false;
    bool m_accountHasPassword = false;
    QString m_accountEmail;
    QString m_pendingApiKey;
    QString m_message;
    quint64 m_requestGeneration = 0;
    quint64 m_accountRequestGeneration = 0;
    QSet<QNetworkReply *> m_activeReplies;
};
