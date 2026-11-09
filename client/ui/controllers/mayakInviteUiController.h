#pragma once

#include <QObject>
#include <QNetworkAccessManager>
#include <QJsonObject>
#include <QSet>
#include <QTimer>
#include <QUrl>
#include <QVariantList>
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
    // Лимит устройств: список устройств аккаунта, одно из которых можно заменить этим.
    Q_PROPERTY(QVariantList limitDevices READ limitDevices NOTIFY stateChanged)
    Q_PROPERTY(int maxDevices READ maxDevices NOTIFY stateChanged)
    // Привязанный Telegram (имя пользователя) или пусто.
    Q_PROPERTY(QString telegramName READ telegramName NOTIFY stateChanged)
    Q_PROPERTY(bool telegramLinkPending READ telegramLinkPending NOTIFY stateChanged)
    Q_PROPERTY(bool telegramLinked READ telegramLinked NOTIFY stateChanged)
    // Telegram, который нажал «Запустить» в боте и ждёт подтверждения в приложении.
    Q_PROPERTY(QString telegramConfirmName READ telegramConfirmName NOTIFY stateChanged)
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
    QVariantList limitDevices() const { return m_limitDevices; }
    int maxDevices() const { return m_maxDevices; }
    QString telegramName() const { return m_telegramName; }
    bool telegramLinkPending() const { return !m_telegramLinkRequestId.isEmpty(); }
    bool telegramLinked() const { return m_telegramLinked; }
    QString telegramConfirmName() const { return m_telegramConfirmName; }
    Q_INVOKABLE void confirmTelegramLink();
    Q_INVOKABLE void replaceDevice(const QString &deviceId);
    Q_INVOKABLE void linkTelegram();
    Q_INVOKABLE void cancelTelegramLink();
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
    // Ссылка на бота для привязки Telegram: QML открывает её во внешнем приложении.
    void openExternalUrl(const QString &url);
private:
    void requestAppKey(const QString &replaceDeviceId = QString());
    void requestLegacyAppKey();
    void pollTelegramLink();
    void continueWithAppKey(const QString &key);
    QString findServerForApiKey(const QString &apiKey) const;
    QString findManagedMayakServer() const;
    QString findServerForDevice() const;
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
    QVariantList m_limitDevices;
    int m_maxDevices = 0;
    QString m_telegramName;
    QString m_telegramLinkRequestId;
    int m_telegramPolls = 0;
    bool m_telegramLinked = false;
    bool m_telegramConfirmPending = false;
    QString m_telegramConfirmName;
    bool m_telegramPollInFlight = false;
    // Сервер подтвердил, что это устройство уже было в этом аккаунте: ключ можно заменить на месте.
    bool m_pendingKeyReused = false;
    QString m_pendingDeviceId;
    qint64 m_telegramConfirmId = 0;
    QTimer *m_telegramPollTimer = nullptr;
    quint64 m_requestGeneration = 0;
    quint64 m_accountRequestGeneration = 0;
    QSet<QNetworkReply *> m_activeReplies;
};
