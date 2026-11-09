#pragma once

#include <QObject>
#include <QPointer>
#include <memory>
#include "core/controllers/mayakBackendBridge.h"
#include "core/controllers/api/mayakAdmissionClient.h"
#include "core/protocols/vpnProtocol.h"

class SecureQSettings;
class SecureServersRepository;
class SecureAppSettingsRepository;
class SubscriptionController;
class ConnectionController;

// Application-thread owner. No platform getter is read across thread boundaries.
class MayakAutoConnectRuntime final : public QObject {
    Q_OBJECT
public:
    MayakAutoConnectRuntime(SecureQSettings*, SecureServersRepository*, SecureAppSettingsRepository*,
                           SubscriptionController*, ConnectionController*, MayakBackendBridge::Port,
                           QObject* parent = nullptr, mayak::admission::Transport transport = {});
    ~MayakAutoConnectRuntime() override;
    bool manages(const QString& serverId) const;
    void begin(const QString& serverId);
    void cancel();
    void shutdown();
    bool busy() const;
    QString message() const { return m_message; }
signals:
    void stateChanged(Vpn::ConnectionState state, const QString& message);
private:
    struct Session;
    void publish(Vpn::ConnectionState state, const QString& message);
    SecureQSettings* m_settings;
    QPointer<SecureServersRepository> m_servers;
    QPointer<SecureAppSettingsRepository> m_app;
    SubscriptionController* m_subscription;
    QPointer<ConnectionController> m_connection;
    MayakBackendBridge::Port m_port;
    mayak::admission::Transport m_transport;
    std::shared_ptr<Session> m_session;
    QString m_message;
};
