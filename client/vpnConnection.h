#ifndef VPNCONNECTION_H
#define VPNCONNECTION_H

#include <QObject>
#include <QMetaObject>
#include <QString>
#include <QScopedPointer>
#include <QRemoteObjectNode>
#include <QTimer>

#include "core/protocols/vpnProtocol.h"
#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"
#include "core/utils/awgTunnelHealth.h"
#include "core/controllers/mayakBackendBridge.h"
#include "core/repositories/secureServersRepository.h"
#include "core/repositories/secureAppSettingsRepository.h"

#ifdef AMNEZIA_DESKTOP
#include "core/utils/ipcClient.h"
#endif

#ifdef Q_OS_ANDROID
#include "core/protocols/androidVpnProtocol.h"
#endif

using namespace amnezia;

class VpnConnection : public QObject
{
    Q_OBJECT

public:
    // Fork split tunneling settings applied to a given config (Mayak managed start/adopt).
    void appendSplitTunnelingConfig(QJsonObject &config) const;
    // Mayak «Россия напрямую»: replaces the site split keys when the mode is on. Returns false
    // when the mode is off (config untouched). excludeRoutes/routeBudget: platform strategy.
    bool appendMayakRussiaDirectConfig(QJsonObject &config, bool excludeRoutes, int routeBudget) const;
    explicit VpnConnection(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository, QObject* parent = nullptr);
    ~VpnConnection() override;

    static QString bytesPerSecToText(quint64 bytes);

    ErrorCode lastError() const;
    Vpn::ConnectionState connectionState() const;

    QSharedPointer<VpnProtocol> vpnProtocol() const;
    // Owner-thread API for adapters: capture id + configured hex peer + numeric endpoint.
    // Empty context means that no current activation can provide trusted AWG health.
    AwgHealthContext expectedAwgHealthContext() const;

    // Safe facade construction seam; lambdas dispatch only on this->thread().
    MayakBackendBridge::Port managedBackendPort();
    const QString &remoteAddress() const;
    void addSitesRoutes(const QString &gw, amnezia::RouteMode mode);

#ifdef Q_OS_ANDROID
    void restoreConnection();
#endif

public slots:
    void setRepositories(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository);
    void connectToVpn(const QString &serverId, DockerContainer container, const QJsonObject &vpnConfiguration);
    void reconnectToVpn();
    void disconnectFromVpn();

    void onKillSwitchModeChanged(bool enabled);
    void disconnectSlots();

    void setConnectionState(Vpn::ConnectionState state);

signals:
    void bytesChanged(quint64 receivedBytes, quint64 sentBytes);
    void awgTunnelHealthUpdated(const AwgTunnelHealth& health);
    void connectionStateChanged(Vpn::ConnectionState state);
    void vpnProtocolError(amnezia::ErrorCode error);

    void serviceIsNotReady();

protected slots:
    void onBytesChanged(quint64 receivedBytes, quint64 sentBytes);
    void onConnectionStateChanged(Vpn::ConnectionState state);
    void onAwgTunnelHealth(const AwgTunnelHealth& health);

protected:
    QSharedPointer<VpnProtocol> m_vpnProtocol;

private:
    struct ManagedBackend;
    std::shared_ptr<ManagedBackend> m_managedBackend;
#ifdef AMNEZIA_DESKTOP
    // Mayak Xray path (Windows/desktop): the fork's XrayProtocol under the managed lifecycle.
    void launchMayakXray(std::shared_ptr<ManagedBackend> s, MayakBackendBridge::Ticket t, QJsonObject config,
                         qint64 deadline, MayakBackendBridge::Done done);
    void stopMayakXray(std::shared_ptr<ManagedBackend> s, std::function<void(QString, QString, bool)> finish,
                       QString nonce, QString context, qint64 deadline);
    // A Mayak Xray tunnel left by an ended process (interface 10.33.0.2): stopped before inspection.
    bool cleanupMayakXrayLeftover();
#endif
    SecureServersRepository* m_serversRepository;
    SecureAppSettingsRepository* m_appSettingsRepository;

    QJsonObject m_vpnConfiguration;
    QJsonObject m_routeMode;
    QString m_remoteAddress;

    // Only for iOS for now, check counters
    QTimer m_checkTimer;

#ifdef Q_OS_ANDROID
   AndroidVpnProtocol* androidVpnProtocol = nullptr;

   AndroidVpnProtocol* createDefaultAndroidVpnProtocol();
   void createAndroidConnections();
#endif

   Vpn::ConnectionState m_connectionState;

   void createProtocolConnections();

   void appendSplitTunnelingConfig();
   void appendKillSwitchConfig();
};

#endif // VPNCONNECTION_H
