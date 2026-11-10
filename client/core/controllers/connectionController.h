#ifndef CONNECTIONCONTROLLER_H
#define CONNECTIONCONTROLLER_H

#include <QObject>
#include <QJsonObject>
#include <QPair>
#include <QVariantMap>
#include <memory>

#include "core/utils/containerEnum.h"
#include "core/utils/containers/containerUtils.h"
#include "core/utils/protocolEnum.h"
#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"
#include "core/repositories/secureServersRepository.h"
#include "core/repositories/secureAppSettingsRepository.h"
#include "core/protocols/vpnProtocol.h"
#include "vpnConnection.h"

using namespace amnezia;
class MayakAutoConnectRuntime;

class ConnectionController : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool cleanupPending READ managedCleanupPending NOTIFY connectionStateChanged)

public:
    explicit ConnectionController(SecureServersRepository* serversRepository,
                                 SecureAppSettingsRepository* appSettingsRepository,
                                 VpnConnection* vpnConnection,
                                 QObject* parent = nullptr);
    ~ConnectionController() = default;

    ErrorCode prepareConnection(const QString &serverId,
                               QJsonObject& vpnConfiguration,
                               DockerContainer& container);

    ErrorCode isConnectionSupported(const QString &serverId) const;

    ErrorCode openConnection(const QString &serverId);

    void closeConnection();

#ifdef Q_OS_ANDROID
    void restoreConnection();
#endif

    void onKillSwitchModeChanged(bool enabled);

    ErrorCode lastConnectionError() const;

    bool isConnected() const;
    void setConnectionState(Vpn::ConnectionState state);

    // Mayak Xray path: the vpn configuration of an admitted amnezia-xray container (decoded
    // xray_paths entry) with the managed server's DNS and local settings. Nothing is stored.
    amnezia::ErrorCode prepareMayakXrayConnection(const QString &serverId, const QJsonObject &xrayRoot,
                                                  QJsonObject &vpnConfiguration);
    // Rule 5: xray writes every destination to its access log unless told not to (an empty
    // "access" means stdout). Forces log.access="none" and no DNS log in a prepared Xray config.
    static void disableXrayAccessLog(QJsonObject &vpnConfiguration);
    QJsonObject createConnectionConfiguration(const QPair<QString, QString> &dns,
                                             bool isApiConfig,
                                             const QString &hostName,
                                             const QString &description,
                                             int configVersion,
                                             const ContainerConfig &containerConfig,
                                             DockerContainer container);

    bool isServiceReady() const;

    bool isContainerSupported(DockerContainer container) const;
    void setMayakRuntime(MayakAutoConnectRuntime* runtime);
    bool isMayakManaged(const QString& serverId) const;
    bool isMayakActive() const { return m_managedActive; }
    QString managedMessage() const;
    QString managedConnectionPhase() const;
    QVariantMap managedExitLocation() const;
    bool managedCleanupPending() const;
    void retryManagedCleanup();
    bool canInstallUpdate() const;

signals:
    void connectionStateChanged(Vpn::ConnectionState state);
    void openConnectionRequested(const QString &serverId, DockerContainer container, const QJsonObject &vpnConfiguration);
    void closeConnectionRequested();
    void killSwitchModeChangedRequested(bool enabled);

#ifdef Q_OS_ANDROID
    void restoreConnectionRequested();
#endif

private:
    ErrorCode defaultContainerForServer(const QString &serverId, DockerContainer &container) const;
    // Rule 4 for a manually imported Xray config (not a Mayak server): the fork reports
    // "Connected" as soon as tun2socks runs. Mayak shows "Connecting" until a probe through
    // the Xray interface reaches the expected egress (the server's own IPv4).
    void legacyXrayState(Vpn::ConnectionState state);
    void probeLegacyXray(quint64 generation, int attempt);
    QString m_legacyXrayEgress;   // empty: the legacy connection is not Xray
    quint64 m_legacyXrayGeneration = 0;
    bool m_legacyXrayProven = false;

    SecureServersRepository* m_serversRepository;
    SecureAppSettingsRepository* m_appSettingsRepository;
    VpnConnection* m_vpnConnection;
    MayakAutoConnectRuntime* m_mayak = nullptr;
    bool m_managedActive = false;
    Vpn::ConnectionState m_effectiveState = Vpn::ConnectionState::Disconnected;
};

#endif
