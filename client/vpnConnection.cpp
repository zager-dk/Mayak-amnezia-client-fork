#include "vpnConnection.h"

#include <QDebug>
#include <QEventLoop>
#include <QFile>
#include <QHostInfo>
#include <QJsonObject>
#include <QObject>
#include <QSharedPointer>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QThread>

#include <core/configurators/openVpnConfigurator.h>
#include <core/configurators/wireguardConfigurator.h>

#ifdef AMNEZIA_DESKTOP
    #include "core/utils/ipcClient.h"
    #include <core/protocols/wireGuardProtocol.h>
    #include <QRemoteObjectPendingCallWatcher>
#endif

#ifdef Q_OS_ANDROID
    #include "platforms/android/android_controller.h"
    #include <QThread>

#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    #include "platforms/ios/ios_controller.h"
#endif

#include "core/utils/networkUtilities.h"
#include "core/utils/serverConfigUtils.h"
#include "vpnConnection.h"

using namespace ProtocolUtils;

struct VpnConnection::ManagedBackend {
    MayakBackendBridge::Ticket ticket;
    AwgHealthContext expected;
    QSharedPointer<VpnProtocol> protocol;
    QPointer<MayakTunnelProbe> probe;
    QString inspectedIdentity;
    std::function<void(MayakBackendBridge::Ticket, AwgTunnelHealth)> health;
    MayakBackendBridge::Done event;
};

VpnConnection::VpnConnection(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository, QObject *parent)
    : QObject(parent),
      m_serversRepository(serversRepository),
      m_appSettingsRepository(appSettingsRepository),
      m_checkTimer(this),
      m_connectionState(Vpn::ConnectionState::Disconnected)
{
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    m_checkTimer.setInterval(1000);
    connect(IosController::Instance(), &IosController::connectionStateChanged, this, &VpnConnection::setConnectionState);
    connect(IosController::Instance(), &IosController::bytesChanged, this, &VpnConnection::onBytesChanged);
#endif
}

VpnConnection::~VpnConnection()
{
}

void VpnConnection::onBytesChanged(quint64 receivedBytes, quint64 sentBytes)
{
    emit bytesChanged(receivedBytes, sentBytes);
}

void VpnConnection::onKillSwitchModeChanged(bool enabled)
{
#ifdef AMNEZIA_DESKTOP
    IpcClient::withInterface([enabled](QSharedPointer<IpcInterfaceReplica> iface){
        QRemoteObjectPendingReply<bool> reply = iface->refreshKillSwitch(enabled);
        if (reply.waitForFinished() && reply.returnValue())
            qDebug() << "VpnConnection::onKillSwitchModeChanged: Killswitch refreshed";
        else
            qWarning() << "VpnConnection::onKillSwitchModeChanged: Failed to execute remote refreshKillSwitch call";
    });
#endif
}

void VpnConnection::onConnectionStateChanged(Vpn::ConnectionState state)
{
#ifdef AMNEZIA_DESKTOP
    if (!m_serversRepository || !m_appSettingsRepository) {
        qCritical() << "VpnConnection::onConnectionStateChanged: repositories not initialized";
        return;
    }

    const QString defaultServerId = m_serversRepository->defaultServerId();
    DockerContainer container = DockerContainer::None;
    switch (m_serversRepository->serverKind(defaultServerId)) {
    case serverConfigUtils::ConfigType::SelfHostedAdmin: {
        const auto cfg = m_serversRepository->selfHostedAdminConfig(defaultServerId);
        if (cfg.has_value()) {
            container = cfg->defaultContainer;
        }
        break;
    }
    case serverConfigUtils::ConfigType::SelfHostedUser: {
        const auto cfg = m_serversRepository->selfHostedUserConfig(defaultServerId);
        if (cfg.has_value()) {
            container = cfg->defaultContainer;
        }
        break;
    }
    case serverConfigUtils::ConfigType::Native: {
        const auto cfg = m_serversRepository->nativeConfig(defaultServerId);
        if (cfg.has_value()) {
            container = cfg->defaultContainer;
        }
        break;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV2:
    case serverConfigUtils::ConfigType::AmneziaFreeV3:
    case serverConfigUtils::ConfigType::ExternalPremium: {
        const auto cfg = m_serversRepository->apiV2Config(defaultServerId);
        if (cfg.has_value()) {
            container = cfg->defaultContainer;
        }
        break;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV1:
    case serverConfigUtils::ConfigType::AmneziaFreeV2:
        break;
    case serverConfigUtils::ConfigType::Invalid:
    default:
        break;
    }

    IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
        switch (state) {
            case Vpn::ConnectionState::Connected: {
                iface->resetIpStack();

                auto flushDns = iface->flushDns();
                if (flushDns.waitForFinished() && flushDns.returnValue())
                    qDebug() << "VpnConnection::onConnectionStateChanged: Successfully flushed DNS";
                else
                    qWarning() << "VpnConnection::onConnectionStateChanged: Failed to flush DNS";

                if (!ContainerUtils::isAwgContainer(container) && container != DockerContainer::WireGuard) {
                    QString dns1 = m_vpnConfiguration.value(configKey::dns1).toString();
                    QString dns2 = m_vpnConfiguration.value(configKey::dns2).toString();

#ifdef Q_OS_MACOS
                    if (!m_appSettingsRepository->isSitesSplitTunnelingEnabled() || m_appSettingsRepository->routeMode() != amnezia::RouteMode::VpnAllExceptSites) {
                        iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << dns1 << dns2);
                    }
#else
                    iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << dns1 << dns2);
#endif

                    if (m_appSettingsRepository->isSitesSplitTunnelingEnabled()) {
                        iface->routeDeleteList(m_vpnProtocol->vpnGateway(), QStringList() << "0.0.0.0");
                        RouteMode routeMode = m_appSettingsRepository->routeMode();
                        if (routeMode == amnezia::RouteMode::VpnOnlyForwardSites) {
                            QTimer::singleShot(1000, m_vpnProtocol.data(),
                                               [this, routeMode]() { addSitesRoutes(m_vpnProtocol->vpnGateway(), routeMode); });
                        } else if (routeMode == amnezia::RouteMode::VpnAllExceptSites) {
                            iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << "0.0.0.0/1");
                            iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << "128.0.0.0/1");

                            iface->routeAddList(m_vpnProtocol->routeGateway(), QStringList() << remoteAddress());
#ifdef Q_OS_MACOS
                            iface->routeAddList(m_vpnProtocol->routeGateway(), QStringList() << dns1 << dns2);
#endif
                            addSitesRoutes(m_vpnProtocol->routeGateway(), routeMode);
                        }
                    }
                }
            } break;
            case Vpn::ConnectionState::Disconnected:
            case Vpn::ConnectionState::Error: {
                auto flushDns = iface->flushDns();
                if (flushDns.waitForFinished() && flushDns.returnValue())
                    qDebug() << "VpnConnection::onConnectionStateChanged: Successfully flushed DNS";
                else
                    qWarning() << "VpnConnection::onConnectionStateChanged: Failed to flush DNS";

                auto clearSavedRoutes = iface->clearSavedRoutes();
                if (clearSavedRoutes.waitForFinished() && clearSavedRoutes.returnValue())
                    qDebug() << "VpnConnection::onConnectionStateChanged: Successfully cleared saved routes";
                else
                    qWarning() << "VpnConnection::onConnectionStateChanged: Failed to clear saved routes";
            } break;
            default:
                break;
        }
    });
#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    if (state == Vpn::ConnectionState::Connected ||
        state == Vpn::ConnectionState::Connecting ||
        state == Vpn::ConnectionState::Reconnecting) {
        m_checkTimer.start();
    } else {
        m_checkTimer.stop();
    }
#endif
}

const QString &VpnConnection::remoteAddress() const
{
    return m_remoteAddress;
}

void VpnConnection::setRepositories(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository)
{
    m_serversRepository = serversRepository;
    m_appSettingsRepository = appSettingsRepository;
}

void VpnConnection::addSitesRoutes(const QString &gw, amnezia::RouteMode mode)
{
#ifdef AMNEZIA_DESKTOP
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::addSitesRoutes: repositories not initialized";
        return;
    }

    QStringList ips;
    QStringList sites;
    const QVariantMap &m = m_appSettingsRepository->vpnSites(mode);
    for (auto i = m.constBegin(); i != m.constEnd(); ++i) {
        if (NetworkUtilities::checkIpSubnetFormat(i.key())) {
            ips.append(i.key());
        } else {
            const QStringList siteIps = SecureAppSettingsRepository::siteIpList(i.value());
            for (const QString &ip : siteIps) {
                if (NetworkUtilities::checkIpSubnetFormat(ip)) {
                    ips.append(ip);
                }
            }
            sites.append(i.key());
        }
    }
    ips.removeDuplicates();

    IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
        iface->routeAddList(gw, ips);
    });

    auto remainingLookups = QSharedPointer<int>::create(sites.size());
    auto needFlush = QSharedPointer<bool>::create(false);

    // re-resolve domains
    for (const QString &site : sites) {
        const auto &cbResolv = [this, site, gw, mode, ips, remainingLookups, needFlush](const QHostInfo &hostInfo) {
            QStringList resolvedIps;
            for (const QHostAddress &addr : hostInfo.addresses()) {
                if (addr.protocol() == QAbstractSocket::NetworkLayerProtocol::IPv4Protocol) {
                    resolvedIps.append(addr.toString());
                }
            }
            resolvedIps.removeDuplicates();
            qDebug() << "[SplitTunneling] addSitesRoutes resolved" << site << "->" << resolvedIps;

            QStringList newIps;
            for (const QString &ip : resolvedIps) {
                if (!ips.contains(ip)) {
                    IpcClient::withInterface([gw, ip](QSharedPointer<IpcInterfaceReplica> iface) {
                        iface->routeAddList(gw, QStringList() << ip);
                    });
                    newIps.append(ip);
                }
            }

            if (!newIps.isEmpty()) {
                m_appSettingsRepository->addVpnSite(mode, site, newIps);
                *needFlush = true;
            }

            if (--(*remainingLookups) > 0)
                return;

            if (!*needFlush)
                return;

            // Async flush: never waitForFinished() here — that re-enters the event loop and
            // can re-enter this QHostInfo callback until the stack overflows (0xc00000fd).
            IpcClient::withInterface([this](QSharedPointer<IpcInterfaceReplica> iface) {
                QRemoteObjectPendingReply<bool> reply = iface->flushDns();
                auto *watcher = new QRemoteObjectPendingCallWatcher(reply, this);
                QObject::connect(watcher, &QRemoteObjectPendingCallWatcher::finished, this,
                        [](QRemoteObjectPendingCallWatcher *call) {
                            if (call->error() != QRemoteObjectPendingCall::NoError
                                || !call->returnValue().toBool()) {
                                qWarning() << "VpnConnection::addSitesRoutes: Failed to flush DNS";
                            }
                            call->deleteLater();
                        });
            });
        };
        QHostInfo::lookupHost(site, this, cbResolv);
    }
#endif
}

QSharedPointer<VpnProtocol> VpnConnection::vpnProtocol() const
{
    return m_vpnProtocol;
}

void VpnConnection::disconnectSlots()
{
    if (m_vpnProtocol) {
        m_vpnProtocol->disconnect();
    }
}

ErrorCode VpnConnection::lastError() const
{
#ifdef Q_OS_ANDROID
    return ErrorCode::AndroidError;
#endif

    if (m_vpnProtocol.isNull()) {
        return ErrorCode::InternalError;
    }

    return m_vpnProtocol.data()->lastError();
}

Vpn::ConnectionState VpnConnection::connectionState() const
{
    return m_connectionState;
}

void VpnConnection::connectToVpn(const QString &serverId, DockerContainer container, const QJsonObject &vpnConfiguration)
{
    if (m_managedBackend && (m_managedBackend->ticket.valid() || m_managedBackend->protocol)) return; // managed owner must drain first
    if (!m_appSettingsRepository || !m_serversRepository) {
        qCritical() << "VpnConnection::connectToVpn: repositories not initialized";
        setConnectionState(Vpn::ConnectionState::Error);
        return;
    }

    qDebug() << QString("Trying to connect to VPN, server id is %1, container is %2, route mode is")
                        .arg(serverId)
                        .arg(ContainerUtils::containerToString(container))
             << m_appSettingsRepository->routeMode();

    m_remoteAddress = NetworkUtilities::getIPAddress(vpnConfiguration.value(configKey::hostName).toString());
    setConnectionState(Vpn::ConnectionState::Connecting);

    m_vpnConfiguration = vpnConfiguration;

#ifdef AMNEZIA_DESKTOP
    if (m_vpnProtocol) {
        disconnect(m_vpnProtocol.data(), &VpnProtocol::protocolError, this, &VpnConnection::vpnProtocolError);
        m_vpnProtocol->stop();
        m_vpnProtocol.reset();
    }
    appendKillSwitchConfig();
#endif

    appendSplitTunnelingConfig();

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    m_vpnProtocol.reset(VpnProtocol::factory(container, m_vpnConfiguration));
    if (!m_vpnProtocol) {
        setConnectionState(Vpn::ConnectionState::Error);
        return;
    }
    m_vpnProtocol->prepare();
#elif defined Q_OS_ANDROID
    androidVpnProtocol = createDefaultAndroidVpnProtocol();
    createAndroidConnections();

    m_vpnProtocol.reset(androidVpnProtocol);
#elif defined Q_OS_IOS || defined(MACOS_NE)
    Proto proto = ContainerUtils::defaultProtocol(container);
    IosController::Instance()->connectVpn(proto, m_vpnConfiguration);
    connect(&m_checkTimer, &QTimer::timeout, IosController::Instance(), &IosController::checkStatus);
    return;
#endif

    createProtocolConnections();

    if (ErrorCode err = m_vpnProtocol->start(); err != ErrorCode::NoError) {
        setConnectionState(Vpn::ConnectionState::Error);
        emit vpnProtocolError(err);
    }
}

void VpnConnection::createProtocolConnections()
{
    connect(m_vpnProtocol.data(), &VpnProtocol::protocolError, this, &VpnConnection::vpnProtocolError);
    connect(m_vpnProtocol.data(), &VpnProtocol::connectionStateChanged, this, &VpnConnection::setConnectionState);
    connect(m_vpnProtocol.data(), SIGNAL(bytesChanged(quint64, quint64)), this, SLOT(onBytesChanged(quint64, quint64)));
#ifdef AMNEZIA_DESKTOP
    if (auto* wireguard = qobject_cast<WireguardProtocol*>(m_vpnProtocol.data())) {
        connect(wireguard, &WireguardProtocol::awgTunnelHealthUpdated,
                this, &VpnConnection::onAwgTunnelHealth);
    }
#endif

#ifdef AMNEZIA_DESKTOP
    IpcClient::withInterface([this](QSharedPointer<IpcInterfaceReplica> rep) {
        connect(rep.data(), &IpcInterfaceReplica::networkChanged, this, &VpnConnection::reconnectToVpn, Qt::QueuedConnection);
        connect(rep.data(), &IpcInterfaceReplica::wakeup, this, &VpnConnection::reconnectToVpn, Qt::QueuedConnection);
    });
#endif
}

void VpnConnection::appendKillSwitchConfig()
{
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::appendKillSwitchConfig: repositories not initialized";
        return;
    }

    m_vpnConfiguration.insert(configKey::killSwitchOption, QVariant(m_appSettingsRepository->isKillSwitchEnabled()).toString());
    m_vpnConfiguration.insert(configKey::allowedDnsServers, QVariant(m_appSettingsRepository->getAllowedDnsServers()).toJsonValue());
}

void VpnConnection::appendSplitTunnelingConfig()
{
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::appendSplitTunnelingConfig: repositories not initialized";
        return;
    }

    bool allowSiteBasedSplitTunneling = true;

    // this block is for old native configs and for old self-hosted configs
    auto protocolName = m_vpnConfiguration.value(configKey::vpnProto).toString();
    if (protocolName == ProtocolUtils::protoToString(Proto::Awg) || protocolName == ProtocolUtils::protoToString(Proto::WireGuard)) {
        allowSiteBasedSplitTunneling = false;
        auto configData = m_vpnConfiguration.value(protocolName + "_config_data").toObject();
        if (configData.value(configKey::allowedIps).isString()) {
            QJsonArray allowedIpsJsonArray = QJsonArray::fromStringList(configData.value(configKey::allowedIps).toString().split(", "));
            configData.insert(configKey::allowedIps, allowedIpsJsonArray);
            m_vpnConfiguration.insert(protocolName + "_config_data", configData);
        } else if (configData.value(configKey::allowedIps).isUndefined()) {
            auto nativeConfig = configData.value(configKey::config).toString();
            auto nativeConfigLines = nativeConfig.split("\n");
            for (auto &line : nativeConfigLines) {
                auto allowedIpsString = line.split("=", Qt::KeepEmptyParts);
                if (allowedIpsString.size() >= 2 && allowedIpsString.first().trimmed() == QStringLiteral("AllowedIPs")) {
                    QJsonArray allowedIpsJsonArray;
                    const QString allowedIps = allowedIpsString.mid(1).join(QStringLiteral("=")).trimmed();
                    for (const QString &allowedIp : allowedIps.split(",", Qt::SkipEmptyParts)) {
                        allowedIpsJsonArray.append(allowedIp.trimmed());
                    }
                    configData.insert(configKey::allowedIps, allowedIpsJsonArray);
                    m_vpnConfiguration.insert(protocolName + "_config_data", configData);
                    break;
                }
            }
        }

        if (configData.value(configKey::persistentKeepAlive).isUndefined()) {
            auto nativeConfig = configData.value(configKey::config).toString();
            auto nativeConfigLines = nativeConfig.split("\n");
            for (auto &line : nativeConfigLines) {
                auto persistentKeepaliveString = line.split("=", Qt::KeepEmptyParts);
                if (persistentKeepaliveString.size() >= 2
                        && persistentKeepaliveString.first().trimmed() == QStringLiteral("PersistentKeepalive")) {
                    configData.insert(configKey::persistentKeepAlive,
                                      persistentKeepaliveString.mid(1).join(QStringLiteral("=")).trimmed());
                    m_vpnConfiguration.insert(protocolName + "_config_data", configData);
                    break;
                }
            }
        }

        QJsonArray allowedIpsJsonArray = configData.value(configKey::allowedIps).toArray();
        if (allowedIpsJsonArray.contains("0.0.0.0/0") && allowedIpsJsonArray.contains("::/0")) {
            allowSiteBasedSplitTunneling = true;
        }
    }

    amnezia::RouteMode routeMode = amnezia::RouteMode::VpnAllSites;
    QJsonArray sitesJsonArray;
    if (m_appSettingsRepository->isSitesSplitTunnelingEnabled()) {
        routeMode = m_appSettingsRepository->routeMode();

        if (allowSiteBasedSplitTunneling) {
            QStringList sites;
            const QVariantMap &m = m_appSettingsRepository->vpnSites(routeMode);
            for (auto i = m.constBegin(); i != m.constEnd(); ++i) {
                if (NetworkUtilities::checkIpSubnetFormat(i.key())) {
                    sites.append(i.key());
                } else {
                    const QStringList siteIps = SecureAppSettingsRepository::siteIpList(i.value());
                    for (const QString &ip : siteIps) {
                        if (NetworkUtilities::checkIpSubnetFormat(ip)) {
                            sites.append(ip);
                        }
                    }
                }
            }
            sites.removeDuplicates();
            for (const auto &site : sites) {
                sitesJsonArray.append(site);
            }

            if (sitesJsonArray.isEmpty()) {
                routeMode = amnezia::RouteMode::VpnAllSites;
            } else if (routeMode == amnezia::RouteMode::VpnOnlyForwardSites) {
                // Allow traffic to Amnezia DNS
                sitesJsonArray.append(m_vpnConfiguration.value(configKey::dns1).toString());
                sitesJsonArray.append(m_vpnConfiguration.value(configKey::dns2).toString());
            }
        }
    }

    m_vpnConfiguration.insert(configKey::splitTunnelType, routeMode);
    m_vpnConfiguration.insert(configKey::splitTunnelSites, sitesJsonArray);

    amnezia::AppsRouteMode appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
    QJsonArray appsJsonArray;
    if (m_appSettingsRepository->isAppsSplitTunnelingEnabled()) {
        appsRouteMode = m_appSettingsRepository->appsRouteMode();

        auto apps = m_appSettingsRepository->vpnApps(appsRouteMode);
        for (const auto &app : apps) {
            appsJsonArray.append(app.appPath.isEmpty() ? app.packageName : app.appPath);
        }

        if (appsJsonArray.isEmpty()) {
            appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
        }
    }

    m_vpnConfiguration.insert(configKey::appSplitTunnelType, appsRouteMode);
    m_vpnConfiguration.insert(configKey::splitTunnelApps, appsJsonArray);

    qDebug() << QString("Site split tunneling is %1, route mode is %2")
                        .arg(m_appSettingsRepository->isSitesSplitTunnelingEnabled() ? "enabled" : "disabled")
                        .arg(routeMode);
    qDebug() << QString("App split tunneling is %1, route mode is %2")
                        .arg(m_appSettingsRepository->isAppsSplitTunnelingEnabled() ? "enabled" : "disabled")
                        .arg(appsRouteMode);
}

#ifdef Q_OS_ANDROID
void VpnConnection::restoreConnection()
{
    createAndroidConnections();

    m_vpnProtocol.reset(androidVpnProtocol);

    createProtocolConnections();
}

void VpnConnection::createAndroidConnections()
{
    androidVpnProtocol = createDefaultAndroidVpnProtocol();

    connect(AndroidController::instance(), &AndroidController::connectionStateChanged, androidVpnProtocol,
            &AndroidVpnProtocol::setConnectionState);
    connect(AndroidController::instance(), &AndroidController::statisticsUpdated, androidVpnProtocol, &AndroidVpnProtocol::setBytesChanged);
    connect(AndroidController::instance(), &AndroidController::awgTunnelHealthUpdated,
            this, &VpnConnection::onAwgTunnelHealth, Qt::UniqueConnection);
}

AndroidVpnProtocol *VpnConnection::createDefaultAndroidVpnProtocol()
{
    return new AndroidVpnProtocol(m_vpnConfiguration);
}
#endif

AwgHealthContext VpnConnection::expectedAwgHealthContext() const
{
#ifdef Q_OS_ANDROID
    return AndroidController::instance()->expectedAwgHealthContext();
#elif defined(AMNEZIA_DESKTOP)
    if (auto* protocol = qobject_cast<WireguardProtocol*>(m_vpnProtocol.data()))
        return protocol->expectedAwgHealthContext();
#endif
    return {};
}

void VpnConnection::onAwgTunnelHealth(const AwgTunnelHealth& health)
{
    Q_ASSERT(QThread::currentThread() == thread());
    // Recheck at final delivery: a queued sample may outlive its source activation.
    if (m_connectionState != Vpn::ConnectionState::Connecting &&
        m_connectionState != Vpn::ConnectionState::Connected) return;
    if (!expectedAwgHealthContext().matches(health)) return;
    emit awgTunnelHealthUpdated(health);
}

QString VpnConnection::bytesPerSecToText(quint64 bytes)
{
    double mbps = bytes * 8 / 1e6;
    return QString("%1 %2").arg(QString::number(mbps, 'f', 2)).arg(tr("Mbps")); // Mbit/s
}

void VpnConnection::reconnectToVpn() {
    if (m_managedBackend && (m_managedBackend->ticket.valid() || m_managedBackend->protocol)) return; // no autonomous trusted activation
    if (m_vpnProtocol.isNull())
        return;

    if (m_connectionState != Vpn::ConnectionState::Connected) {
        qWarning() << QString("Reconnect triggered on %1 during inappropriate state: %2; ignoring slot")
                              .arg(QMetaEnum::fromType<Vpn::ConnectionState>().valueToKey(m_connectionState));
        return;
    }

    qDebug() << "Reconnect triggered. Reconnecting to the server";

    setConnectionState(Vpn::ConnectionState::Reconnecting);

    m_vpnProtocol->stop();
    if (ErrorCode err = m_vpnProtocol->start(); err != ErrorCode::NoError) {
        setConnectionState(Vpn::ConnectionState::Error);
        emit vpnProtocolError(err);
    }
}

void VpnConnection::disconnectFromVpn()
{
    if (m_managedBackend && (m_managedBackend->ticket.valid() || m_managedBackend->protocol)) return; // managed stop retains protocol until exact ACK
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    // iOS/macOS NE use IosController directly; m_vpnProtocol is not set there.
    IosController::Instance()->disconnectVpn();
    disconnect(&m_checkTimer, &QTimer::timeout, IosController::Instance(), &IosController::checkStatus);
#endif

    if (m_vpnProtocol.isNull()) {
        setConnectionState(Vpn::ConnectionState::Disconnected);
        return;
    }

    setConnectionState(Vpn::ConnectionState::Disconnecting);

#ifdef Q_OS_ANDROID
    auto *const connection = new QMetaObject::Connection;
    *connection = connect(AndroidController::instance(), &AndroidController::vpnStateChanged, this,
                          [this, connection](AndroidController::ConnectionState state) {
                              if (state == AndroidController::ConnectionState::DISCONNECTED) {
                                  setConnectionState(Vpn::ConnectionState::Disconnected);
                                  disconnect(*connection);
                                  delete connection;
                              }
                          });
#endif

    m_vpnProtocol->stop();

#if !defined(Q_OS_ANDROID) && !defined(AMNEZIA_DESKTOP)
    m_vpnProtocol->deleteLater();
#endif

    m_vpnProtocol = nullptr;
}

void VpnConnection::setConnectionState(Vpn::ConnectionState state) {
    onConnectionStateChanged(state);

    if (state == Vpn::Disconnected && m_connectionState == Vpn::Reconnecting)
        return;

    m_connectionState = state;
    emit connectionStateChanged(state);
}

// Tagged managed lifecycle. Prepared configuration is already complete on GUI;
// this path does not access either repository or legacy route/state callbacks.
MayakBackendBridge::Port VpnConnection::managedBackendPort() {
    using B = MayakBackendBridge;
    const QPointer<VpnConnection> self(this);
#ifdef Q_OS_ANDROID
    const QPointer<AndroidController> android(AndroidController::instance());
#endif
    B::Port port;
    port.owner = this;
    port.preparePermissions = [
#ifdef Q_OS_ANDROID
        android
#endif
    ](QString requestId, B::PermissionDone done) mutable {
#ifdef Q_OS_ANDROID
        if (!android) { if (done) done(requestId, B::PermissionResult::Unavailable); return; }
        android->prepareManagedPermissions(requestId, [done = std::move(done)](const QString &id,
                                      AndroidController::ManagedPermissionResult result) mutable {
            if (!done) return;
            const auto mapped = result == AndroidController::ManagedPermissionResult::Ready ? B::PermissionResult::Ready :
                result == AndroidController::ManagedPermissionResult::Denied ? B::PermissionResult::Denied : B::PermissionResult::Unavailable;
            done(id, mapped);
        });
#else
        if (done) done(requestId, B::PermissionResult::Ready);
#endif
    };
    port.cancelPermissionPreparation = [
#ifdef Q_OS_ANDROID
        android
#endif
    ](QString requestId) {
#ifdef Q_OS_ANDROID
        if (android) android->cancelManagedPermissionPreparation(requestId);
#else
        Q_UNUSED(requestId);
#endif
    };
    port.observe = [self](QObject* receiver, std::function<void(B::Ticket, AwgTunnelHealth)> health, B::Done event) {
        if (!self) return;
        Q_ASSERT(QThread::currentThread() == self->thread());
        if (!self->m_managedBackend) self->m_managedBackend = std::make_shared<ManagedBackend>();
        const auto s = self->m_managedBackend;
        const QPointer<QObject> target(receiver);
        s->health = [target, health](B::Ticket t, AwgTunnelHealth h) { if (target && health) health(t, h); };
        s->event = [target, event](B::Result r) { if (target && event) event(r); };
    };
    port.start = [self
#ifdef Q_OS_ANDROID
        , android
#endif
    ](B::Ticket t, QString serverId, QJsonObject config, B::Millis deadline, B::Done done) {
        Q_UNUSED(serverId);
        if (!self) return;
        Q_ASSERT(QThread::currentThread() == self->thread());
        if (!self->m_managedBackend) self->m_managedBackend = std::make_shared<ManagedBackend>();
        const auto s = self->m_managedBackend;
        if (s->ticket.valid() || self->m_vpnProtocol || !t.valid()) { done({t, B::Outcome::Busy}); return; }
        if (B::monotonicMillis() >= deadline) t.gate->cancel();
        if (t.gate->state.load() != B::StartGate::Pending) { done({t, B::Outcome::Cancelled}); return; }
        const QString proto = config.value("protocol").toString();
        if (proto != "awg" && proto != "wireguard") { done({t, B::Outcome::Failed, {}, {}, QStringLiteral("AWG required")}); return; }
        s->ticket = t;
#ifdef AMNEZIA_DESKTOP
        // Existing AWG protocol wrapper, never a second backend implementation.
        auto* wg = new WireguardProtocol(config);
        wg->useManagedLifecycle();
        s->protocol.reset(wg);
        const std::weak_ptr<ManagedBackend> weak = s;
        connect(wg, &WireguardProtocol::awgTunnelHealthUpdated, self, [self, weak](const AwgTunnelHealth& h) {
            const auto s = weak.lock();
            if (!self || !s || !s->expected.matches(h)) return;
            if (s->health) s->health(s->ticket, h);
        });
        connect(wg, &VpnProtocol::protocolError, self, [self, weak](ErrorCode) {
            const auto s = weak.lock();
            if (self && s && s->event) s->event({s->ticket, B::Outcome::Failed, s->expected});
        });
        // This check is the linearization point immediately before native start.
        if (B::monotonicMillis() >= deadline || !t.gate->commit()) {
            t.gate->cancel(); s->protocol.reset(); s->ticket = {};
            done({t, B::Outcome::Cancelled}); return;
        }
        const ErrorCode err = wg->start();
        s->expected = wg->expectedAwgHealthContext(); // VPN owner thread only
        done({t, err == ErrorCode::NoError ? B::Outcome::Started : B::Outcome::Failed, s->expected});
#elif defined(Q_OS_ANDROID)
        if (!android) { done({t, B::Outcome::Unknown}); return; }
        QMetaObject::invokeMethod(android, [self, android, s, t, config, deadline, done] {
            if (!android || B::monotonicMillis() >= deadline || !t.gate->commit()) {
                t.gate->cancel();
                if (self) QMetaObject::invokeMethod(self, [done,t] { done({t,B::Outcome::Cancelled}); }, Qt::QueuedConnection);
                return;
            }
            QJsonObject tagged = config;
            tagged.insert("managedTicket", t.opaqueAttempt);
            android->start(tagged);
            const AwgHealthContext expected = android->expectedAwgHealthContext();
            if (self) QMetaObject::invokeMethod(self, [self, s, t, expected, done] {
                if (!self || self->m_managedBackend != s || !s->ticket.same(t)) return;
                s->expected = expected;
                done({t,B::Outcome::Started,expected});
            }, Qt::QueuedConnection);
        }, Qt::QueuedConnection);
        connect(android, &AndroidController::managedDenied, self, [self,s,t](QString ticket, QString context) {
            if (!self || self->m_managedBackend != s || !s->ticket.same(t) || ticket != t.opaqueAttempt || context != s->expected.id) return;
            if (s->event) s->event({t,B::Outcome::Failed,s->expected,{},QStringLiteral("permissionDenied")});
        });
        connect(android, &AndroidController::awgTunnelHealthUpdated, self, [self,s,t](AwgTunnelHealth h) {
            if (self && self->m_managedBackend == s && s->ticket.same(t) && s->expected.matches(h) && s->health) s->health(t,h);
        });
#else
        done({t, B::Outcome::Unknown});
#endif
    };
    port.cancel = [self
#ifdef Q_OS_ANDROID
        , android
#endif
    ](B::Ticket t) {
        if (!self) return;
        Q_ASSERT(QThread::currentThread() == self->thread());
        const auto s = self->m_managedBackend;
        if (!s || !s->ticket.same(t)) return;
        if (s->probe) { s->probe->cancel(); s->probe->deleteLater(); s->probe = nullptr; }
#ifdef Q_OS_ANDROID
        if (android) QMetaObject::invokeMethod(android, [android,t] { if (android) android->cancelManaged(t.opaqueAttempt); }, Qt::QueuedConnection);
#endif
    };
    port.stop = [self
#ifdef Q_OS_ANDROID
        , android
#endif
    ](B::Ticket t, QString nonce, B::Millis deadline, B::Done done) {
        if (!self) return;
        Q_ASSERT(QThread::currentThread() == self->thread());
        auto s = self->m_managedBackend;
        B::Result result{t, B::Outcome::Unknown}; result.requestId = nonce;
        qInfo() << "MayakStopPort stage=entry ticket_valid=" << t.valid()
                << "owner_present=" << bool(s) << "gate_state="
                << (t.valid() ? int(t.gate->state.load()) : -1);
        // A canceled, never-committed ticket is Off by the shared linearization
        // gate. This is not a native/legacy disconnected assertion.
        if (t.valid() && t.gate->state.load() == B::StartGate::Cancelled && (!s || !s->ticket.valid() || s->ticket.same(t))) {
            if (s && s->ticket.same(t)) { s->ticket = {}; s->protocol.clear(); }
            result.outcome = B::Outcome::ConfirmedDown;
            qInfo() << "MayakStopPort result=confirmed_down reason=never_committed";
            done(result); return;
        }
        if (!s || !s->ticket.same(t)) {
            qInfo() << "MayakStopPort result=unknown reason=owner_or_ticket_mismatch";
            done(result); return;
        }
        result.expected = s->expected;
        const QString context = s->expected.id.isEmpty() ? s->inspectedIdentity : s->expected.id;
        const qint64 remainingMs = deadline - B::monotonicMillis();
        if (context.isEmpty() || remainingMs <= 0) {
            qInfo() << "MayakStopPort result=unknown context_present=" << !context.isEmpty()
                    << "remaining_ms=" << remainingMs;
            done(result); return;
        }
        qInfo() << "MayakStopPort stage=dispatch context_present=true remaining_ms=" << remainingMs;
        auto completed = std::make_shared<bool>(false);
        auto finish = [self,s,result,done,completed,deadline](QString request, QString actual, bool stopped) mutable {
            const bool requestMatch = request == result.requestId;
            const bool contextMatch = actual == (s->expected.id.isEmpty() ? s->inspectedIdentity : s->expected.id);
            const bool ownerMatch = self && self->m_managedBackend == s;
            const bool ticketMatch = ownerMatch && s->ticket.same(result.ticket);
            if (!requestMatch || !contextMatch || !ticketMatch) {
                qInfo() << "MayakStopPortAck accepted=false request_match=" << requestMatch
                        << "context_match=" << contextMatch << "owner_match=" << ownerMatch
                        << "ticket_match=" << ticketMatch;
                return;
            }
            qInfo() << "MayakStopPortAck accepted=true stopped=" << stopped
                    << "operation_pending=" << !*completed
                    << "remaining_ms=" << (deadline - B::monotonicMillis());
            result.outcome = stopped ? B::Outcome::ConfirmedDown : B::Outcome::Failed;
            // Retain until true ACK even if the bounded caller already expired.
            const auto retained = s->protocol;
            if (stopped) {
                s->expected = {};
                s->ticket = {}; s->inspectedIdentity.clear(); s->protocol.clear();
                if (s->event) s->event(result);
                if (!self) return;
            }
            if (!*completed) {
                *completed = true;
                if (B::monotonicMillis() >= deadline) result.outcome = B::Outcome::Deadline;
                qInfo() << "MayakStopPort result outcome=" << int(result.outcome)
                        << "remaining_ms=" << (deadline - B::monotonicMillis());
                done(result);
            }
        };
        QTimer::singleShot(int(qMax<qint64>(0, deadline-B::monotonicMillis())), self, [result,done,completed,deadline] () mutable {
            if (*completed) return; *completed = true; result.outcome = B::Outcome::Deadline;
            qInfo() << "MayakStopPortAck accepted=false reason=deadline outcome=" << int(result.outcome)
                    << "remaining_ms=" << (deadline - B::monotonicMillis());
            done(result);
        });
#ifdef AMNEZIA_DESKTOP
        auto* wg = qobject_cast<WireguardProtocol*>(s->protocol.data());
        if (!wg) { done(result); *completed = true; return; }
        connect(wg, &WireguardProtocol::managedStopped, self, finish);
        wg->managedDeactivate(nonce, context);
#elif defined(Q_OS_ANDROID)
        if (!android) return;
        connect(android, &AndroidController::managedStopped, self, finish);
        QMetaObject::invokeMethod(android, [android,nonce,context,t] { if (android) android->managedStop(nonce,context,t.opaqueAttempt); }, Qt::QueuedConnection);
#else
        done(result); *completed = true;
#endif
    };
    port.inspect = [self
#ifdef Q_OS_ANDROID
        , android
#endif
    ](QString nonce, B::Millis deadline, B::Inspected done) {
        if (!self) return;
        Q_ASSERT(QThread::currentThread() == self->thread());
        if (!self->m_managedBackend) self->m_managedBackend = std::make_shared<ManagedBackend>();
        const auto s = self->m_managedBackend;
        if (s->ticket.valid()) {
            s->ticket.gate->cancel();
            if (s->ticket.gate->state.load() == B::StartGate::Cancelled) {
                s->ticket = {}; s->expected = {}; s->protocol.clear();
            }
        }
        auto complete = std::make_shared<bool>(false);
        auto finish = [self,s,nonce,deadline,done,complete](QString request, QString state, QString identity) {
            if (!self || *complete || request != nonce) return;
            *complete = true;
            B::Inspection result{B::OwnState::Unknown,nonce,{}};
            if (B::monotonicMillis() < deadline && self->m_managedBackend == s) {
                if (state == "off" && !s->ticket.valid()) { result.state = B::OwnState::Off; s->ticket = {}; s->inspectedIdentity.clear(); s->protocol.clear(); }
                if (state == "active" && !identity.isEmpty()) {
                    result.state = B::OwnState::Active; result.ownControlIdentity = identity;
                    if (!s->ticket.valid()) {
                        s->ticket = {QStringLiteral("recovery:")+identity, std::make_shared<B::StartGate>()};
                        s->ticket.gate->commit(); s->inspectedIdentity = identity;
                    }
                    result.recoveryTicket = s->ticket;
                }
            }
            done(result);
        };
        QTimer::singleShot(int(qMax<qint64>(0, deadline-B::monotonicMillis())), self, [finish,nonce] { finish(nonce, "unknown", {}); });
#ifdef AMNEZIA_DESKTOP
        auto* wg = qobject_cast<WireguardProtocol*>(s->protocol.data());
        if (!wg) { wg = new WireguardProtocol(QJsonObject{}); s->protocol.reset(wg); }
        connect(wg, &WireguardProtocol::managedInspected, self, finish);
        wg->inspectOwnBackend(nonce);
#elif defined(Q_OS_ANDROID)
        if (!android) return;
        connect(android, &AndroidController::managedInspected, self, finish);
        QMetaObject::invokeMethod(android, [android,nonce] { if (android) android->managedInspect(nonce); }, Qt::QueuedConnection);
#else
        finish(nonce,"unknown",{});
#endif
    };
    port.probe = [self](B::Ticket t, MayakTunnelProbeRequest request, B::Millis deadline, B::Probed done) {
        if (!self) return;
        Q_ASSERT(QThread::currentThread() == self->thread());
        const auto s = self->m_managedBackend;
        if (!s || !s->ticket.same(t) || s->expected.id.isEmpty() || s->probe || request.attemptTag != t.opaqueAttempt) {
            done(t,false,{},QStringLiteral("invalid-current-ticket")); return;
        }
        auto* probe = new MayakTunnelProbe(self);
        s->probe = probe;
        request.deadlineMs = int(qMin<qint64>(request.deadlineMs,qMax<qint64>(0,deadline-B::monotonicMillis())));
        connect(probe,&MayakTunnelProbe::finished,self,[self,s,t,done,probe](quint64,bool ok,MayakTunnelProbeProof proof,QString error) {
            probe->deleteLater();
            if (!self || self->m_managedBackend != s || !s->ticket.same(t) || s->probe != probe) return;
            s->probe = nullptr;
            done(t,ok,proof,error);
        });
        probe->start(request);
    };
    return port;
}
