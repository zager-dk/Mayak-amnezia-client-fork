#include "vpnConnection.h"

#include <QDebug>
#include <QEventLoop>
#include <QFile>
#include <QHostInfo>
#include <QJsonDocument>
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
    #include <core/protocols/xrayProtocol.h>
    #include "core/controllers/mayakForeignVpn.h"
    #include <QLocalSocket>
    #include "core/utils/constants/protocolConstants.h"
    #include <QJsonDocument>
    #include <QNetworkInterface>
    #include <QRemoteObjectPendingCallWatcher>
#endif
#ifdef Q_OS_WIN
    #include <winsock2.h>
    #include <ws2ipdef.h>
    #include <iphlpapi.h>
    #include <netioapi.h>
    #include <tlhelp32.h>
#endif

#ifdef Q_OS_ANDROID
    #include "platforms/android/android_controller.h"
    #include <QGuiApplication>
    #include <QHostAddress>
    #include <QThread>

#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    #include "platforms/ios/ios_controller.h"
#endif

#include "core/utils/mayakSplitTunneling.h"
#include "core/utils/networkUtilities.h"
#include <QCoreApplication>
#include <QHash>
#include <functional>
#include <memory>
#include <QJsonArray>
#ifdef Q_OS_ANDROID
#include <QJniEnvironment>
#include <QJniObject>
#endif
#include "core/utils/serverConfigUtils.h"
#include "vpnConnection.h"

using namespace ProtocolUtils;

namespace {
// Identifiers the fork's app split list may use for this app.
QStringList mayakSelfAppIds()
{
#ifdef Q_OS_ANDROID
    const QJniObject context = QNativeInterface::QAndroidApplication::context();
    const QString package = context.isValid() ? context.callObjectMethod<jstring>("getPackageName").toString() : QString();
    return package.isEmpty() ? QStringList() : QStringList{package};
#else
    return {QCoreApplication::applicationFilePath()};
#endif
}

// «Россия напрямую» strategy. Route exclusion: Android 13+ (VpnService.Builder.excludeRoute)
// and Windows (daemon exclusion routes); older Android gets the complement as included routes.
bool mayakExcludeRoutesSupported()
{
#ifdef Q_OS_ANDROID
    return QJniObject::getStaticField<jint>("android/os/Build$VERSION", "SDK_INT") >= 33;
#else
    return true;
#endif
}

// Route budgets: the embedded list is coarsened (smallest Russian pieces dropped, they stay in
// the VPN) until the platform gets at most this many routes.
// Android (measured r14, 06.11.2026): every route lands in the VPN network's LinkProperties
// (~84 bytes each), which the system sends to every app with a network callback. 8 672 routes
// made it ~730 KB, overflowed binder (VPN service DeadSystemException, app ANR); 685 routes still
// lost a few ~97 KB callbacks to frozen apps. 400 keeps it near 35-40 KB.
// Windows: the daemon installs every exclusion route before the peer, each with a full routing
// table pass, inside an 8 s attempt (independent review 3): kept equally small until measured.
// Android 9-12 (no route exclusion) gets the complement, which the priority networks fragment:
// it does not fit 400 even at /8 (612), so it gets 700 (689 routes, the size measured fine in r16).
int mayakRussiaRouteBudget(bool excludeRoutes)
{
    return excludeRoutes ? 400 : 700;
}

#ifdef Q_OS_ANDROID
// An app removed after it was chosen for split tunneling makes VpnService.Builder throw
// (NameNotFoundException) and every connect fail: keep only installed packages.
void mayakDropUninstalledApps(QJsonObject &config)
{
    const QJsonArray apps = config.value(amnezia::configKey::splitTunnelApps).toArray();
    if (apps.isEmpty()) return;
    const QJniObject context = QNativeInterface::QAndroidApplication::context();
    const QJniObject pm = context.isValid()
        ? context.callObjectMethod("getPackageManager", "()Landroid/content/pm/PackageManager;") : QJniObject();
    if (!pm.isValid()) return;
    QJsonArray kept;
    for (const auto &v : apps) {
        QJniEnvironment env;
        const QJniObject info = pm.callObjectMethod("getApplicationInfo",
            "(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;",
            QJniObject::fromString(v.toString()).object<jstring>(), jint(0));
        const bool missing = env.checkAndClearExceptions() || !info.isValid();
        if (!missing) kept.append(v);
    }
    if (kept.size() == apps.size()) return;
    qInfo().noquote() << QStringLiteral("MayakNet event=split_apps_missing count=%1").arg(apps.size() - kept.size());
    config.insert(amnezia::configKey::splitTunnelApps, kept);
    if (kept.isEmpty()) config.insert(amnezia::configKey::appSplitTunnelType, 0);
}
#endif

// Desktop passes the app list as excluded apps in every mode; Android honours the mode.
bool mayakDesktopAppList()
{
#ifdef Q_OS_ANDROID
    return false;
#else
    return true;
#endif
}

// Resolves the probe's echo hosts to IPv4 (system DNS, before the new tunnel exists). Calls done
// exactly once on the context's thread, with the endpoints interleaved by host.
void resolveMayakProbeEndpoints(QObject *context, int timeoutMs,
                                std::function<void(QList<mayak::split::ProbeEndpoint>)> done)
{
    struct State {
        QStringList hosts;
        QHash<QString, QList<mayak::split::ProbeEndpoint>> byHost;
        int pending = 0;
        bool finished = false;
        std::function<void(QList<mayak::split::ProbeEndpoint>)> done;
    };
    auto st = std::make_shared<State>();
    st->hosts = MayakTunnelProbe::echoHosts();
    st->pending = int(st->hosts.size());
    st->done = std::move(done);
    auto finish = [st] {
        if (st->finished) return;
        st->finished = true;
        QList<mayak::split::ProbeEndpoint> out;
        for (int i = 0; i < 2; ++i)
            for (const auto &host : st->hosts)
                if (st->byHost.value(host).size() > i) out.append(st->byHost.value(host).at(i));
        qInfo().noquote() << QStringLiteral("MayakNet event=split_probe_resolve endpoints=%1").arg(out.size());
        if (st->done) st->done(out);
    };
    if (st->pending == 0 || timeoutMs <= 0) { QTimer::singleShot(0, context, finish); return; }
    QTimer::singleShot(timeoutMs, context, finish);
    for (const auto &host : st->hosts) {
        QHostInfo::lookupHost(host, context, [st, host, finish](const QHostInfo &info) {
            if (st->finished) return;
            for (const auto &address : info.addresses())
                if (address.protocol() == QAbstractSocket::IPv4Protocol)
                    st->byHost[host].append({host, address.toString()});
            if (--st->pending == 0) finish();
        });
    }
}
} // namespace

struct VpnConnection::ManagedBackend {
    MayakBackendBridge::Ticket ticket;
    AwgHealthContext expected;
    QSharedPointer<VpnProtocol> protocol;
    QPointer<MayakTunnelProbe> probe;
    QString inspectedIdentity;
    // Adoption handed this backend from `adoptedFrom` (recovery) to `ticket`. If the owner never
    // learned of the hand-over (cancelled/late reply), it still stops with the recovery ticket.
    MayakBackendBridge::Ticket adoptedFrom;
    // Split tunneling (sites): the echo endpoints routed through this backend's VPN.
    QList<mayak::split::ProbeEndpoint> probeEndpoints;
    quint64 endpointsGeneration = 0; // a late DNS answer of an older start/adopt must not overwrite
    std::function<void(MayakBackendBridge::Ticket, AwgTunnelHealth)> health;
    MayakBackendBridge::Done event;
    // Mayak Xray path: XrayProtocol backend; its health is its own tunnel interface (no peer).
    bool xray = false;
    QPointer<QTimer> xrayHealthTimer;
    qint64 raceToken = 0; // service xray engine token of the path race (no tunnel)
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
    appendSplitTunnelingConfig(m_vpnConfiguration);
}

void VpnConnection::appendSplitTunnelingConfig(QJsonObject &config) const
{
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::appendSplitTunnelingConfig: repositories not initialized";
        return;
    }

    bool allowSiteBasedSplitTunneling = true;

    // this block is for old native configs and for old self-hosted configs
    auto protocolName = config.value(configKey::vpnProto).toString();
    if (protocolName == ProtocolUtils::protoToString(Proto::Awg) || protocolName == ProtocolUtils::protoToString(Proto::WireGuard)) {
        allowSiteBasedSplitTunneling = false;
        auto configData = config.value(protocolName + "_config_data").toObject();
        if (configData.value(configKey::allowedIps).isString()) {
            QJsonArray allowedIpsJsonArray = QJsonArray::fromStringList(configData.value(configKey::allowedIps).toString().split(", "));
            configData.insert(configKey::allowedIps, allowedIpsJsonArray);
            config.insert(protocolName + "_config_data", configData);
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
                    config.insert(protocolName + "_config_data", configData);
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
                    config.insert(protocolName + "_config_data", configData);
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
                sitesJsonArray.append(config.value(configKey::dns1).toString());
                sitesJsonArray.append(config.value(configKey::dns2).toString());
            }
        }
    }

    config.insert(configKey::splitTunnelType, routeMode);
    config.insert(configKey::splitTunnelSites, sitesJsonArray);

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

    config.insert(configKey::appSplitTunnelType, appsRouteMode);
    config.insert(configKey::splitTunnelApps, appsJsonArray);

    qDebug() << QString("Site split tunneling is %1, route mode is %2")
                        .arg(m_appSettingsRepository->isSitesSplitTunnelingEnabled() ? "enabled" : "disabled")
                        .arg(routeMode);
    qDebug() << QString("App split tunneling is %1, route mode is %2")
                        .arg(m_appSettingsRepository->isAppsSplitTunnelingEnabled() ? "enabled" : "disabled")
                        .arg(appsRouteMode);
}

namespace {
QStringList siteListIps(const QVariantMap &sites)
{
    QStringList out;
    for (auto i = sites.constBegin(); i != sites.constEnd(); ++i) {
        if (NetworkUtilities::checkIpSubnetFormat(i.key())) { out.append(i.key()); continue; }
        for (const QString &ip : SecureAppSettingsRepository::siteIpList(i.value()))
            if (NetworkUtilities::checkIpSubnetFormat(ip)) out.append(ip);
    }
    return out;
}

struct EmbeddedRussia { mayak::split::Ipv4Ranges all, priority; };
const EmbeddedRussia &embeddedRussia()
{
    static const EmbeddedRussia list = [] {
        EmbeddedRussia r;
        QFile f(QStringLiteral(":/mayak/ru_ipv4.txt"));
        if (!f.open(QIODevice::ReadOnly)) { qWarning() << "MayakNet event=russia_list_missing"; return r; }
        r.all = mayak::split::parseIpv4List(f.readAll(), &r.priority);
        return r;
    }();
    return list;
}
} // namespace

bool VpnConnection::appendMayakRussiaDirectConfig(QJsonObject &config, bool excludeRoutes, int routeBudget) const
{
    if (!m_appSettingsRepository || !m_appSettingsRepository->isMayakRussiaDirectEnabled()) return false;
    mayak::split::RussiaDirectInput in;
    in.russia = embeddedRussia().all;
    in.priority = embeddedRussia().priority;
    // Exceptions reuse the fork's two site lists: "only these via VPN" = always via VPN,
    // "all except these" = always direct.
    in.direct = siteListIps(m_appSettingsRepository->vpnSites(amnezia::RouteMode::VpnAllExceptSites));
    in.viaVpn = siteListIps(m_appSettingsRepository->vpnSites(amnezia::RouteMode::VpnOnlyForwardSites));
    const int userViaVpn = int(in.viaVpn.size());
    // No DNS outside the VPN: the tunnel DNS, and on Windows also the adapters' own DNS servers
    // (Windows may query every adapter's resolver; a Russian ISP resolver must not become direct).
    in.viaVpn << config.value(amnezia::configKey::dns1).toString() << config.value(amnezia::configKey::dns2).toString();
    in.viaVpn << NetworkUtilities::systemDnsServersIpv4();
    in.excludeRoutes = excludeRoutes;
    in.routeBudget = routeBudget;
    const auto routes = mayak::split::russiaDirectRoutes(in);
    mayak::split::applyRussiaDirect(config, routes);
    qInfo().noquote() << QStringLiteral("MayakNet event=russia_direct exclude=%1 routes=%2 min_prefix=%3 over_budget=%4 priority_dropped=%7 exceptions_direct=%5 exceptions_vpn=%6")
        .arg(excludeRoutes ? 1 : 0).arg(routes.routes).arg(routes.minPrefix).arg(routes.overBudget ? 1 : 0)
        .arg(in.direct.size()).arg(userViaVpn).arg(routes.priorityDropped ? 1 : 0);
    return true;
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
        if (proto != "awg" && proto != "wireguard" && proto != "xray") { done({t, B::Outcome::Failed, {}, {}, QStringLiteral("AWG or Xray required")}); return; }
        if (s->raceToken) { done({t, B::Outcome::Busy}); return; } // the race engine is still running
        // Split tunneling: the fork's settings apply to Mayak sessions as well (they bypass
        // connectToVpn), with the Mayak invariants that keep the tunnel proof possible.
        self->appendSplitTunnelingConfig(config);
#ifdef Q_OS_ANDROID
        mayakDropUninstalledApps(config);
#endif
        const bool excludeRoutes = mayakExcludeRoutesSupported();
        self->appendMayakRussiaDirectConfig(config, excludeRoutes, mayakRussiaRouteBudget(excludeRoutes));
        const bool selfKept = mayak::split::keepSelfInTunnel(config, mayakSelfAppIds(), mayakDesktopAppList());
        const auto routing = mayak::split::sitesRouting(config);
        auto launch = [self, s, t, deadline, done, selfKept
#ifdef Q_OS_ANDROID
            , android
#endif
        ](QJsonObject config, QList<mayak::split::ProbeEndpoint> endpoints) {
        if (!self || self->m_managedBackend != s) { done({t, B::Outcome::Cancelled}); return; }
        if (s->ticket.valid() || self->m_vpnProtocol) { done({t, B::Outcome::Busy}); return; }
        if (B::monotonicMillis() >= deadline) t.gate->cancel();
        if (t.gate->state.load() != B::StartGate::Pending) { done({t, B::Outcome::Cancelled}); return; }
        qInfo().noquote() << QStringLiteral("MayakNet event=split_config sites_mode=%1 apps_mode=%2 self_kept=%3 probe_endpoints=%4")
            .arg(config.value(amnezia::configKey::splitTunnelType).toInt())
            .arg(config.value(amnezia::configKey::appSplitTunnelType).toInt())
            .arg(selfKept ? 1 : 0).arg(endpoints.size());
        s->ticket = t; s->adoptedFrom = {}; s->probeEndpoints = endpoints; ++s->endpointsGeneration;
#ifdef AMNEZIA_DESKTOP
        if (config.value("protocol").toString() == QStringLiteral("xray")) {
            self->launchMayakXray(s, t, config, deadline, done);
            return;
        }
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
        if (routing == mayak::split::SitesRouting::AllSites) { launch(config, {}); return; }
        // Site routing: the probe's echo hosts must be inside the VPN routes ("only listed")
        // or outside the exclusions ("all except"); the probe then uses exactly these addresses.
        const int budgetMs = int(qBound(qint64(0), qint64(deadline - B::monotonicMillis() - 3000), qint64(2500)));
        resolveMayakProbeEndpoints(self, budgetMs, [launch, config](QList<mayak::split::ProbeEndpoint> resolved) {
            QJsonObject routed = config;
            const auto endpoints = mayak::split::applyProbeRoutes(routed, resolved);
            launch(routed, endpoints);
        });
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
        // N1: the recovery ticket an adoption replaced still names this very backend.
        const bool viaAdoptedFrom = s && s->ticket.valid() && s->adoptedFrom.valid() && s->adoptedFrom.same(t);
        if (!s || (!s->ticket.same(t) && !viaAdoptedFrom)) {
            qInfo() << "MayakStopPort result=unknown reason=owner_or_ticket_mismatch";
            done(result); return;
        }
        if (viaAdoptedFrom) qInfo() << "MayakStopPort stage=adopted_from_recovery";
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
            const bool ticketMatch = ownerMatch && (s->ticket.same(result.ticket) ||
                (s->ticket.valid() && s->adoptedFrom.valid() && s->adoptedFrom.same(result.ticket)));
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
                s->ticket = {}; s->adoptedFrom = {}; s->inspectedIdentity.clear(); s->protocol.clear();
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
        if (s->xray) { self->stopMayakXray(s, finish, nonce, context, deadline); return; }
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
        if (s->xray) {
            // This process still runs a managed Xray path: it is the own backend to stop.
            finish(nonce, s->ticket.valid() ? QStringLiteral("active") : QStringLiteral("off"), s->expected.id);
            return;
        }
        if (!self->cleanupMayakXrayLeftover()) { finish(nonce, QStringLiteral("unknown"), {}); return; }
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
        request.pinnedEndpoints = s->probeEndpoints;
        // A managed proof is always bound to its interface with the exit's own egress.
        request.socksPort = 0; request.acceptAnyPublicEgress = false;
        request.deadlineMs = int(qMin<qint64>(request.deadlineMs,qMax<qint64>(0,deadline-B::monotonicMillis())));
        connect(probe,&MayakTunnelProbe::finished,self,[self,s,t,done,probe](quint64,bool ok,MayakTunnelProbeProof proof,QString error) {
            probe->deleteLater();
            if (!self || self->m_managedBackend != s || !s->ticket.same(t) || s->probe != probe) return;
            s->probe = nullptr;
            done(t,ok,proof,error);
        });
        probe->start(request);
    };
#ifdef AMNEZIA_DESKTOP
    // Xray path race: the service's xray engine with loopback SOCKS entries only (no TUN, no
    // routes). Never while a managed tunnel or a legacy connection runs.
    port.raceStart = [self](QString, QJsonObject config, B::Millis deadline, std::function<void(bool)> done) {
        if (!self) return;
        if (!self->m_managedBackend) self->m_managedBackend = std::make_shared<ManagedBackend>();
        const auto s = self->m_managedBackend;
        if (s->ticket.valid() || s->raceToken || self->m_vpnProtocol || B::monotonicMillis() >= deadline) { done(false); return; }
        const QString json = QString::fromUtf8(QJsonDocument(config).toJson(QJsonDocument::Compact));
        const qint64 token = IpcClient::withInterface([&json](QSharedPointer<IpcInterfaceReplica> iface) -> qint64 {
            auto start = iface->xrayStartOwned(json);
            return start.waitForFinished() ? start.returnValue() : 0;
        }, [] { return qint64(0); });
        s->raceToken = token;
        qInfo().noquote() << QStringLiteral("MayakNet event=race_engine_start ok=%1").arg(token ? 1 : 0);
        done(token != 0);
    };
    port.raceStop = [self](QString, B::Millis, std::function<void(bool)> done) {
        if (!self) return;
        const auto s = self->m_managedBackend;
        if (!s || !s->raceToken) { done(true); return; }
        const qint64 token = s->raceToken;
        const bool stopped = IpcClient::withInterface([token](QSharedPointer<IpcInterfaceReplica> iface) {
            auto stop = iface->xrayStopOwned(token);
            return stop.waitForFinished() && stop.returnValue();
        }, [] { return false; });
        // A later managed start replaces the service's single xray engine anyway: never let an
        // unconfirmed race stop block every following start of this process.
        s->raceToken = 0;
        qInfo().noquote() << QStringLiteral("MayakNet event=race_engine_stop ok=%1").arg(stopped ? 1 : 0);
        done(stopped);
    };
#endif
#ifdef Q_OS_ANDROID
    // Xray path race: xray in the app process with loopback SOCKS entries only (no VpnService).
    port.raceStart = [self](QString, QJsonObject config, B::Millis deadline, std::function<void(bool)> done) {
        if (!self) return;
        if (!self->m_managedBackend) self->m_managedBackend = std::make_shared<ManagedBackend>();
        const auto s = self->m_managedBackend;
        if (s->ticket.valid() || s->raceToken || B::monotonicMillis() >= deadline) { done(false); return; }
        const auto context = QNativeInterface::QAndroidApplication::context();
        const QString json = QString::fromUtf8(QJsonDocument(config).toJson(QJsonDocument::Compact));
        const bool ok = QJniObject::callStaticMethod<jboolean>("org/amnezia/vpn/protocol/xray/MayakXrayRace", "start",
            "(Landroid/content/Context;Ljava/lang/String;)Z", context.object<jobject>(), QJniObject::fromString(json).object<jstring>());
        QJniEnvironment env;
        if (env->ExceptionCheck()) { env->ExceptionClear(); done(false); return; }
        s->raceToken = ok ? 1 : 0;
        qInfo().noquote() << QStringLiteral("MayakNet event=race_engine_start ok=%1").arg(ok ? 1 : 0);
        done(ok);
    };
    port.raceStop = [self](QString, B::Millis, std::function<void(bool)> done) {
        if (!self) return;
        const auto s = self->m_managedBackend;
        if (!s || !s->raceToken) { done(true); return; }
        const auto context = QNativeInterface::QAndroidApplication::context();
        const bool ok = QJniObject::callStaticMethod<jboolean>("org/amnezia/vpn/protocol/xray/MayakXrayRace", "stop",
            "(Landroid/content/Context;)Z", context.object<jobject>());
        QJniEnvironment env;
        if (env->ExceptionCheck()) env->ExceptionClear();
        s->raceToken = 0; // MayakXrayRace.stop() always forgets the engine
        done(ok);
    };
    // Soft recovery: same ticket and proof context, new AWG backend transport.
    port.recover = [self, android](B::Ticket t, QString nonce, B::Millis deadline, B::Done done) {
        if (!self) return;
        Q_ASSERT(QThread::currentThread() == self->thread());
        const auto s = self->m_managedBackend;
        B::Result result{t, B::Outcome::Failed}; result.requestId = nonce;
        if (!android || !s || !s->ticket.same(t) || s->expected.id.isEmpty()) { done(result); return; }
        result.expected = s->expected;
        const QString context = s->expected.id;
        auto completed = std::make_shared<bool>(false);
        auto link = std::make_shared<QMetaObject::Connection>();
        *link = connect(android, &AndroidController::managedRecovered, self,
            [self, s, t, result, done, completed, link, context](QString request, QString actual, bool recovered) mutable {
            if (*completed || request != result.requestId || actual != context) return;
            *completed = true; QObject::disconnect(*link);
            const bool current = self && self->m_managedBackend == s && s->ticket.same(t);
            result.outcome = recovered && current ? B::Outcome::Started : B::Outcome::Failed;
            done(result);
        });
        QTimer::singleShot(int(qMax<qint64>(0, deadline - B::monotonicMillis())), self, [result, done, completed, link]() mutable {
            if (*completed) return;
            *completed = true; QObject::disconnect(*link);
            result.outcome = B::Outcome::Deadline;
            done(result);
        });
        QMetaObject::invokeMethod(android, [android, nonce, context, t] {
            if (android) android->managedRecover(nonce, context, t.opaqueAttempt);
        }, Qt::QueuedConnection);
    };
    port.observeNetwork = [self, android](QObject* receiver, std::function<void(B::Ticket, bool)> changed) {
        if (!self || !android) return;
        const QPointer<QObject> target(receiver);
        connect(android, &AndroidController::managedNetworkChanged, self, [self, target, changed](QString context, bool available) {
            if (!self || !target || !changed) return;
            const auto s = self->m_managedBackend;
            if (!s || !s->ticket.valid() || s->expected.id.isEmpty() || context != s->expected.id) return;
            changed(s->ticket, available);
        });
    };
    // Cold-start adoption: exchange the inspected recovery authority for the attempt's full
    // ticket once the service confirms identity+ticket (and soft-replaces the backend).
    port.adopt = [self, android](B::Ticket recovery, B::Ticket fresh, QString identity, QJsonObject config,
                                 QString nonce, B::Millis deadline, B::Done done) {
        if (!self) return;
        Q_ASSERT(QThread::currentThread() == self->thread());
        const auto s = self->m_managedBackend;
        B::Result result{fresh, B::Outcome::Failed}; result.requestId = nonce;
        if (!android || !s || !s->ticket.same(recovery) || s->inspectedIdentity.isEmpty() || s->inspectedIdentity != identity) {
            done(result); return;
        }
        // Expected own-peer context exactly as AndroidController::start derives it.
        const QString protocol = config.value("protocol").toString();
        const QJsonObject peer = config.value(protocol + "_config_data").toObject();
        QString host = peer.value("hostName").toString();
        QHostAddress numericHost;
        if (numericHost.setAddress(host)) host = numericHost.toString();
        const AwgHealthContext expected{identity,
            QString::fromLatin1(QByteArray::fromBase64(peer.value("server_pub_key").toString().toLatin1()).toHex()),
            AwgHealthContext::endpointForHost(host, peer.value("port").toInt())};
        if (expected.peerPublicKey.isEmpty() || expected.endpoint.isEmpty() || B::monotonicMillis() >= deadline) {
            done(result); return;
        }
        result.expected = expected;
        {
            // Split tunneling (sites): the live backend was routed when it started. Re-resolve the
            // echo hosts so the adoption proof uses addresses inside those routes; a proof that
            // runs first, or a changed DNS answer, fails and the runtime replaces the backend.
            QJsonObject routed = config;
            self->appendSplitTunnelingConfig(routed);
            const bool excludeRoutes = mayakExcludeRoutesSupported();
            self->appendMayakRussiaDirectConfig(routed, excludeRoutes, mayakRussiaRouteBudget(excludeRoutes));
            s->probeEndpoints.clear();
            const quint64 generation = ++s->endpointsGeneration;
            if (mayak::split::sitesRouting(routed) != mayak::split::SitesRouting::AllSites) {
                const int budgetMs = int(qBound(qint64(0), qint64(deadline - B::monotonicMillis()), qint64(2500)));
                resolveMayakProbeEndpoints(self, budgetMs, [self, s, routed, generation](QList<mayak::split::ProbeEndpoint> resolved) {
                    QJsonObject applied = routed;
                    const auto endpoints = mayak::split::applyProbeRoutes(applied, resolved);
                    if (self && self->m_managedBackend == s && s->endpointsGeneration == generation) s->probeEndpoints = endpoints;
                });
            }
        }
        auto completed = std::make_shared<bool>(false);
        auto link = std::make_shared<QMetaObject::Connection>();
        *link = connect(android, &AndroidController::managedAdopted, self,
            [self, s, recovery, fresh, expected, result, done, completed, link, nonce, deadline](QString request, QString context, bool adopted) mutable {
            if (*completed || request != nonce || context != expected.id) return;
            *completed = true; QObject::disconnect(*link);
            const bool current = self && self->m_managedBackend == s && s->ticket.same(recovery);
            if (adopted && current && B::monotonicMillis() < deadline && !fresh.gate->cancellationRequested.load()) {
                s->adoptedFrom = recovery; // N1: a cancel racing this reply may still stop by recovery
                s->ticket = fresh; s->expected = expected; // inspectedIdentity stays as stop-context fallback
                result.outcome = B::Outcome::Started;
            } else {
                result.outcome = adopted ? B::Outcome::Deadline : B::Outcome::Failed; // recovery stays the authority
            }
            done(result);
        });
        QTimer::singleShot(int(qMax<qint64>(0, deadline - B::monotonicMillis())), self, [result, done, completed, link]() mutable {
            if (*completed) return;
            *completed = true; QObject::disconnect(*link);
            result.outcome = B::Outcome::Deadline;
            done(result);
        });
        connect(android, &AndroidController::awgTunnelHealthUpdated, self, [self, s, fresh](AwgTunnelHealth h) {
            if (self && self->m_managedBackend == s && s->ticket.same(fresh) && s->expected.matches(h) && s->health) s->health(fresh, h);
        });
        connect(android, &AndroidController::managedDenied, self, [self, s, fresh](QString ticket, QString context) {
            if (!self || self->m_managedBackend != s || !s->ticket.same(fresh) || ticket != fresh.opaqueAttempt || context != s->expected.id) return;
            if (s->event) s->event({fresh, B::Outcome::Failed, s->expected, {}, QStringLiteral("permissionDenied")});
        });
        QMetaObject::invokeMethod(android, [android, nonce, expected, fresh] {
            if (android) android->managedAdopt(nonce, expected, fresh.opaqueAttempt);
        }, Qt::QueuedConnection);
    };
    port.observeUserStop = [self, android](QObject* receiver, std::function<void(B::Ticket)> stopped) {
        if (!self || !android) return;
        const QPointer<QObject> target(receiver);
        connect(android, &AndroidController::managedUserStopped, self, [self, target, stopped](QString context) {
            if (!self || !target || !stopped) return;
            const auto s = self->m_managedBackend;
            if (!s || !s->ticket.valid() || s->expected.id.isEmpty() || context != s->expected.id) return;
            stopped(s->ticket);
        });
    };
    port.observeResume = [self, android](QObject* receiver, std::function<void(B::Ticket, bool, bool)> resumed) {
        if (!self || !android) return;
        const QPointer<QObject> target(receiver);
        connect(android, &AndroidController::managedResumed, self,
            [self, target, resumed](QString context, bool replaced, bool available) {
            if (!self || !target || !resumed) return;
            const auto s = self->m_managedBackend;
            if (!s || !s->ticket.valid() || s->expected.id.isEmpty() || context != s->expected.id) return;
            resumed(s->ticket, replaced, available);
        });
    };
    port.observeFailover = [self, android](QObject* receiver, std::function<void(B::Ticket)> requested) {
        if (!self || !android) return;
        const QPointer<QObject> target(receiver);
        connect(android, &AndroidController::managedFailoverRequested, self, [self, target, requested](QString context) {
            if (!self || !target || !requested) return;
            const auto s = self->m_managedBackend;
            if (!s || !s->ticket.valid() || s->expected.id.isEmpty() || context != s->expected.id) return;
            requested(s->ticket);
        });
    };
    // Activity stopped (Qt reports Hidden/Suspended) = the service pauses health for this UI.
    port.observeVisibility = [self](QObject* receiver, std::function<void(bool)> changed) {
        auto* app = qobject_cast<QGuiApplication*>(QCoreApplication::instance());
        if (!self || !app || !changed) return;
        const QPointer<QObject> target(receiver);
        const auto visibleOf = [](Qt::ApplicationState s) {
            return s == Qt::ApplicationActive || s == Qt::ApplicationInactive;
        };
        connect(app, &QGuiApplication::applicationStateChanged, self, [target, changed, visibleOf](Qt::ApplicationState s) {
            if (target) changed(visibleOf(s));
        });
        changed(visibleOf(app->applicationState())); // a session may begin while hidden (background connect)
    };
#endif
    return port;
}


#ifdef AMNEZIA_DESKTOP
namespace {
constexpr char kMayakXrayTun[] = "tun2"; // XrayProtocol's interface (Windows/Linux)
// The Xray tunnel interface: the one owning XrayProtocol's local address.
bool mayakXrayInterface(QNetworkInterface *out) {
    for (const auto &iface : QNetworkInterface::allInterfaces())
        for (const auto &entry : iface.addressEntries())
            if (entry.ip().toString() == QLatin1String(amnezia::protocols::xray::defaultLocalAddr)) { if (out) *out = iface; return true; }
    return false;
}
void mayakInterfaceCounters(int index, quint64 *rx, quint64 *tx) {
    *rx = *tx = 0;
#ifdef Q_OS_WIN
    MIB_IF_ROW2 row{};
    row.InterfaceIndex = NET_IFINDEX(index);
    if (GetIfEntry2(&row) == NO_ERROR) { *rx = row.InOctets; *tx = row.OutOctets; }
#else
    Q_UNUSED(index);
#endif
}
// Another MayakVPN.exe (e.g. another Windows user's session) than this process is running.
bool mayakOtherAppRunning() {
#ifdef Q_OS_WIN
    const DWORD self = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return true; // unknown: do not touch the tunnel
    bool other = false;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    for (BOOL ok = Process32FirstW(snapshot, &entry); ok && !other; ok = Process32NextW(snapshot, &entry))
        other = _wcsicmp(entry.szExeFile, L"MayakVPN.exe") == 0 && entry.th32ProcessID != self;
    CloseHandle(snapshot);
    return other;
#else
    return false;
#endif
}
QString mayakXrayEndpoint(const QJsonObject &config) {
    const QJsonObject data = config.value(QStringLiteral("xray_config_data")).toObject();
    const QJsonObject client = QJsonDocument::fromJson(data.value(amnezia::configKey::config).toString().toUtf8()).object();
    const QJsonObject vnext = client.value("outbounds").toArray().first().toObject().value("settings").toObject()
                                  .value("vnext").toArray().first().toObject();
    QString host = vnext.value("address").toString();
    QHostAddress numeric;
    if (numeric.setAddress(host)) host = numeric.toString();
    const int port = vnext.value("port").toInt();
    return host.isEmpty() || port <= 0 ? QString() : AwgHealthContext::endpointForHost(host, port);
}
}

bool VpnConnection::cleanupMayakXrayLeftover()
{
    if (!mayakXrayInterface(nullptr)) return true;
    if (m_vpnProtocol) return true; // a live connection of this process owns the interface
    // Another Mayak app (another Windows user, same service) may own this live tunnel: never end it.
    if (mayakOtherAppRunning()) { qInfo().noquote() << QStringLiteral("MayakNet event=xray_leftover_skip reason=other_app"); return true; }
    qInfo().noquote() << QStringLiteral("MayakNet event=xray_leftover_cleanup");
    // The orphaned tun2socks keeps the adapter; only the service may end it (own executable only).
    const int ended = mayak::foreignvpn::stopXrayLeftoverBlocking(1500);
    qInfo().noquote() << QStringLiteral("MayakNet event=xray_leftover_tun2socks ended=%1").arg(ended);
    // 10.33.0.2 is also used by other Amnezia-based apps: the system-wide part of the cleanup
    // runs only when Mayak's own tun2socks was found and ended (the tunnel was ours).
    if (ended <= 0) return true;
    IpcClient::withInterface([](QSharedPointer<IpcInterfaceReplica> iface) {
        // As XrayProtocol::stop(): a kill switch of the ended tunnel must not outlive it.
        auto killSwitch = iface->disableKillSwitch(); killSwitch.waitForFinished();
        auto stop = iface->xrayStop(); stop.waitForFinished();
        auto tun = iface->deleteTun(QString::fromLatin1(kMayakXrayTun)); tun.waitForFinished();
        auto routes = iface->clearSavedRoutes(); routes.waitForFinished();
        auto dns = iface->restoreResolvers(); dns.waitForFinished();
        auto ipv6 = iface->StartRoutingIpv6(); ipv6.waitForFinished();
        return true;
    }, [] { return false; });
    // No waiting here: the result does not gate the inspection (its 3 s budget stays for AWG).
    const bool gone = !mayakXrayInterface(nullptr);
    qInfo().noquote() << QStringLiteral("MayakNet event=xray_leftover_cleanup_done gone=%1").arg(gone ? 1 : 0);
    // Never block the inspection on it: without engine, routes and DNS the adapter carries
    // nothing, AWG is unaffected, and an Xray path start fails cleanly to the next path.
    return true;
}

void VpnConnection::launchMayakXray(std::shared_ptr<ManagedBackend> s, MayakBackendBridge::Ticket t, QJsonObject config,
                                    qint64 deadline, MayakBackendBridge::Done done)
{
    using B = MayakBackendBridge;
    const QString endpoint = mayakXrayEndpoint(config);
    if (endpoint.isEmpty()) { s->ticket = {}; done({t, B::Outcome::Failed, {}, {}, QStringLiteral("xray endpoint")}); return; }
    // The site mode of the config (incl. «Россия напрямую») is applied below by routes, so the
    // fork's XrayProtocol must not add its own "all sites" routes: it sees the site mode.
    const int siteMode = config.value(amnezia::configKey::splitTunnelType).toInt();
    QStringList sites;
    for (const auto &v : config.value(amnezia::configKey::splitTunnelSites).toArray()) sites << v.toString();
    auto *xray = new XrayProtocol(config);
    s->protocol.reset(xray);
    s->xray = true;
    s->expected = AwgHealthContext{QStringLiteral("xray:") + t.opaqueAttempt, QStringLiteral("78726179"), endpoint};
    const AwgHealthContext expected = s->expected;
    const QString dns1 = config.value(amnezia::configKey::dns1).toString(), dns2 = config.value(amnezia::configKey::dns2).toString();
    auto settled = std::make_shared<bool>(false);
    const std::weak_ptr<ManagedBackend> weak = s;
    const QPointer<VpnConnection> self(this);
    auto report = [self, weak, t, expected, done, settled](B::Outcome outcome, const QString &detail) {
        if (*settled) return;
        *settled = true;
        qInfo().noquote() << QStringLiteral("MayakNet event=xray_backend_start outcome=%1 detail=%2").arg(int(outcome)).arg(detail);
        done({t, outcome, expected, {}, detail});
    };
    connect(xray, &VpnProtocol::connectionStateChanged, this, [self, weak, t, expected, report, siteMode, sites, dns1, dns2, xray](Vpn::ConnectionState state) {
        const auto s = weak.lock();
        if (!self || !s || s->protocol.data() != xray || !s->ticket.same(t)) return;
        if (state == Vpn::ConnectionState::Connected) {
            // Started only: tun2socks and routes are up. Never "connected" -- the owner proves it.
            const QString tunGw = xray->vpnGateway(), physGw = xray->routeGateway();
            const bool routed = IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
                auto add = [&iface](const QString &gw, const QStringList &ips) {
                    if (ips.isEmpty()) return 0;
                    auto call = iface->routeAddList(gw, ips);
                    return call.waitForFinished() ? call.returnValue() : -1;
                };
                QStringList dns; if (!dns1.isEmpty()) dns << dns1; if (!dns2.isEmpty()) dns << dns2;
                if (siteMode == amnezia::RouteMode::VpnAllExceptSites) {
                    if (add(tunGw, {QStringLiteral("0.0.0.0/1"), QStringLiteral("128.0.0.0/1")}) != 2) return false;
                    add(physGw, {expected.endpoint.section(':', 0, 0)});
                    const int direct = add(physGw, sites);
                    qInfo().noquote() << QStringLiteral("MayakNet event=xray_routes mode=except direct=%1/%2").arg(direct).arg(sites.size());
                } else if (siteMode == amnezia::RouteMode::VpnOnlyForwardSites) {
                    const int via = add(tunGw, sites);
                    add(tunGw, dns);
                    qInfo().noquote() << QStringLiteral("MayakNet event=xray_routes mode=only via=%1/%2").arg(via).arg(sites.size());
                    if (via <= 0) return false;
                }
                return true;
            }, [] { return false; });
            if (!routed) { report(B::Outcome::Failed, QStringLiteral("routes")); return; }
            // Health = this tunnel's interface identity and byte counters (no peer exists).
            auto *timer = new QTimer(self);
            timer->setInterval(1000);
            s->xrayHealthTimer = timer;
            auto generation = std::make_shared<quint64>(1);
            const auto tick = [self, weak, t, expected, timer] {
                const auto s = weak.lock();
                if (!self || !s || !s->xray || !s->ticket.same(t) || s->xrayHealthTimer != timer) { timer->deleteLater(); return; }
                QNetworkInterface iface;
                if (!mayakXrayInterface(&iface)) return;
                quint64 rx = 0, tx = 0;
                mayakInterfaceCounters(iface.index(), &rx, &tx);
                AwgTunnelHealth h;
                h.healthContextId = expected.id; h.generation = 1; h.peerPublicKey = expected.peerPublicKey; h.endpoint = expected.endpoint;
                h.localAddress = QString::fromLatin1(amnezia::protocols::xray::defaultLocalAddr) + QStringLiteral("/32");
                h.interfaceName = iface.name(); h.rxTotal = rx; h.txTotal = tx; h.valid = true;
                if (s->health) s->health(t, h);
            };
            QObject::connect(timer, &QTimer::timeout, self, tick);
            timer->start();
            QTimer::singleShot(0, timer, tick);
            report(B::Outcome::Started, QStringLiteral("tunnel_up"));
        } else if (state == Vpn::ConnectionState::Error || state == Vpn::ConnectionState::Disconnected) {
            report(B::Outcome::Failed, QStringLiteral("backend_down"));
            // A running path that died: the owner's monitor sees no health/probe and stops it.
            if (s->event && s->ticket.same(t)) s->event({t, B::Outcome::Failed, expected});
        }
    }, Qt::QueuedConnection);
    // This check is the linearization point immediately before native start.
    if (B::monotonicMillis() >= deadline || !t.gate->commit()) {
        t.gate->cancel(); s->protocol.reset(); s->ticket = {}; s->xray = false;
        report(B::Outcome::Cancelled, QStringLiteral("cancelled")); return;
    }
    QTimer::singleShot(int(qMax<qint64>(0, deadline - B::monotonicMillis())), this, [report] {
        report(B::Outcome::Failed, QStringLiteral("deadline"));
    });
    const ErrorCode err = xray->start();
    if (err != ErrorCode::NoError) report(B::Outcome::Failed, QStringLiteral("start_error_%1").arg(int(err)));
}

void VpnConnection::stopMayakXray(std::shared_ptr<ManagedBackend> s, std::function<void(QString, QString, bool)> finish,
                                  QString nonce, QString context, qint64 deadline)
{
    if (s->xrayHealthTimer) { s->xrayHealthTimer->stop(); s->xrayHealthTimer->deleteLater(); s->xrayHealthTimer.clear(); }
    auto *xray = dynamic_cast<XrayProtocol *>(s->protocol.data()); // XrayProtocol has no Q_OBJECT
    if (xray) {
        xray->blockSignals(true); // our own stop is not a backend failure
        xray->stop();             // synchronous: tun, resolvers, routes of the fork, engine, tun2socks
    }
    IpcClient::withInterface([](QSharedPointer<IpcInterfaceReplica> iface) {
        auto routes = iface->clearSavedRoutes(); // the site routes added by launchMayakXray
        return routes.waitForFinished() && routes.returnValue();
    }, [] { return false; });
    // Down = the tunnel interface is gone (bounded by the stop deadline).
    while (mayakXrayInterface(nullptr) && MayakBackendBridge::monotonicMillis() + 100 < deadline) QThread::msleep(100);
    const bool gone = !mayakXrayInterface(nullptr);
    qInfo().noquote() << QStringLiteral("MayakNet event=xray_backend_stop gone=%1").arg(gone ? 1 : 0);
    if (gone) s->xray = false;
    finish(nonce, context, gone);
}
#endif
