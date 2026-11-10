#include "connectionController.h"
#include "mayakAutoConnectRuntime.h"

#include <QJsonDocument>

#include "core/configurators/configuratorBase.h"
#include "core/utils/protocolEnum.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/payloadSender.h"
#include "core/utils/utilities.h"
#include "core/utils/serverConfigUtils.h"
#include "version.h"
#include "core/utils/containerEnum.h"
#include "core/utils/containers/containerUtils.h"
#include "core/utils/protocolEnum.h"
#include "core/models/containerConfig.h"
#include "core/models/protocolConfig.h"
#include "core/utils/mayakTunnelProbe.h"
#include "core/utils/networkUtilities.h"
#include "core/utils/constants/protocolConstants.h"
#include <QNetworkInterface>
#include <QTimer>
#include <QUuid>

using namespace amnezia;
using namespace ProtocolUtils;

ConnectionController::ConnectionController(SecureServersRepository* serversRepository,
                                         SecureAppSettingsRepository* appSettingsRepository,
                                         VpnConnection* vpnConnection,
                                         QObject* parent)
    : QObject(parent),
      m_serversRepository(serversRepository),
      m_appSettingsRepository(appSettingsRepository),
      m_vpnConnection(vpnConnection)
{
    if (!m_vpnConnection) return; // Injectable configuration-only test facade.
    connect(m_vpnConnection, &VpnConnection::connectionStateChanged, this, [this](Vpn::ConnectionState state) {
        if (!m_managedActive) legacyXrayState(state);
    });
    connect(this, &ConnectionController::openConnectionRequested, m_vpnConnection, &VpnConnection::connectToVpn, Qt::QueuedConnection);
    connect(this, &ConnectionController::closeConnectionRequested, m_vpnConnection, &VpnConnection::disconnectFromVpn, Qt::QueuedConnection);
    connect(this, &ConnectionController::killSwitchModeChangedRequested, m_vpnConnection, &VpnConnection::onKillSwitchModeChanged, Qt::QueuedConnection);
#ifdef Q_OS_ANDROID
    connect(this, &ConnectionController::restoreConnectionRequested, m_vpnConnection, &VpnConnection::restoreConnection, Qt::QueuedConnection);
#endif
}

bool ConnectionController::isConnected() const
{
    return m_effectiveState == Vpn::ConnectionState::Connected;
}

void ConnectionController::setConnectionState(Vpn::ConnectionState state)
{
    if (m_managedActive) return;
    m_effectiveState = state;
    emit connectionStateChanged(state);
}

void ConnectionController::setMayakRuntime(MayakAutoConnectRuntime* runtime)
{
    m_mayak = runtime;
    connect(runtime, &MayakAutoConnectRuntime::stateChanged, this, [this](Vpn::ConnectionState state, const QString&) {
        m_managedActive = true; m_effectiveState = state; emit connectionStateChanged(state);
    });
}
bool ConnectionController::isMayakManaged(const QString& id) const { return m_mayak && m_mayak->manages(id); }
QString ConnectionController::managedMessage() const { return m_managedActive && m_mayak ? m_mayak->message() : QString(); }
QString ConnectionController::managedConnectionPhase() const {
    return m_managedActive && m_mayak ? m_mayak->connectionPhase() : QStringLiteral("idle");
}
QVariantMap ConnectionController::managedExitLocation() const {
    return m_managedActive && m_mayak ? m_mayak->exitLocation() : QVariantMap{};
}
bool ConnectionController::managedCleanupPending() const { return m_managedActive && m_mayak && m_mayak->cleanupPending(); }
void ConnectionController::retryManagedCleanup() { if (managedCleanupPending()) m_mayak->retryCleanup(); }
bool ConnectionController::canInstallUpdate() const {
    return m_effectiveState == Vpn::ConnectionState::Disconnected && (!m_mayak || !m_mayak->busy());
}

ErrorCode ConnectionController::defaultContainerForServer(const QString &serverId, DockerContainer &container) const
{
    const auto kind = m_serversRepository->serverKind(serverId);
    switch (kind) {
    case serverConfigUtils::ConfigType::SelfHostedAdmin: {
        const auto cfg = m_serversRepository->selfHostedAdminConfig(serverId);
        if (!cfg.has_value()) {
            return ErrorCode::InternalError;
        }
        container = cfg->defaultContainer;
        return ErrorCode::NoError;
    }
    case serverConfigUtils::ConfigType::SelfHostedUser: {
        const auto cfg = m_serversRepository->selfHostedUserConfig(serverId);
        if (!cfg.has_value()) {
            return ErrorCode::InternalError;
        }
        container = cfg->defaultContainer;
        return ErrorCode::NoError;
    }
    case serverConfigUtils::ConfigType::Native: {
        const auto cfg = m_serversRepository->nativeConfig(serverId);
        if (!cfg.has_value()) {
            return ErrorCode::InternalError;
        }
        container = cfg->defaultContainer;
        return ErrorCode::NoError;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV2:
    case serverConfigUtils::ConfigType::AmneziaFreeV3:
    case serverConfigUtils::ConfigType::ExternalPremium: {
        const auto cfg = m_serversRepository->apiV2Config(serverId);
        if (!cfg.has_value()) {
            return ErrorCode::InternalError;
        }
        container = cfg->defaultContainer;
        return ErrorCode::NoError;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV1:
    case serverConfigUtils::ConfigType::AmneziaFreeV2:
        return ErrorCode::LegacyApiV1NotSupportedError;
    case serverConfigUtils::ConfigType::Invalid:
    default:
        return ErrorCode::InternalError;
    }
}

ErrorCode ConnectionController::isConnectionSupported(const QString &serverId) const
{
    if (serverId.isEmpty()) {
        return ErrorCode::InternalError;
    }

    if (!isServiceReady()) {
        return ErrorCode::AmneziaServiceNotRunning;
    }

    const serverConfigUtils::ConfigType kind = m_serversRepository->serverKind(serverId);
    if (serverConfigUtils::isLegacyApiSubscription(kind)) {
        return ErrorCode::LegacyApiV1NotSupportedError;
    }

    DockerContainer container = DockerContainer::None;
    const ErrorCode errorCode = defaultContainerForServer(serverId, container);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    if (container == DockerContainer::None) {
        if (serverConfigUtils::isApiV2Subscription(kind)) {
            return ErrorCode::NoError;
        }
        return ErrorCode::NoInstalledContainersError;
    }

    if (ContainerUtils::isUnsupportedContainer(container)) {
        return ErrorCode::LegacyContainerNotSupportedError;
    }

    if (!isContainerSupported(container)) {
        return ErrorCode::NotSupportedOnThisPlatform;
    }

    return ErrorCode::NoError;
}

ErrorCode ConnectionController::prepareConnection(const QString &serverId,
                                                 QJsonObject& vpnConfiguration,
                                                 DockerContainer& container)
{
    ContainerConfig containerConfigModel;
    QPair<QString, QString> dns;
    QString hostName;
    QString description;
    int configVersion = 0;
    bool isApiConfig = false;

    const auto kind = m_serversRepository->serverKind(serverId);
    const QString primaryDns = m_appSettingsRepository->primaryDns();
    const QString secondaryDns = m_appSettingsRepository->secondaryDns();
    switch (kind) {
    case serverConfigUtils::ConfigType::SelfHostedAdmin: {
        const auto cfg = m_serversRepository->selfHostedAdminConfig(serverId);
        if (!cfg.has_value()) return ErrorCode::InternalError;
        container = cfg->defaultContainer;
        containerConfigModel = cfg->containerConfig(container);
        dns = cfg->getDnsPair(m_appSettingsRepository->useAmneziaDns(), primaryDns, secondaryDns);
        hostName = cfg->hostName;
        description = cfg->description;
        break;
    }
    case serverConfigUtils::ConfigType::SelfHostedUser: {
        const auto cfg = m_serversRepository->selfHostedUserConfig(serverId);
        if (!cfg.has_value()) return ErrorCode::InternalError;
        container = cfg->defaultContainer;
        containerConfigModel = cfg->containerConfig(container);
        dns = cfg->getDnsPair(primaryDns, secondaryDns);
        hostName = cfg->hostName;
        description = cfg->description;
        break;
    }
    case serverConfigUtils::ConfigType::Native: {
        const auto cfg = m_serversRepository->nativeConfig(serverId);
        if (!cfg.has_value()) return ErrorCode::InternalError;
        container = cfg->defaultContainer;
        containerConfigModel = cfg->containerConfig(container);
        dns = cfg->getDnsPair(primaryDns, secondaryDns);
        hostName = cfg->hostName;
        description = cfg->description;
        break;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV2:
    case serverConfigUtils::ConfigType::AmneziaFreeV3:
    case serverConfigUtils::ConfigType::ExternalPremium: {
        const auto cfg = m_serversRepository->apiV2Config(serverId);
        if (!cfg.has_value()) return ErrorCode::InternalError;
        container = cfg->defaultContainer;
        containerConfigModel = cfg->containerConfig(container);
        dns = cfg->getDnsPair(primaryDns, secondaryDns);
        hostName = cfg->hostName;
        description = cfg->description;
        configVersion = serverConfigUtils::ConfigSource::AmneziaGateway;
        isApiConfig = true;
        break;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV1:
    case serverConfigUtils::ConfigType::AmneziaFreeV2:
        return ErrorCode::InternalError;
    case serverConfigUtils::ConfigType::Invalid:
    default:
        return ErrorCode::InternalError;
    }

    vpnConfiguration = createConnectionConfiguration(dns, isApiConfig, hostName, description, configVersion,
                                                     containerConfigModel, container);

    return ErrorCode::NoError;
}

ErrorCode ConnectionController::prepareMayakXrayConnection(const QString &serverId, const QJsonObject &xrayRoot,
                                                          QJsonObject &vpnConfiguration)
{
    const auto managed = m_serversRepository->apiV2Config(serverId);
    if (!managed.has_value()) return ErrorCode::InternalError;
    const ApiV2ServerConfig admitted = ApiV2ServerConfig::fromJson(xrayRoot);
    if (admitted.defaultContainer != DockerContainer::Xray || admitted.containers.size() != 1
        || !admitted.containers.contains(DockerContainer::Xray) || admitted.hostName.isEmpty())
        return ErrorCode::ApiConfigEmptyError;
    const QPair<QString, QString> dns = managed->getDnsPair(m_appSettingsRepository->primaryDns(),
                                                            m_appSettingsRepository->secondaryDns());
    vpnConfiguration = createConnectionConfiguration(dns, true, admitted.hostName, managed->description,
                                                     serverConfigUtils::ConfigSource::AmneziaGateway,
                                                     admitted.containerConfig(DockerContainer::Xray), DockerContainer::Xray);
    if (vpnConfiguration.isEmpty()) return ErrorCode::ApiConfigEmptyError;
    disableXrayAccessLog(vpnConfiguration);
    return ErrorCode::NoError;
}

void ConnectionController::disableXrayAccessLog(QJsonObject &vpnConfiguration)
{
    for (const QString key : {QStringLiteral("xray_config_data"), QStringLiteral("ssxray_config_data")}) {
        if (!vpnConfiguration.value(key).isObject()) continue;
        QJsonObject data = vpnConfiguration.value(key).toObject();
        QJsonObject client = QJsonDocument::fromJson(data.value(configKey::config).toString().toUtf8()).object();
        if (client.isEmpty()) continue;
        QJsonObject log = client.value(QStringLiteral("log")).toObject();
        log.insert(QStringLiteral("access"), QStringLiteral("none"));
        log.insert(QStringLiteral("dnsLog"), false);
        // info/debug also log destinations: never below "warning".
        const QString level = log.value(QStringLiteral("loglevel")).toString().toLower(); // xray ignores case
        if (level.isEmpty() || level == QStringLiteral("info") || level == QStringLiteral("debug"))
            log.insert(QStringLiteral("loglevel"), QStringLiteral("warning"));
        client.insert(QStringLiteral("log"), log);
        data.insert(configKey::config, QString::fromUtf8(QJsonDocument(client).toJson(QJsonDocument::Compact)));
        vpnConfiguration.insert(key, data);
    }
}

ErrorCode ConnectionController::openConnection(const QString &serverId)
{
    if (isMayakManaged(serverId)) { m_managedActive = true; m_mayak->begin(serverId); return ErrorCode::NoError; }
    if (m_mayak && m_mayak->busy()) return ErrorCode::InternalError;
    m_managedActive = false;
    QJsonObject vpnConfiguration;
    DockerContainer container;

    ErrorCode errorCode = prepareConnection(serverId, vpnConfiguration, container);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    const auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (apiV2.has_value() && !apiV2->sendPayload.isEmpty()) {
        PayloadSender::sendAll(apiV2->sendPayload);
    }

    ++m_legacyXrayGeneration; m_legacyXrayProven = false; m_legacyXrayEgress.clear();
    if (container == DockerContainer::Xray || container == DockerContainer::SSXray) {
        disableXrayAccessLog(vpnConfiguration); // rule 5 also for the user's own Xray configs
        // "Only listed sites via VPN": the echo hosts are not routed through the tunnel, so the
        // tunnel cannot be proven this way; the fork's behaviour is kept for that mode.
        const bool onlyListedSites = m_appSettingsRepository->isSitesSplitTunnelingEnabled() &&
            m_appSettingsRepository->routeMode() == amnezia::RouteMode::VpnOnlyForwardSites;
        if (!onlyListedSites) m_legacyXrayEgress = QStringLiteral("any");
    }
    emit openConnectionRequested(serverId, container, vpnConfiguration);
    return ErrorCode::NoError;
}

void ConnectionController::legacyXrayState(Vpn::ConnectionState state)
{
    if (state == Vpn::ConnectionState::Connected && !m_legacyXrayEgress.isEmpty() && !m_legacyXrayProven) {
        // Started, not proven: keep showing "Connecting" and prove the tunnel first.
        m_effectiveState = Vpn::ConnectionState::Connecting;
        emit connectionStateChanged(m_effectiveState);
        probeLegacyXray(++m_legacyXrayGeneration, 0);
        return;
    }
    if (state != Vpn::ConnectionState::Connected) { ++m_legacyXrayGeneration; m_legacyXrayProven = false; }
    m_effectiveState = state;
    emit connectionStateChanged(state);
}

void ConnectionController::probeLegacyXray(quint64 generation, int attempt)
{
    if (generation != m_legacyXrayGeneration || m_managedActive) return;
#ifdef Q_OS_ANDROID
    const QString local = QStringLiteral("10.0.42.2");        // Xray.kt VPN address
#else
    const QString local = QString::fromLatin1(amnezia::protocols::xray::defaultLocalAddr); // XrayProtocol tun
#endif
    QString name;
    for (const auto &iface : QNetworkInterface::allInterfaces())
        for (const auto &entry : iface.addressEntries())
            if (entry.ip().toString() == local) name = iface.name();
    auto retryOrFail = [this, generation, attempt] {
        if (generation != m_legacyXrayGeneration) return;
        if (attempt < 3) {
            QTimer::singleShot(4000, this, [this, generation, attempt] { probeLegacyXray(generation, attempt + 1); });
            return;
        }
        qWarning().noquote() << "MayakNet event=legacy_xray_unproven";
        ++m_legacyXrayGeneration;
        m_effectiveState = Vpn::ConnectionState::Error;
        emit connectionStateChanged(m_effectiveState);
        emit closeConnectionRequested(); // never leave an unproven tunnel looking like VPN
    };
    if (name.isEmpty()) { retryOrFail(); return; }
    auto *probe = new MayakTunnelProbe(this);
    MayakTunnelProbeRequest request;
    request.attemptTag = QStringLiteral("legacy-xray-%1").arg(generation);
    request.localAddress = QHostAddress(local);
    request.interfaceName = name;
    request.acceptAnyPublicEgress = true; // the user's own server: its egress is not known
    request.nonce = QUuid::createUuid().toString(QUuid::Id128);
    request.deadlineMs = 8000;
    connect(probe, &MayakTunnelProbe::finished, this, [this, probe, generation, retryOrFail](quint64, bool ok, MayakTunnelProbeProof, QString) {
        probe->deleteLater();
        if (generation != m_legacyXrayGeneration) return;
        if (!ok) { retryOrFail(); return; }
        qInfo().noquote() << "MayakNet event=legacy_xray_proven";
        m_legacyXrayProven = true;
        m_effectiveState = Vpn::ConnectionState::Connected;
        emit connectionStateChanged(m_effectiveState);
    });
    probe->start(request);
}

void ConnectionController::closeConnection()
{
    if (managedCleanupPending()) { retryManagedCleanup(); return; }
    if (m_managedActive && m_mayak) { m_mayak->cancel(); return; }
    if (m_vpnConnection) {
        emit closeConnectionRequested();
    }
}

#ifdef Q_OS_ANDROID
void ConnectionController::restoreConnection()
{
    if (m_vpnConnection) {
        emit restoreConnectionRequested();
    }
}
#endif

void ConnectionController::onKillSwitchModeChanged(bool enabled)
{
    if (m_vpnConnection) {
        emit killSwitchModeChangedRequested(enabled);
    }
}

ErrorCode ConnectionController::lastConnectionError() const
{
    if (m_managedActive) return ErrorCode::ApiConfigDownloadError;
    return m_vpnConnection->lastError();
}

QJsonObject ConnectionController::createConnectionConfiguration(const QPair<QString, QString> &dns,
                                                              bool isApiConfig,
                                                              const QString &hostName,
                                                              const QString &description,
                                                              int configVersion,
                                                              const ContainerConfig &containerConfig,
                                                              DockerContainer container)
{
    QJsonObject vpnConfiguration {};

    if (ContainerUtils::containerService(container) == ServiceType::Other) {
        return vpnConfiguration;
    }

    Proto proto = ContainerUtils::defaultProtocol(container);

    ConnectionSettings connectionSettings = {
        { dns.first, dns.second },
        isApiConfig,
        {
            m_appSettingsRepository->isSitesSplitTunnelingEnabled(),
            m_appSettingsRepository->routeMode()
        }
    };

    auto configurator = ConfiguratorBase::create(proto, nullptr);
    ProtocolConfig processedConfig = configurator->processConfigWithLocalSettings(connectionSettings,
                                                                                  containerConfig.protocolConfig);

    QJsonObject vpnConfigData = processedConfig.getClientConfigJson();
    if (ContainerUtils::isAwgContainer(container) || container == DockerContainer::WireGuard) {
        if (vpnConfigData[configKey::mtu].toString().isEmpty()) {
            vpnConfigData[configKey::mtu] =
                    ContainerUtils::isAwgContainer(container) ? protocols::awg::defaultMtu :
                    protocols::wireguard::defaultMtu;
        }
    }

    vpnConfiguration.insert(ProtocolUtils::key_proto_config_data(proto), vpnConfigData);
    vpnConfiguration[configKey::vpnProto] = ProtocolUtils::protoToString(proto);

    vpnConfiguration[configKey::dns1] = dns.first;
    vpnConfiguration[configKey::dns2] = dns.second;

    vpnConfiguration[configKey::hostName] = hostName;
    vpnConfiguration[configKey::description] = description;
    vpnConfiguration[configKey::configVersion] = configVersion;

    return vpnConfiguration;
}

bool ConnectionController::isServiceReady() const
{
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    return Utils::processIsRunning(Utils::executable(SERVICE_NAME, false), true);
#else
    return true;
#endif
}

bool ConnectionController::isContainerSupported(DockerContainer container) const
{
    return ContainerUtils::isSupportedByCurrentPlatform(container);
}
