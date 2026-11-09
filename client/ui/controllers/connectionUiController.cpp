#include "connectionUiController.h"

#include <QTimer>

#if defined(Q_OS_ANDROID) || defined(Q_OS_IOS) || defined(MACOS_NE)
    #include <QGuiApplication>
#else
    #include <QApplication>
#endif

#include "amneziaApplication.h"
#include "core/controllers/serversController.h"
#include "core/controllers/mayakForeignVpn.h"
#include "core/models/containerConfig.h"
#include "core/utils/containerEnum.h"

ConnectionUiController::ConnectionUiController(ConnectionController* connectionController,
                                                ServersController* serversController,
                                                QObject *parent)
    : QObject(parent),
      m_connectionController(connectionController),
      m_serversController(serversController)
{
    connect(m_connectionController, &ConnectionController::connectionStateChanged, this, &ConnectionUiController::onConnectionStateChanged);

    connect(this, &ConnectionUiController::connectButtonClicked, this, &ConnectionUiController::toggleConnection, Qt::QueuedConnection);

    m_state = Vpn::ConnectionState::Disconnected;
}

void ConnectionUiController::openConnection()
{
    const QString serverId = m_serversController->getDefaultServerId();
    if (serverId.isEmpty()) {
        m_connectionController->setConnectionState(Vpn::ConnectionState::Disconnected);
        return;
    }

    ErrorCode errorCode = m_connectionController->openConnection(serverId);

    if (errorCode != ErrorCode::NoError) {
        notifyConnectionBlocked(errorCode);
        return;
    }
}

void ConnectionUiController::closeConnection()
{
    m_connectionController->closeConnection();
}

ErrorCode ConnectionUiController::getLastConnectionError()
{
    return m_connectionController->lastConnectionError();
}

void ConnectionUiController::onConnectionStateChanged(Vpn::ConnectionState state)
{
    m_state = state;

    m_isConnected = false;
    m_connectionStateText = tr("Connecting...");
    switch (state) {
    case Vpn::ConnectionState::Connected: {
        amnApp->networkManager()->clearConnectionCache();

        m_isConnectionInProgress = false;
        m_isConnected = true;
        m_connectionStateText = tr("Connected");
        break;
    }
    case Vpn::ConnectionState::Connecting: {
        m_isConnectionInProgress = true;
        break;
    }
    case Vpn::ConnectionState::Reconnecting: {
        m_isConnectionInProgress = true;
        m_connectionStateText = tr("Reconnecting...");
        break;
    }
    case Vpn::ConnectionState::Disconnected: {
        m_isConnectionInProgress = false;
        m_connectionStateText = tr("Connect");
        break;
    }
    case Vpn::ConnectionState::Disconnecting: {
        m_isConnectionInProgress = true;
        m_connectionStateText = tr("Disconnecting...");
        break;
    }
    case Vpn::ConnectionState::Preparing: {
        m_isConnectionInProgress = true;
        m_connectionStateText = tr("Preparing...");
        break;
    }
    case Vpn::ConnectionState::Error: {
        m_isConnectionInProgress = false;
        m_connectionStateText = tr("Connect");
        // Managed connections already provide a precise inline failure. The
        // legacy lastError fallback is always API error1100 and is misleading.
        if (m_connectionController->managedMessage().isEmpty())
            emit connectionErrorOccurred(getLastConnectionError());
        break;
    }
    case Vpn::ConnectionState::Unknown: {
        m_isConnectionInProgress = false;
        m_connectionStateText = tr("Connect");
        if (m_connectionController->managedMessage().isEmpty())
            emit connectionErrorOccurred(getLastConnectionError());
        break;
    }
    }
    const auto managed = m_connectionController->managedMessage();
    if (!managed.isEmpty()) m_connectionStateText = managed;
    emit connectionStateChanged();
}

void ConnectionUiController::onTranslationsUpdated()
{
    onConnectionStateChanged(getCurrentConnectionState());
}

Vpn::ConnectionState ConnectionUiController::getCurrentConnectionState()
{
    return m_state;
}

QString ConnectionUiController::connectionStateText() const
{
    return m_connectionStateText;
}

QString ConnectionUiController::connectionPhase() const
{
    return m_connectionController->managedConnectionPhase();
}

bool ConnectionUiController::cleanupPending() const
{
    return m_connectionController->managedCleanupPending();
}

QVariantMap ConnectionUiController::exitLocation() const
{
    return m_connectionController->managedExitLocation();
}

void ConnectionUiController::toggleConnection()
{
    if (cleanupPending()) { closeConnection(); return; }
    if (m_state == Vpn::ConnectionState::Preparing) {
        if (m_connectionController->isMayakActive()) { closeConnection(); return; }
        emit preparingConfig();
        return;
    }

    if (isConnectionInProgress()) {
        closeConnection();
    } else if (isConnected()) {
        closeConnection();
    } else {
        const QString serverId = m_serversController->getDefaultServerId();
        if (serverId.isEmpty()) {
            return;
        }

        if (m_connectionController->isMayakManaged(serverId)) {
            if (m_foreignStopInFlight) return;
            // Windows lets several VPNs run at once; a second tunnel that captures all traffic
            // can keep Mayak from connecting. Ask the user first (Mayak never stops it silently).
            const auto foreign = mayak::foreignvpn::detect();
            if (foreign.found()) {
                m_foreignProgram = foreign.program;
                qInfo().noquote() << QStringLiteral("MayakNet event=foreign_vpn_detected known=%1 stoppable=%2")
                                         .arg(foreign.program == QLatin1String("Browsec") ? "browsec" : "other")
                                         .arg(foreign.stoppable ? 1 : 0);
                emit foreignVpnDetected(foreign.program, foreign.stoppable);
                return;
            }
            openConnection();
            return;
        }
        const ErrorCode errorCode = m_connectionController->isConnectionSupported(serverId);
        if (errorCode != ErrorCode::NoError) {
            notifyConnectionBlocked(errorCode);
            return;
        }

        emit prepareConfig();
    }
}

void ConnectionUiController::connectDespiteForeignVpn()
{
    if (m_foreignStopInFlight || isConnected() || isConnectionInProgress()) return;
    qInfo().noquote() << QStringLiteral("MayakNet event=foreign_vpn_ignored");
    openConnection();
}

void ConnectionUiController::stopForeignVpnAndConnect()
{
    if (m_foreignStopInFlight || isConnected() || isConnectionInProgress()) return;
    m_foreignStopInFlight = true;
    const QString program = m_foreignProgram;
    mayak::foreignvpn::requestStop(this, [this, program](bool replied, int stopped) {
        qInfo().noquote() << QStringLiteral("MayakNet event=foreign_vpn_stop_reply replied=%1 stopped=%2")
                                 .arg(replied ? 1 : 0).arg(stopped);
        // The tunnel adapter disappears shortly after its core exits; then look again.
        QTimer::singleShot(replied && stopped > 0 ? 1500 : 0, this, [this, program] {
            m_foreignStopInFlight = false;
            const auto still = mayak::foreignvpn::detect();
            qInfo().noquote() << QStringLiteral("MayakNet event=foreign_vpn_after_stop present=%1")
                                     .arg(still.found() ? 1 : 0);
            if (still.found()) {
                emit foreignVpnStopFailed(program);
                return;
            }
            openConnection();
        });
    });
}

void ConnectionUiController::notifyConnectionBlocked(ErrorCode errorCode)
{
    if (errorCode == ErrorCode::LegacyApiV1NotSupportedError) {
        emit unsupportedConnectDrawerRequested();
        return;
    }

    if (errorCode == ErrorCode::NoInstalledContainersError) {
        emit noInstalledContainers();
        return;
    }

    emit connectionErrorOccurred(errorCode);
}

bool ConnectionUiController::isConnectionInProgress() const
{
    return m_isConnectionInProgress;
}

bool ConnectionUiController::isConnected() const
{
    return m_isConnected;
}

bool ConnectionUiController::isRevokeBlockedDuringActiveConnection(const QString &serverId, int containerIndex,
                                                                   const QString &clientId) const
{
    if (clientId.isEmpty() || (!isConnected() && !isConnectionInProgress())) {
        return false;
    }

    if (m_serversController->getDefaultServerId() != serverId) {
        return false;
    }

    if (static_cast<int>(m_serversController->getDefaultContainer(serverId)) != containerIndex) {
        return false;
    }

    const auto adminConfig = m_serversController->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        return false;
    }

    const QString connectionClientId =
            adminConfig->containerConfig(static_cast<DockerContainer>(containerIndex)).protocolConfig.clientId();
    if (connectionClientId.isEmpty()) {
        return false;
    }

    return connectionClientId == clientId || connectionClientId.contains(clientId);
}
