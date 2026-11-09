#ifndef CONNECTIONUICONTROLLER_H
#define CONNECTIONUICONTROLLER_H

#include <QObject>
#include <QVariantMap>

#include "core/controllers/connectionController.h"
#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"
#include "core/protocols/vpnProtocol.h"
#include "core/controllers/serversController.h"

class ConnectionUiController : public QObject
{
    Q_OBJECT

public:
    Q_PROPERTY(bool isConnected READ isConnected NOTIFY connectionStateChanged)
    Q_PROPERTY(bool isConnectionInProgress READ isConnectionInProgress NOTIFY connectionStateChanged)
    Q_PROPERTY(QString connectionStateText READ connectionStateText NOTIFY connectionStateChanged)
    Q_PROPERTY(QString connectionPhase READ connectionPhase NOTIFY connectionStateChanged)
    Q_PROPERTY(bool cleanupPending READ cleanupPending NOTIFY connectionStateChanged)
    Q_PROPERTY(QVariantMap exitLocation READ exitLocation NOTIFY connectionStateChanged)

    explicit ConnectionUiController(ConnectionController* connectionController,
                                    ServersController* serversController,
                                    QObject *parent = nullptr);

    ~ConnectionUiController() = default;

    bool isConnected() const;
    bool isConnectionInProgress() const;
    QString connectionStateText() const;
    QString connectionPhase() const;
    bool cleanupPending() const;
    QVariantMap exitLocation() const;

public slots:
    void toggleConnection();

    void openConnection();
    void closeConnection();

    bool isRevokeBlockedDuringActiveConnection(const QString &serverId, int containerIndex, const QString &clientId) const;

    ErrorCode getLastConnectionError();
    void onConnectionStateChanged(Vpn::ConnectionState state);

    void onTranslationsUpdated();

    // Mayak (Windows): answers to the "another VPN is on" question.
    void stopForeignVpnAndConnect();
    void connectDespiteForeignVpn();

signals:
    void connectionStateChanged();

    void connectionErrorOccurred(ErrorCode errorCode);

    void connectButtonClicked();
    void preparingConfig();
    void prepareConfig();
    void unsupportedConnectDrawerRequested();
    void noInstalledContainers();

    void foreignVpnDetected(const QString &program, bool stoppable);
    void foreignVpnStopFailed(const QString &program);

private:
    Vpn::ConnectionState getCurrentConnectionState();
    void notifyConnectionBlocked(ErrorCode errorCode);

    ConnectionController* m_connectionController;
    ServersController* m_serversController;

    bool m_isConnected = false;
    bool m_isConnectionInProgress = false;
    QString m_connectionStateText = tr("Connect");

    Vpn::ConnectionState m_state;

    QString m_foreignProgram;
    bool m_foreignStopInFlight = false;
};

#endif
