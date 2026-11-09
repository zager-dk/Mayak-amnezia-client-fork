#ifndef WIREGUARDPROTOCOL_H
#define WIREGUARDPROTOCOL_H

#include <QObject>
#include <QProcess>
#include <QString>
#include <QTemporaryFile>
#include <QTimer>

#include "vpnProtocol.h"
#include "core/utils/awgTunnelHealth.h"

#include "mozilla/controllerimpl.h"

class WireguardProtocol : public VpnProtocol
{
    Q_OBJECT

public:
    explicit WireguardProtocol(const QJsonObject& configuration, QObject* parent = nullptr);
    virtual ~WireguardProtocol() override;

    ErrorCode start() override;
    void stop() override;

    AwgHealthContext expectedAwgHealthContext() const { return m_impl ? m_impl->expectedAwgHealthContext() : AwgHealthContext{}; }

    void useManagedLifecycle() { m_managedLifecycle = true; }
    void managedDeactivate(const QString& request, const QString& context);
    void inspectOwnBackend(const QString& request);
    ErrorCode startMzImpl();
    ErrorCode stopMzImpl();

signals:
    void awgTunnelHealthUpdated(const AwgTunnelHealth& health);
    void managedStopped(const QString& request, const QString& context, bool stopped);
    void managedInspected(const QString& request, const QString& state, const QString& identity);

private:

    QScopedPointer<ControllerImpl> m_impl;
    QTimer m_healthPollTimer;
    bool m_managedLifecycle = false;
};

#endif // WIREGUARDPROTOCOL_H
