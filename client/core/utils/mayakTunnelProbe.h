#pragma once

#include <QJsonObject>
#include <QHostAddress>
#include <QNetworkInterface>
#include <QObject>
#include <QPointer>
#include <QStringList>

#include "core/utils/mayakSplitTunneling.h"

struct MayakTunnelProbeRequest {
    QString attemptTag;
    QHostAddress localAddress;
    QString interfaceName;
    QStringList expectedEgressIpv4;
    QString nonce;
    int deadlineMs = 8000;
    // Split tunneling (sites): endpoints routed through the VPN. When set, the probe connects
    // only to these IPv4 addresses; TLS still verifies the certificate for the host name.
    QList<mayak::split::ProbeEndpoint> pinnedEndpoints;
    // Xray path race (no tunnel exists yet): connect through this local SOCKS5 entry of the
    // race engine instead of binding to a tunnel interface. Never a tunnel proof by itself:
    // the proof of a started path always binds to its tunnel interface.
    quint16 socksPort = 0;
    QString socksUser;
    QString socksPassword;
    bool viaSocks() const { return socksPort != 0; }
    // Manually imported configs only: the egress is unknown, so any public IPv4 is accepted
    // (TLS + nonce through the bound interface still required). Never for a Mayak server.
    bool acceptAnyPublicEgress = false;
#ifdef MAYAK_TUNNEL_PROBE_TESTING
    QString testHost;
    quint16 testPort = 0;
    int testConnectDelayMs = 0;
    int testSourceBindFailures = 0;
    int testSourceBindError = 9;
    int testBindRetryIntervalMs = 25;
    bool testIdentityDriftDuringBindWait = false;
#endif
};

struct MayakTunnelProbeProof {
    QString attemptTag;
    QString nonce;
    QString observedEgressIpv4;
    QString interfaceName;
    QString localAddress;
    bool certificateVerified = false;
};

class MayakTunnelProbe final : public QObject {
    Q_OBJECT
public:
    explicit MayakTunnelProbe(QObject *parent = nullptr);
    quint64 start(const MayakTunnelProbeRequest &request);
    void cancel();

    // Strict response validator also used by deterministic tests.
    static bool validateResponse(const QByteArray &body, const QString &nonce,
                                 const QStringList &expectedEgressIpv4,
                                 QString *observedEgressIpv4, QString *error);
    static bool parseHttpResponse(const QByteArray &wire, QByteArray *body, QString *error);
    // HTTPS echo hosts the probe uses (resolved by the owner for split tunneling routes).
    static QStringList echoHosts();

signals:
    void finished(quint64 generation, bool success, const MayakTunnelProbeProof &proof,
                  const QString &error);

private:
    quint64 m_generation = 0;
    QPointer<QObject> m_run;
};
