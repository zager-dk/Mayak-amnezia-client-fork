#pragma once

#include <QJsonObject>
#include <QHostAddress>
#include <QNetworkInterface>
#include <QObject>
#include <QPointer>
#include <QStringList>

struct MayakTunnelProbeRequest {
    QString attemptTag;
    QHostAddress localAddress;
    QString interfaceName;
    QStringList expectedEgressIpv4;
    QString nonce;
    int deadlineMs = 8000;
#ifdef MAYAK_TUNNEL_PROBE_TESTING
    QString testHost;
    quint16 testPort = 0;
    int testConnectDelayMs = 0;
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

signals:
    void finished(quint64 generation, bool success, const MayakTunnelProbeProof &proof,
                  const QString &error);

private:
    quint64 m_generation = 0;
    QPointer<QObject> m_run;
};
