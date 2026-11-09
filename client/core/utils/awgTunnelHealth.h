#ifndef AWGTUNNELHEALTH_H
#define AWGTUNNELHEALTH_H

#include <QJsonObject>
#include <QByteArray>
#include <QMetaType>
#include <QString>
#include <QtGlobal>

// Own-peer WireGuard telemetry. A valid snapshot describes the tunnel only;
// it is not evidence that arbitrary internet destinations are reachable.
struct AwgTunnelHealth {
    QString healthContextId;
    quint64 generation = 0;
    QString peerPublicKey;
    QString endpoint;
    QString localAddress;
    QString interfaceName;
    quint64 latestHandshakeEpochMs = 0;
    quint64 rxTotal = 0;
    quint64 txTotal = 0;
    bool valid = false;

    bool hasConfirmedHandshake() const { return valid && latestHandshakeEpochMs > 0; }
    bool matchesConfiguredPeer(const QString& configuredPublicKeyBase64) const {
        const QString configuredHex = QString::fromLatin1(
            QByteArray::fromBase64(configuredPublicKeyBase64.toLatin1()).toHex());
        return !configuredHex.isEmpty() &&
            peerPublicKey.compare(configuredHex, Qt::CaseInsensitive) == 0;
    }

    static AwgTunnelHealth fromJson(const QJsonObject& json) {
        AwgTunnelHealth result;
        bool generationOk = false;
        bool handshakeOk = false;
        bool rxOk = false;
        bool txOk = false;
        const QString generationText = json.value("generation").toString();
        const QString handshakeText = json.value("latestHandshakeEpochMs").toString();
        const QString rxText = json.value("rxTotal").toString();
        const QString txText = json.value("txTotal").toString();
        result.generation = generationText.toULongLong(&generationOk, 10);
        result.latestHandshakeEpochMs = handshakeText.toULongLong(&handshakeOk, 10);
        result.rxTotal = rxText.toULongLong(&rxOk, 10);
        result.txTotal = txText.toULongLong(&txOk, 10);
        result.healthContextId = json.value("healthContextId").toString();
        result.peerPublicKey = json.value("peerPublicKey").toString();
        result.endpoint = json.value("endpoint").toString();
        result.localAddress = json.value("localAddress").toString();
        result.interfaceName = json.value("interfaceName").toString();
        result.valid = json.value("valid").toBool() && generationOk && result.generation > 0 &&
            handshakeOk && rxOk && txOk && !result.peerPublicKey.isEmpty() &&
            !result.endpoint.isEmpty() && !result.localAddress.isEmpty() &&
            !result.interfaceName.isEmpty();
        return result;
    }
};

// Expected identity belongs to the activation owner, never inferred from a sample.
// An empty context allows ordinary/manual VPN operation but no trusted health.
struct AwgHealthContext {
    QString id;
    QString peerPublicKey; // canonical hex
    QString endpoint;      // exact numeric host:port, IPv6 in brackets

    bool matches(const AwgTunnelHealth& sample) const {
        return !id.isEmpty() && !peerPublicKey.isEmpty() && !endpoint.isEmpty() &&
            sample.healthContextId == id && sample.generation > 0 &&
            sample.peerPublicKey.compare(peerPublicKey, Qt::CaseInsensitive) == 0 &&
            sample.endpoint == endpoint;
    }
    static QString endpointForHost(QString host, int port) {
        if (host.contains(':') && !host.startsWith('[')) host = '[' + host + ']';
        return host + ':' + QString::number(port);
    }
};

Q_DECLARE_METATYPE(AwgTunnelHealth)
Q_DECLARE_METATYPE(AwgHealthContext)

#endif // AWGTUNNELHEALTH_H
