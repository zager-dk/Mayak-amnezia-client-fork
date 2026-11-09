#pragma once

#include <QHostAddress>
#include <QNetworkInterface>
#include <QString>
#include <QVector>

namespace mayak::tunnel {

// A deliberately small snapshot of the Qt interface identity used by the
// Windows probe. Keeping the matching logic independent from the live host
// makes ambiguity and identity-drift behavior directly testable.
struct InterfaceCandidate {
    QString name;
    QString humanReadableName;
    int index = 0;
    QList<QHostAddress> addresses;
};

struct InterfaceIdentity {
    QString name;
    QString humanReadableName;
    int index = 0;

    bool operator==(const InterfaceIdentity &other) const {
        return name == other.name && humanReadableName == other.humanReadableName && index == other.index;
    }
    bool operator!=(const InterfaceIdentity &other) const { return !(*this == other); }
};

QVector<InterfaceCandidate> interfaceCandidates(const QList<QNetworkInterface> &interfaces);

// Resolve only an exact internal name or exact friendly alias. A token that
// identifies multiple interfaces across either namespace is rejected.
bool resolveInterface(const QVector<InterfaceCandidate> &interfaces,
                      const QString &reportedName,
                      const QHostAddress &expectedLocalAddress,
                      InterfaceIdentity *identity);

} // namespace mayak::tunnel
