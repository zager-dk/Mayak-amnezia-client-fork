#include "mayakTunnelInterfaceResolver.h"

#include <utility>
#include <algorithm>

namespace mayak::tunnel {

QVector<InterfaceCandidate> interfaceCandidates(const QList<QNetworkInterface> &interfaces) {
    QVector<InterfaceCandidate> result;
    result.reserve(interfaces.size());
    for (const auto &interface : interfaces) {
        InterfaceCandidate candidate;
        candidate.name = interface.name();
        candidate.humanReadableName = interface.humanReadableName();
        candidate.index = interface.index();
        for (const auto &entry : interface.addressEntries()) candidate.addresses.append(entry.ip());
        result.append(std::move(candidate));
    }
    return result;
}

bool resolveInterface(const QVector<InterfaceCandidate> &interfaces,
                      const QString &reportedName,
                      const QHostAddress &expectedLocalAddress,
                      InterfaceIdentity *identity) {
    if (!identity || reportedName.isEmpty() || expectedLocalAddress.isNull() ||
        expectedLocalAddress.protocol() != QAbstractSocket::IPv4Protocol) return false;

    const InterfaceCandidate *match = nullptr;
    for (const auto &candidate : interfaces) {
        if (candidate.name != reportedName && candidate.humanReadableName != reportedName) continue;
        if (match) return false; // Duplicate aliases and cross-namespace collisions are ambiguous.
        match = &candidate;
    }
    if (!match || match->index <= 0 ||
        std::find(match->addresses.cbegin(), match->addresses.cend(), expectedLocalAddress) == match->addresses.cend())
        return false;

    identity->name = match->name;
    identity->humanReadableName = match->humanReadableName;
    identity->index = match->index;
    return true;
}

} // namespace mayak::tunnel
