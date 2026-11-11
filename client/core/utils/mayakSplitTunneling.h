#pragma once

#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

// Mayak layer around the fork's split tunneling (CLAUDE.md rule 2). The fork's
// VpnConnection::appendSplitTunnelingConfig() builds the split keys from the user's settings;
// these functions only keep the tunnel proof (MayakTunnelProbe, rule 4) possible in every mode.
// Pure functions over the managed config: no network, no settings, no platform calls.
namespace mayak::split {
// Windows service reported that app exclusions could not be applied (driver unavailable). Process-wide,
// monotonic time in milliseconds; read by the Mayak runtime to show a clear error instead of retrying.
void markAppExclusionFailure();
bool appExclusionFailedSince(qint64 monotonicMs);
qint64 monotonicNowMs();

struct ProbeEndpoint {
    QString host;  // TLS peer name, SNI and Host header
    QString ipv4;  // address the probe connects to (inside the VPN routes)
    bool operator==(const ProbeEndpoint &o) const { return host == o.host && ipv4 == o.ipv4; }
};

enum class SitesRouting { AllSites, OnlyListed, AllExcept };

// Effective site routing of a config after appendSplitTunnelingConfig(): a mode with an empty
// list is not in effect.
SitesRouting sitesRouting(const QJsonObject &config);

// Keeps the Mayak app itself inside the VPN, whatever the app split mode:
// - Android "only selected": Mayak is added to the list;
// - Android "all except": Mayak is removed from the list;
// - desktop: the fork passes the list as excluded apps in every mode, so Mayak is removed.
// A list that becomes empty switches app splitting off. selfIds are the identifiers this app may
// have in the list (Android package name; desktop executable path, compared case-insensitively
// with either separator). Returns true when the config was changed.
bool keepSelfInTunnel(QJsonObject &config, const QStringList &selfIds, bool desktopList);

// Routes the probe endpoints through the VPN and returns the endpoints the probe must use:
// - "only listed": the resolved endpoints are added to the listed routes, all are returned;
// - "all except": no pinning when no endpoint is excluded (empty list); otherwise endpoints not
//   covered by an exclusion are returned; if every resolved
//   endpoint is excluded, the covering exclusions are removed and all are returned;
// - no site routing: nothing changes and an empty list is returned (the probe resolves itself).
// Only valid IPv4 endpoints are used, at most maxEndpoints of them.
QList<ProbeEndpoint> applyProbeRoutes(QJsonObject &config, const QList<ProbeEndpoint> &resolved,
                                      int maxEndpoints = 4);

// True when the IPv4 address lies in entry ("a.b.c.d" or "a.b.c.d/n").
bool ipv4Covered(const QString &ipv4, const QString &entry);

// ---- «Россия напрямую» -------------------------------------------------------------------
// Disjoint, sorted, merged IPv4 ranges [first, end).
struct Ipv4Range {
    quint64 first = 0;
    quint64 end = 0;
    bool operator==(const Ipv4Range &o) const { return first == o.first && end == o.end; }
};
using Ipv4Ranges = QList<Ipv4Range>;

// "a.b.c.d" or "a.b.c.d/n" per entry; other entries (IPv6, names, garbage) are ignored.
Ipv4Ranges ipv4Ranges(const QStringList &entries);
// The embedded list format: one entry per line, '#' comments. Lines starting with '!' are
// priority networks (key Russian services): part of the list and also returned in *priority.
Ipv4Ranges parseIpv4List(const QByteArray &text, Ipv4Ranges *priority = nullptr);
Ipv4Ranges unite(const Ipv4Ranges &a, const Ipv4Ranges &b);
Ipv4Ranges subtract(const Ipv4Ranges &a, const Ipv4Ranges &b);
Ipv4Ranges complement(const Ipv4Ranges &a);
// Keeps only the CIDR pieces of at most /maxPrefix (smaller pieces are dropped).
Ipv4Ranges dropPiecesSmallerThan(const Ipv4Ranges &a, int maxPrefix);
QStringList toCidrs(const Ipv4Ranges &a);
int cidrCount(const Ipv4Ranges &a);

struct RussiaDirectInput {
    Ipv4Ranges russia;        // embedded list
    Ipv4Ranges priority;      // key Russian services: never dropped by the budget
    QStringList direct;       // user exceptions "always direct" (IPs/CIDRs)
    QStringList viaVpn;       // user exceptions "always via VPN" + tunnel DNS
    bool excludeRoutes = true; // platform can exclude routes (Android 13+, Windows)
    int routeBudget = 0;      // max routes handed to the platform
};

struct RussiaDirectRoutes {
    int splitTunnelType = 0;  // fork value: 1 only listed (via VPN), 2 all except (direct)
    QStringList sites;        // fork splitTunnelSites
    int minPrefix = 32;       // smallest Russian piece kept (coarsening to the budget)
    int routes = 0;
    // Even the coarsest list exceeded the budget (many user exceptions): the mode is off for this
    // session (plain tunnel, everything via VPN) instead of overloading the platform.
    bool overBudget = false;
    // The priority networks were not kept: with them the routes did not fit the budget.
    bool priorityDropped = false;
};

// Direct = Russia (coarsened to the budget by dropping the smallest pieces) + "direct" exceptions,
// minus "via VPN" exceptions. With route exclusion this is handed over as "all except";
// otherwise its complement as "only listed". User exceptions are never dropped.
RussiaDirectRoutes russiaDirectRoutes(const RussiaDirectInput &in);
// Writes the result into the fork's site split keys of a managed config.
void applyRussiaDirect(QJsonObject &config, const RussiaDirectRoutes &routes);

} // namespace mayak::split
