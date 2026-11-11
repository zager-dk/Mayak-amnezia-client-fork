#include "mayakSplitTunneling.h"

#include <QDir>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <QHostAddress>
#include <QJsonArray>

namespace mayak::split {
namespace {
std::atomic<qint64> g_appExclusionFailureAt{0};
}
qint64 monotonicNowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}
void markAppExclusionFailure() { g_appExclusionFailureAt.store(monotonicNowMs()); }
bool appExclusionFailedSince(qint64 monotonicMs) {
    const qint64 at = g_appExclusionFailureAt.load();
    return at != 0 && at >= monotonicMs;
}

namespace {
// Values written by the fork (amnezia::RouteMode / amnezia::AppsRouteMode).
constexpr int kAll = 0;
constexpr int kOnly = 1;
constexpr int kExcept = 2;

const QString kSitesType = QStringLiteral("splitTunnelType");
const QString kSites = QStringLiteral("splitTunnelSites");
const QString kAppsType = QStringLiteral("appSplitTunnelType");
const QString kApps = QStringLiteral("splitTunnelApps");

bool validIpv4(const QString &text) {
    QHostAddress ip;
    return ip.setAddress(text) && ip.protocol() == QAbstractSocket::IPv4Protocol && ip.toString() == text;
}

QString normalizedPath(const QString &path) {
    return QDir::cleanPath(QDir::fromNativeSeparators(path.trimmed()));
}

bool sameApp(const QString &entry, const QString &self, bool desktopList) {
    if (self.isEmpty()) return false;
    if (!desktopList) return entry.trimmed() == self;
    return normalizedPath(entry).compare(normalizedPath(self), Qt::CaseInsensitive) == 0;
}
} // namespace

bool ipv4Covered(const QString &ipv4, const QString &entry) {
    QHostAddress ip;
    if (!ip.setAddress(ipv4) || ip.protocol() != QAbstractSocket::IPv4Protocol) return false;
    const QString text = entry.trimmed();
    if (!text.contains('/')) {
        QHostAddress single;
        return single.setAddress(text) && single.protocol() == QAbstractSocket::IPv4Protocol && single == ip;
    }
    const auto subnet = QHostAddress::parseSubnet(text);
    return subnet.first.protocol() == QAbstractSocket::IPv4Protocol && ip.isInSubnet(subnet);
}

SitesRouting sitesRouting(const QJsonObject &config) {
    if (config.value(kSites).toArray().isEmpty()) return SitesRouting::AllSites;
    switch (config.value(kSitesType).toInt(kAll)) {
    case kOnly: return SitesRouting::OnlyListed;
    case kExcept: return SitesRouting::AllExcept;
    default: return SitesRouting::AllSites;
    }
}

bool keepSelfInTunnel(QJsonObject &config, const QStringList &selfIds, bool desktopList) {
    const int type = config.value(kAppsType).toInt(kAll);
    if (type != kOnly && type != kExcept) return false;
    const QJsonArray apps = config.value(kApps).toArray();
    QStringList ids;
    for (const auto &id : selfIds)
        if (!id.trimmed().isEmpty()) ids.append(id.trimmed());
    if (ids.isEmpty()) return false;

    auto isSelf = [&](const QString &entry) {
        for (const auto &id : ids)
            if (sameApp(entry, id, desktopList)) return true;
        return false;
    };

    if (type == kOnly && !desktopList) {
        for (const auto &v : apps)
            if (isSelf(v.toString())) return false;
        QJsonArray withSelf = apps;
        withSelf.append(ids.first());
        config.insert(kApps, withSelf);
        return true;
    }

    // Excluded list (Android "all except"; desktop in every mode).
    QJsonArray kept;
    for (const auto &v : apps)
        if (!isSelf(v.toString())) kept.append(v);
    if (kept.size() == apps.size()) return false;
    config.insert(kApps, kept);
    if (kept.isEmpty()) config.insert(kAppsType, kAll);
    return true;
}

QList<ProbeEndpoint> applyProbeRoutes(QJsonObject &config, const QList<ProbeEndpoint> &resolved, int maxEndpoints) {
    QList<ProbeEndpoint> endpoints;
    for (const auto &e : resolved) {
        if (endpoints.size() >= maxEndpoints) break;
        if (e.host.isEmpty() || !validIpv4(e.ipv4) || endpoints.contains(e)) continue;
        endpoints.append(e);
    }
    const SitesRouting routing = sitesRouting(config);
    if (routing == SitesRouting::AllSites || endpoints.isEmpty()) return {};

    QJsonArray sites = config.value(kSites).toArray();
    if (routing == SitesRouting::OnlyListed) {
        for (const auto &e : endpoints) {
            bool listed = false;
            for (const auto &v : sites)
                if (ipv4Covered(e.ipv4, v.toString())) { listed = true; break; }
            if (!listed) sites.append(e.ipv4);
        }
        config.insert(kSites, sites);
        return endpoints;
    }

    // All except the list: prefer endpoints the user did not exclude.
    auto excluded = [&](const ProbeEndpoint &e) {
        for (const auto &v : sites)
            if (ipv4Covered(e.ipv4, v.toString())) return true;
        return false;
    };
    QList<ProbeEndpoint> free;
    for (const auto &e : endpoints)
        if (!excluded(e)) free.append(e);
    // Nothing excluded: no pinning, the probe resolves through the tunnel as without splitting.
    if (free.size() == endpoints.size()) return {};
    if (!free.isEmpty()) return free;

    QJsonArray kept;
    for (const auto &v : sites) {
        bool coversProbe = false;
        for (const auto &e : endpoints)
            if (ipv4Covered(e.ipv4, v.toString())) { coversProbe = true; break; }
        if (!coversProbe) kept.append(v);
    }
    config.insert(kSites, kept);
    if (kept.isEmpty()) config.insert(kSitesType, kAll);
    return endpoints;
}

namespace {
constexpr quint64 kSpace = quint64(1) << 32;

bool parseEntry(const QString &raw, Ipv4Range *out) {
    const QString text = raw.trimmed();
    if (text.isEmpty()) return false;
    QHostAddress ip;
    int prefix = 32;
    if (text.contains('/')) {
        const auto subnet = QHostAddress::parseSubnet(text);
        if (subnet.first.protocol() != QAbstractSocket::IPv4Protocol || subnet.second < 0 || subnet.second > 32) return false;
        ip = subnet.first; prefix = subnet.second;
    } else if (!ip.setAddress(text) || ip.protocol() != QAbstractSocket::IPv4Protocol) {
        return false;
    }
    const quint64 size = quint64(1) << (32 - prefix);
    const quint64 first = quint64(ip.toIPv4Address()) & ~(size - 1);
    *out = {first, first + size};
    return true;
}

Ipv4Ranges normalize(Ipv4Ranges r) {
    std::sort(r.begin(), r.end(), [](const Ipv4Range &a, const Ipv4Range &b) { return a.first < b.first; });
    Ipv4Ranges out;
    for (const auto &x : r) {
        if (x.end <= x.first) continue;
        if (!out.isEmpty() && x.first <= out.last().end) out.last().end = qMax(out.last().end, x.end);
        else out.append(x);
    }
    return out;
}

// CIDR decomposition of one range: (first, prefix) pieces.
template <typename F>
void forEachCidr(const Ipv4Range &r, F f) {
    quint64 cur = r.first;
    while (cur < r.end) {
        int prefix = 32;
        while (prefix > 0) {
            const quint64 size = quint64(1) << (32 - (prefix - 1));
            if ((cur & (size - 1)) != 0 || cur + size > r.end) break;
            --prefix;
        }
        f(cur, prefix);
        cur += quint64(1) << (32 - prefix);
    }
}
} // namespace

Ipv4Ranges ipv4Ranges(const QStringList &entries) {
    Ipv4Ranges out;
    for (const auto &e : entries) {
        Ipv4Range r;
        if (parseEntry(e, &r)) out.append(r);
    }
    return normalize(out);
}

Ipv4Ranges parseIpv4List(const QByteArray &text, Ipv4Ranges *priority) {
    QStringList entries, marked;
    for (const auto &line : text.split('\n')) {
        QByteArray t = line.trimmed();
        if (t.isEmpty() || t.startsWith('#')) continue;
        if (t.startsWith('!')) { t = t.mid(1).trimmed(); marked.append(QString::fromLatin1(t)); }
        entries.append(QString::fromLatin1(t));
    }
    if (priority) *priority = ipv4Ranges(marked);
    return ipv4Ranges(entries);
}

Ipv4Ranges unite(const Ipv4Ranges &a, const Ipv4Ranges &b) { return normalize(a + b); }

Ipv4Ranges subtract(const Ipv4Ranges &a, const Ipv4Ranges &b) {
    const Ipv4Ranges bb = normalize(b);
    Ipv4Ranges out;
    int j = 0;
    for (const auto &x : normalize(a)) {
        quint64 cur = x.first;
        while (j < bb.size() && bb[j].end <= cur) ++j;
        int k = j;
        while (cur < x.end && k < bb.size() && bb[k].first < x.end) {
            if (bb[k].first > cur) out.append({cur, bb[k].first});
            cur = qMax(cur, bb[k].end);
            ++k;
        }
        if (cur < x.end) out.append({cur, x.end});
    }
    return out;
}

Ipv4Ranges complement(const Ipv4Ranges &a) { return subtract({{0, kSpace}}, a); }

Ipv4Ranges dropPiecesSmallerThan(const Ipv4Ranges &a, int maxPrefix) {
    Ipv4Ranges out;
    for (const auto &r : a)
        forEachCidr(r, [&](quint64 first, int prefix) {
            if (prefix <= maxPrefix) out.append({first, first + (quint64(1) << (32 - prefix))});
        });
    return normalize(out);
}

QStringList toCidrs(const Ipv4Ranges &a) {
    QStringList out;
    for (const auto &r : a)
        forEachCidr(r, [&](quint64 first, int prefix) {
            out.append(QStringLiteral("%1/%2").arg(QHostAddress(quint32(first)).toString()).arg(prefix));
        });
    return out;
}

int cidrCount(const Ipv4Ranges &a) {
    int n = 0;
    for (const auto &r : a) forEachCidr(r, [&](quint64, int) { ++n; });
    return n;
}

namespace {
RussiaDirectRoutes computeRussiaDirect(const RussiaDirectInput &in);
}

RussiaDirectRoutes russiaDirectRoutes(const RussiaDirectInput &in) {
    RussiaDirectRoutes r = computeRussiaDirect(in);
    // Priority networks fragment the route set; when it does not fit the budget, giving up their
    // protection is better than switching the whole mode off (review 3, R1).
    if (r.overBudget && !in.priority.isEmpty()) {
        RussiaDirectInput plain = in;
        plain.priority.clear();
        r = computeRussiaDirect(plain);
        r.priorityDropped = true;
    }
    return r;
}

namespace {
RussiaDirectRoutes computeRussiaDirect(const RussiaDirectInput &in) {
    const Ipv4Ranges direct = unite(ipv4Ranges(in.direct), in.priority);
    const Ipv4Ranges viaVpn = ipv4Ranges(in.viaVpn);
    RussiaDirectRoutes best;
    Ipv4Ranges chosen;
    for (int minPrefix = 32; minPrefix >= 8; --minPrefix) {
        const Ipv4Ranges russia = minPrefix == 32 ? in.russia : dropPiecesSmallerThan(in.russia, minPrefix);
        const Ipv4Ranges set = subtract(unite(russia, direct), viaVpn);
        const int routes = in.excludeRoutes ? cidrCount(set) : cidrCount(complement(set));
        chosen = set; best.minPrefix = minPrefix; best.routes = routes;
        if (in.routeBudget <= 0 || routes <= in.routeBudget) break;
    }
    if (in.routeBudget > 0 && best.routes > in.routeBudget) {
        best.overBudget = true;
        best.splitTunnelType = kAll;
        best.sites.clear();
        return best;
    }
    if (in.excludeRoutes) {
        best.splitTunnelType = kExcept;
        best.sites = toCidrs(chosen);
    } else {
        best.splitTunnelType = kOnly;
        best.sites = toCidrs(complement(chosen));
    }
    if (best.sites.isEmpty()) { best.splitTunnelType = kAll; return best; } // nothing to split
    // "Only listed" drops the default IPv6 route; keep IPv6 in the tunnel as without splitting
    // (Android uses 2000::/3 for ::/0). Only the Android path without route exclusion gets here.
    if (best.splitTunnelType == kOnly) best.sites.append(QStringLiteral("2000::/3"));
    return best;
}
} // namespace

void applyRussiaDirect(QJsonObject &config, const RussiaDirectRoutes &routes) {
    config.insert(kSitesType, routes.splitTunnelType);
    config.insert(kSites, QJsonArray::fromStringList(routes.sites));
}

} // namespace mayak::split
