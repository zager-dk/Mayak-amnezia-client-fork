#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFile>
#include <QJsonArray>
#include <QJsonObject>
#include <QSignalSpy>
#include <QTest>
#include <QUuid>

#include "core/repositories/secureAppSettingsRepository.h"
#include "core/utils/mayakSplitTunneling.h"
#include "core/utils/mayakTunnelProbe.h"
#include "core/utils/routeModes.h"
#include "secureQSettings.h"
#include "ui/controllers/mayakRoutingUiController.h"
#include "vpnConnection.h"

using namespace mayak::split;

namespace {
QJsonObject apps(int type, const QStringList &list) {
    return QJsonObject{{"appSplitTunnelType", type}, {"splitTunnelApps", QJsonArray::fromStringList(list)}};
}
QJsonObject sites(int type, const QStringList &list) {
    return QJsonObject{{"splitTunnelType", type}, {"splitTunnelSites", QJsonArray::fromStringList(list)}};
}
QStringList strings(const QJsonValue &v) {
    QStringList out;
    for (const auto &x : v.toArray()) out.append(x.toString());
    return out;
}
const QList<ProbeEndpoint> kResolved{
    {"httpbingo.org", "66.241.125.10"}, {"httpbin.org", "34.200.1.1"},
    {"httpbingo.org", "66.241.125.11"}, {"httpbin.org", "34.200.1.2"}};
} // namespace

class TestMayakSplitTunneling : public QObject {
    Q_OBJECT
private slots:
    void ipv4Coverage() {
        QVERIFY(ipv4Covered("10.1.2.3", "10.1.2.3"));
        QVERIFY(ipv4Covered("10.1.2.3", "10.1.0.0/16"));
        QVERIFY(ipv4Covered("10.1.2.3", " 10.0.0.0/8 "));
        QVERIFY(!ipv4Covered("10.1.2.3", "10.1.2.4"));
        QVERIFY(!ipv4Covered("10.1.2.3", "10.2.0.0/16"));
        QVERIFY(!ipv4Covered("10.1.2.3", "::/0"));
        QVERIFY(!ipv4Covered("10.1.2.3", "example.org"));
        QVERIFY(!ipv4Covered("not-an-ip", "0.0.0.0/0"));
    }

    void sitesRoutingNeedsAList() {
        QCOMPARE(sitesRouting(QJsonObject{}), SitesRouting::AllSites);
        QCOMPARE(sitesRouting(sites(1, {})), SitesRouting::AllSites);
        QCOMPARE(sitesRouting(sites(0, {"1.2.3.4"})), SitesRouting::AllSites);
        QCOMPARE(sitesRouting(sites(1, {"1.2.3.4"})), SitesRouting::OnlyListed);
        QCOMPARE(sitesRouting(sites(2, {"1.2.3.4"})), SitesRouting::AllExcept);
    }

    void androidOnlySelectedAddsMayak() {
        auto c = apps(1, {"org.example.browser"});
        QVERIFY(keepSelfInTunnel(c, {"ru.mayaklight.vpn"}, false));
        QCOMPARE(strings(c["splitTunnelApps"]), QStringList({"org.example.browser", "ru.mayaklight.vpn"}));
        QCOMPARE(c["appSplitTunnelType"].toInt(), 1);
        QVERIFY(!keepSelfInTunnel(c, {"ru.mayaklight.vpn"}, false)); // already there
    }

    void androidAllExceptNeverExcludesMayak() {
        auto c = apps(2, {"org.example.bank", "ru.mayaklight.vpn"});
        QVERIFY(keepSelfInTunnel(c, {"ru.mayaklight.vpn"}, false));
        QCOMPARE(strings(c["splitTunnelApps"]), QStringList({"org.example.bank"}));
        QCOMPARE(c["appSplitTunnelType"].toInt(), 2);

        auto onlySelf = apps(2, {"ru.mayaklight.vpn"});
        QVERIFY(keepSelfInTunnel(onlySelf, {"ru.mayaklight.vpn"}, false));
        QVERIFY(strings(onlySelf["splitTunnelApps"]).isEmpty());
        QCOMPARE(onlySelf["appSplitTunnelType"].toInt(), 0); // nothing left to split
    }

    void androidPackageMatchIsExact() {
        auto c = apps(2, {"ru.mayaklight.vpn.helper", "RU.MAYAKLIGHT.VPN"});
        QVERIFY(!keepSelfInTunnel(c, {"ru.mayaklight.vpn"}, false));
        QCOMPARE(strings(c["splitTunnelApps"]).size(), 2);
    }

    void desktopListIsAlwaysExclusions() {
        const QString self = "C:/Program Files/Mayak/Mayak.exe";
        for (int mode : {1, 2}) {
            auto c = apps(mode, {"C:\\program files\\mayak\\MAYAK.EXE", "C:\\Games\\game.exe"});
            QVERIFY(keepSelfInTunnel(c, {self}, true));
            QCOMPARE(strings(c["splitTunnelApps"]), QStringList({"C:\\Games\\game.exe"}));
            QCOMPARE(c["appSplitTunnelType"].toInt(), mode);
        }
        auto c = apps(1, {"C:\\Games\\game.exe"});
        QVERIFY(!keepSelfInTunnel(c, {self}, true)); // desktop never adds itself to an exclusion list
    }

    void appSplittingOffIsUntouched() {
        auto c = apps(0, {"ru.mayaklight.vpn"});
        QVERIFY(!keepSelfInTunnel(c, {"ru.mayaklight.vpn"}, false));
        auto e = QJsonObject{};
        QVERIFY(!keepSelfInTunnel(e, {"ru.mayaklight.vpn"}, false));
        QVERIFY(e.isEmpty());
        auto noId = apps(1, {"org.example"});
        QVERIFY(!keepSelfInTunnel(noId, {}, false));
    }

    void onlyListedRoutesProbeEndpoints() {
        auto c = sites(1, {"10.0.0.0/8", "34.200.1.1", "1.1.1.1"});
        const auto used = applyProbeRoutes(c, kResolved);
        QCOMPARE(used, kResolved);
        // 34.200.1.1 was already listed, the others are added once.
        QCOMPARE(strings(c["splitTunnelSites"]),
                 QStringList({"10.0.0.0/8", "34.200.1.1", "1.1.1.1", "66.241.125.10", "66.241.125.11", "34.200.1.2"}));
        QCOMPARE(c["splitTunnelType"].toInt(), 1);
    }

    void onlyListedSkipsInvalidAndCaps() {
        auto c = sites(1, {"10.0.0.0/8"});
        QList<ProbeEndpoint> resolved{{"httpbingo.org", "::1"}, {"httpbingo.org", "bad"}, {"", "1.2.3.4"},
                                      {"httpbin.org", "34.200.1.1"}, {"httpbin.org", "34.200.1.1"}};
        resolved += kResolved;
        const auto used = applyProbeRoutes(c, resolved, 3);
        QCOMPARE(used.size(), 3);
        QCOMPARE(used.first(), (ProbeEndpoint{"httpbin.org", "34.200.1.1"}));
        for (const auto &e : used) QVERIFY(strings(c["splitTunnelSites"]).contains(e.ipv4));
    }

    void allExceptPrefersFreeEndpoints() {
        auto c = sites(2, {"66.241.125.0/24", "203.0.113.5"});
        const auto before = c;
        const auto used = applyProbeRoutes(c, kResolved);
        QCOMPARE(used, (QList<ProbeEndpoint>{{"httpbin.org", "34.200.1.1"}, {"httpbin.org", "34.200.1.2"}}));
        QCOMPARE(c, before); // the user's exclusions stay
    }

    void allExceptWithoutExcludedEndpointsDoesNotPin() {
        auto c = sites(2, {"10.0.0.0/8", "203.0.113.5"});
        const auto before = c;
        QVERIFY(applyProbeRoutes(c, kResolved).isEmpty()); // probe resolves through the tunnel as before
        QCOMPARE(c, before);
    }

    void priorityGivenUpBeforeTurningTheModeOff() {
        QFile f(":/mayak/ru_ipv4.txt");
        QVERIFY(f.open(QIODevice::ReadOnly));
        Ipv4Ranges priority;
        const auto russia = parseIpv4List(f.readAll(), &priority);
        RussiaDirectInput in;
        in.russia = russia; in.priority = priority; in.excludeRoutes = false; in.routeBudget = 700;
        in.direct = {"203.0.113.1", "203.0.113.77", "198.51.100.9", "192.0.2.200", "100.64.7.7"}; // five direct IPs
        const auto r = russiaDirectRoutes(in);
        QVERIFY(!r.overBudget);          // the mode stays on (Android 9-12)
        QVERIFY(r.priorityDropped);      // only the priority protection was given up
        QVERIFY(r.routes <= 700);
        QCOMPARE(r.splitTunnelType, 1);
    }

    void overBudgetFallsBackToPlainTunnel() {
        QStringList many;
        for (int i = 0; i < 300; ++i) many << QStringLiteral("198.%1.%2.1").arg(18 + i / 256).arg(i % 256);
        RussiaDirectInput in;
        in.russia = ipv4Ranges({"10.0.0.0/8"});
        in.direct = many;                 // user exceptions are never dropped
        in.excludeRoutes = false;         // complement path fragments the most
        in.routeBudget = 400;
        const auto r = russiaDirectRoutes(in);
        QVERIFY(r.overBudget);
        QCOMPARE(r.splitTunnelType, 0);
        QVERIFY(r.sites.isEmpty());
        QJsonObject c; applyRussiaDirect(c, r);
        QCOMPARE(sitesRouting(c), SitesRouting::AllSites); // everything via VPN, nothing overloaded
    }

    void allExceptDropsExclusionsCoveringEveryEndpoint() {
        auto c = sites(2, {"66.241.125.0/24", "34.0.0.0/8", "203.0.113.5"});
        const auto used = applyProbeRoutes(c, kResolved);
        QCOMPARE(used, kResolved);
        QCOMPARE(strings(c["splitTunnelSites"]), QStringList({"203.0.113.5"}));
        QCOMPARE(c["splitTunnelType"].toInt(), 2);

        auto all = sites(2, {"0.0.0.0/1", "34.200.1.0/24", "66.241.125.10", "66.241.125.11"});
        applyProbeRoutes(all, kResolved);
        QVERIFY(strings(all["splitTunnelSites"]).isEmpty());
        QCOMPARE(all["splitTunnelType"].toInt(), 0);
    }

    void noSiteRoutingNoPins() {
        auto c = sites(0, {});
        QVERIFY(applyProbeRoutes(c, kResolved).isEmpty());
        QCOMPARE(c, sites(0, {}));
        auto unresolved = sites(1, {"10.0.0.0/8"});
        QVERIFY(applyProbeRoutes(unresolved, {}).isEmpty());
        QCOMPARE(strings(unresolved["splitTunnelSites"]), QStringList({"10.0.0.0/8"}));
    }

    // The managed config goes through the fork's own split logic, then the Mayak invariants.
    void managedConfigCarriesForkSplitKeys() {
        SecureQSettings settings("Mayak-Split-Test-" + QUuid::createUuid().toString(), "amnezia-client", nullptr, false);
        SecureAppSettingsRepository repo(&settings);
        VpnConnection vpn(nullptr, &repo);
        const QJsonObject base{{"protocol", "awg"}, {"dns1", "1.1.1.1"}, {"dns2", "1.0.0.1"},
                               {"awg_config_data", QJsonObject{{"allowed_ips", QJsonArray{"0.0.0.0/0", "::/0"}}}}};

        QJsonObject off = base;
        vpn.appendSplitTunnelingConfig(off);
        QCOMPARE(off["splitTunnelType"].toInt(), 0);
        QCOMPARE(off["appSplitTunnelType"].toInt(), 0);
        QCOMPARE(sitesRouting(off), SitesRouting::AllSites);

        repo.setSitesSplitTunnelingEnabled(true);
        repo.setRouteMode(amnezia::RouteMode::VpnOnlyForwardSites);
        QVERIFY(repo.addVpnSite(amnezia::RouteMode::VpnOnlyForwardSites, "10.20.30.0/24"));
        repo.setAppsSplitTunnelingEnabled(true);
        repo.setAppsRouteMode(amnezia::AppsRouteMode::VpnAllExceptApps);
        const QString self = QCoreApplication::applicationFilePath();
        repo.setVpnApps(amnezia::AppsRouteMode::VpnAllExceptApps,
                        {amnezia::InstalledAppInfo{"Game", "", "C:/Games/game.exe"},
                         amnezia::InstalledAppInfo{"Mayak", "", self}});

        QJsonObject on = base;
        vpn.appendSplitTunnelingConfig(on);
        QCOMPARE(on["splitTunnelType"].toInt(), 1);
        QCOMPARE(strings(on["splitTunnelSites"]), QStringList({"10.20.30.0/24", "1.1.1.1", "1.0.0.1"}));
        QCOMPARE(on["appSplitTunnelType"].toInt(), 2);
        QCOMPARE(strings(on["splitTunnelApps"]).size(), 2);

        QVERIFY(keepSelfInTunnel(on, {self}, true));
        QCOMPARE(strings(on["splitTunnelApps"]), QStringList({"C:/Games/game.exe"}));
        QCOMPARE(applyProbeRoutes(on, kResolved).size(), 4);
        QVERIFY(strings(on["splitTunnelSites"]).contains("34.200.1.2"));
        settings.clearSettings();
    }

    void rangeArithmetic() {
        const auto a = ipv4Ranges({"10.0.0.0/24", "10.0.1.0/24", "10.0.0.5", "bad", "::/0", "192.0.2.0/25"});
        QCOMPARE(toCidrs(a), QStringList({"10.0.0.0/23", "192.0.2.0/25"}));
        QCOMPARE(toCidrs(subtract(a, ipv4Ranges({"10.0.0.128/25"}))),
                 QStringList({"10.0.0.0/25", "10.0.1.0/24", "192.0.2.0/25"}));
        QCOMPARE(cidrCount(complement({})), 1);
        QCOMPARE(toCidrs(complement(ipv4Ranges({"0.0.0.0/1"}))), QStringList({"128.0.0.0/1"}));
        QCOMPARE(toCidrs(dropPiecesSmallerThan(ipv4Ranges({"10.0.0.0/16", "11.0.0.0/24", "11.0.1.0/26"}), 24)),
                 QStringList({"10.0.0.0/16", "11.0.0.0/24"}));
        QCOMPARE(toCidrs(unite(ipv4Ranges({"10.0.0.0/25"}), ipv4Ranges({"10.0.0.128/25"}))), QStringList({"10.0.0.0/24"}));
        QCOMPARE(parseIpv4List("# c\n10.0.0.0/24\n\n 10.0.1.0/24 \r\n"), ipv4Ranges({"10.0.0.0/23"}));
    }

    void priorityLinesAreParsed() {
        Ipv4Ranges priority;
        const auto all = parseIpv4List("# h\n!10.0.0.0/24\n10.0.1.0/24\n! 192.0.2.0/24\n", &priority);
        QCOMPARE(toCidrs(all), QStringList({"10.0.0.0/23", "192.0.2.0/24"}));
        QCOMPARE(toCidrs(priority), QStringList({"10.0.0.0/24", "192.0.2.0/24"}));
        // A small priority block survives the budget, a small ordinary one is dropped.
        RussiaDirectInput in;
        in.russia = ipv4Ranges({"10.0.0.0/16", "11.0.0.0/30", "12.0.0.0/30"});
        in.priority = ipv4Ranges({"11.0.0.0/30"});
        in.viaVpn = {"11.0.0.2"};
        in.routeBudget = 3;
        const auto r = russiaDirectRoutes(in);
        QVERIFY(!r.overBudget);
        QVERIFY(r.minPrefix < 30);
        const auto direct = ipv4Ranges(r.sites);
        QVERIFY(subtract(ipv4Ranges({"10.0.0.0/16", "11.0.0.0/31", "11.0.0.3"}), direct).isEmpty()); // priority kept
        QCOMPARE(subtract(ipv4Ranges({"11.0.0.2"}), direct).size(), 1);   // user "via VPN" still wins
        QCOMPARE(subtract(ipv4Ranges({"12.0.0.0/30"}), direct).size(), 1); // ordinary small piece dropped
    }

    void russiaDirectWithRouteExclusion() {
        RussiaDirectInput in;
        in.russia = ipv4Ranges({"10.0.0.0/8", "192.0.2.0/24"});
        in.direct = {"198.51.100.7"};
        in.viaVpn = {"10.1.2.3", "1.1.1.1", ""};
        in.excludeRoutes = true;
        const auto r = russiaDirectRoutes(in);
        QCOMPARE(r.splitTunnelType, 2);
        const auto direct = ipv4Ranges(r.sites);
        QVERIFY(!subtract(ipv4Ranges({"192.0.2.0/24", "198.51.100.7"}), direct).size()); // Russia + exception direct
        QVERIFY(subtract(ipv4Ranges({"10.1.2.3"}), direct) == ipv4Ranges({"10.1.2.3"}));    // via-VPN exception stays in
        QCOMPARE(r.routes, r.sites.size());
        QJsonObject c; applyRussiaDirect(c, r);
        QCOMPARE(sitesRouting(c), SitesRouting::AllExcept);
    }

    void russiaDirectWithoutRouteExclusionUsesComplement() {
        RussiaDirectInput in;
        in.russia = ipv4Ranges({"10.0.0.0/8"});
        in.viaVpn = {"10.0.0.1"};
        in.excludeRoutes = false;
        const auto r = russiaDirectRoutes(in);
        QCOMPARE(r.splitTunnelType, 1);
        QCOMPARE(r.sites.last(), QStringLiteral("2000::/3")); // IPv6 stays in the tunnel
        const auto vpn = ipv4Ranges(r.sites);
        QVERIFY(subtract(ipv4Ranges({"8.8.8.8", "10.0.0.1"}), vpn).isEmpty());
        QCOMPARE(subtract(ipv4Ranges({"10.0.0.2"}), vpn), ipv4Ranges({"10.0.0.2"}));
        QCOMPARE(r.routes, r.sites.size() - 1);
    }

    void budgetDropsSmallestRussianPiecesOnly() {
        QStringList small;
        for (int i = 0; i < 200; ++i) small << QStringLiteral("11.%1.%2.0/24").arg(i / 2).arg((i % 2) * 2);
        RussiaDirectInput in;
        in.russia = unite(ipv4Ranges({"10.0.0.0/8"}), ipv4Ranges(small));
        in.direct = {"203.0.113.9"};
        in.excludeRoutes = true;
        in.routeBudget = 10;
        const auto r = russiaDirectRoutes(in);
        QVERIFY(r.routes <= 10);
        QVERIFY(r.minPrefix < 24);
        QVERIFY(r.sites.contains("10.0.0.0/8"));
        QVERIFY(r.sites.contains("203.0.113.9/32")); // user exception never dropped
        in.routeBudget = 0;
        QCOMPARE(russiaDirectRoutes(in).routes, 202);
    }

    void embeddedListAndPlatformBudgets() {
        QFile f(":/mayak/ru_ipv4.txt");
        QVERIFY(f.open(QIODevice::ReadOnly));
        Ipv4Ranges priority;
        const auto russia = parseIpv4List(f.readAll(), &priority);
        QCOMPARE(cidrCount(russia), 8672);
        QVERIFY(cidrCount(priority) >= 40);                                  // key services marked
        QVERIFY(subtract(priority, russia).isEmpty());
        QVERIFY(subtract(ipv4Ranges({"77.88.8.8"}), russia).isEmpty());     // Yandex DNS: Russian
        QCOMPARE(subtract(ipv4Ranges({"8.8.8.8"}), russia).size(), 1);     // Google DNS: not
        for (const auto &[exclude, budget] : {std::pair{true, 400}, std::pair{false, 700}}) {
            RussiaDirectInput in; in.russia = russia; in.priority = priority; in.excludeRoutes = exclude; in.routeBudget = budget;
            in.viaVpn = {"1.1.1.1", "1.0.0.1"};
            QElapsedTimer t; t.start();
            const auto r = russiaDirectRoutes(in);
            const auto kept = dropPiecesSmallerThan(russia, r.minPrefix);
            qInfo().noquote() << QStringLiteral("budget exclude=%1 budget=%2 -> routes=%3 min_prefix=/%4 in %5 ms; priority rescued %6 of %7 networks")
                .arg(exclude).arg(budget).arg(r.routes).arg(r.minPrefix).arg(t.elapsed())
                .arg(cidrCount(subtract(priority, kept))).arg(cidrCount(priority));
            QVERIFY(r.routes <= budget);
            const auto listed = ipv4Ranges(r.sites);
            if (exclude) QVERIFY(subtract(priority, listed).isEmpty());          // all priority direct
            else QCOMPARE(subtract(priority, listed), priority);                 // none routed into VPN
        }
    }

    void russiaDirectChoiceIsRemembered() {
        const QString org = "Mayak-Russia-Test-" + QUuid::createUuid().toString();
        {
            SecureQSettings settings(org, "amnezia-client", nullptr, false);
            SecureAppSettingsRepository repo(&settings);
            MayakRoutingUiController ui(&repo);
            QVERIFY(ui.russiaDirect());   // not chosen yet: on by default
            QVERIFY(ui.noticePending());
            ui.setRussiaDirect(false);
            QVERIFY(!ui.noticePending()); // chosen: no "on by default" notice
        }
        {
            SecureQSettings settings(org, "amnezia-client", nullptr, false); // next start / after an update
            SecureAppSettingsRepository repo(&settings);
            MayakRoutingUiController ui(&repo);
            QVERIFY(!ui.russiaDirect());
            VpnConnection vpn(nullptr, &repo);
            QJsonObject c;
            QVERIFY(!vpn.appendMayakRussiaDirectConfig(c, true, 9000));
            QVERIFY(c.isEmpty());
            ui.setRussiaDirect(true);
            QVERIFY(ui.russiaDirect());
            settings.clearSettings();
        }
    }

    void managedConfigRussiaDirectKeepsDnsAndExceptions() {
        SecureQSettings settings("Mayak-Russia-Cfg-" + QUuid::createUuid().toString(), "amnezia-client", nullptr, false);
        SecureAppSettingsRepository repo(&settings);
        QVERIFY(repo.addVpnSite(amnezia::RouteMode::VpnOnlyForwardSites, "77.88.55.0/24"));  // Russian, forced via VPN
        QVERIFY(repo.addVpnSite(amnezia::RouteMode::VpnAllExceptSites, "203.0.113.0/24"));   // foreign, forced direct
        VpnConnection vpn(nullptr, &repo);
        QJsonObject c{{"protocol", "awg"}, {"dns1", "77.88.8.8"}, {"dns2", "77.88.8.1"},
                      {"awg_config_data", QJsonObject{{"allowed_ips", QJsonArray{"0.0.0.0/0", "::/0"}}}}};
        vpn.appendSplitTunnelingConfig(c);
        QVERIFY(vpn.appendMayakRussiaDirectConfig(c, true, 9000));
        QCOMPARE(sitesRouting(c), SitesRouting::AllExcept);
        const auto direct = ipv4Ranges(strings(c["splitTunnelSites"]));
        QVERIFY(subtract(ipv4Ranges({"203.0.113.10", "95.108.128.1"}), direct).isEmpty());
        QCOMPARE(subtract(ipv4Ranges({"77.88.8.8", "77.88.8.1", "77.88.55.60"}), direct).size(), 3); // DNS + exception in VPN
        settings.clearSettings();
    }

    void probeRejectsForeignPinnedEndpoint() {
        QCOMPARE(MayakTunnelProbe::echoHosts(), QStringList({"httpbingo.org", "httpbin.org"}));
        MayakTunnelProbe probe;
        QSignalSpy spy(&probe, &MayakTunnelProbe::finished);
        MayakTunnelProbeRequest r;
        r.attemptTag = "a"; r.nonce = "n"; r.interfaceName = "awg0";
        r.localAddress = QHostAddress("10.8.1.2"); r.expectedEgressIpv4 = {"203.0.113.9"}; r.deadlineMs = 1000;
        r.pinnedEndpoints = {{"evil.example", "203.0.113.10"}};
        probe.start(r);
        QTRY_COMPARE_WITH_TIMEOUT(spy.count(), 1, 2000);
        QCOMPARE(spy.first().at(1).toBool(), false);
        QCOMPARE(spy.first().at(3).toString(), QStringLiteral("invalid pinned endpoint"));
    }
};

QTEST_MAIN(TestMayakSplitTunneling)
#include "testMayakSplitTunneling.moc"
