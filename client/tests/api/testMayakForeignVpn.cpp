#include <QtTest>
#include <QJsonDocument>
#include <QJsonObject>

#include "core/controllers/mayakForeignVpn.h"
#ifdef Q_OS_WINDOWS
#include "platforms/windows/daemon/mayakforeignvpnstop.h"
#endif

using namespace mayak::foreignvpn;

namespace {

Adapter adapter(quint32 index, const QString& alias, const QString& description, quint32 type,
                bool up = true) {
    Adapter a;
    a.index = index;
    a.alias = alias;
    a.description = description;
    a.ifType = type;
    a.up = up;
    return a;
}

Route v4(quint32 index, quint8 prefix, quint32 destination = 0) {
    Route r;
    r.index = index;
    r.prefixLength = prefix;
    r.v4Destination = destination;
    return r;
}

const Adapter kEthernet = adapter(14, "Ethernet", "Realtek PCIe 5GbE Family Controller", 6);
const Adapter kBrowsec =
    adapter(10, "browbox-tun-4c482c10-522b-4823-acc9-48eb07033a53", "sing-tun Tunnel", 53);
const Adapter kMayak = adapter(11, "MayakVPN", "WireGuard Tunnel", 53);

QByteArray reply(const QString& owner, const QString& id, int stopped) {
    return QJsonDocument(QJsonObject{{"type", "mayakForeignVpnStopped"}, {"owner", owner},
                                     {"requestId", id}, {"stopped", stopped}})
        .toJson(QJsonDocument::Compact);
}

const QString kOwner = QStringLiteral("MayakVpnAwgLifecycleV1");

// Windows path from a forward-slash literal.
QString winPath(const char* path) {
    return QString::fromLatin1(path).replace(QLatin1Char('/'), QChar(0x5C));
}

}  // namespace

class TestMayakForeignVpn : public QObject {
    Q_OBJECT
private slots:
    void nothingWhenOnlyPhysicalAdaptersHaveTheDefaultRoute() {
        const auto f = classify({kEthernet}, {v4(14, 0)}, {"browsec.exe"});
        QVERIFY(!f.found());
    }

    void browsecAppRunningWithItsVpnOffIsNotAConflict() {
        // The owner's 15:36 case: Browsec.exe running, no browbox core, no tunnel adapter.
        const auto f = classify({kEthernet, kMayak}, {v4(14, 0)}, {"browsec.exe"});
        QVERIFY(!f.found());
    }

    void browsecTunnelUpIsFoundAndStoppableWhenItsCoreRuns() {
        const auto f = classify({kEthernet, kBrowsec}, {v4(14, 0)}, {"browsec.exe", "browbox.exe"});
        QVERIFY(f.found());
        QCOMPARE(f.program, QStringLiteral("Browsec"));
        QCOMPARE(f.adapter, kBrowsec.alias);
        QVERIFY(f.stoppable);
    }

    void browsecTunnelWithoutItsCoreIsNotStoppable() {
        const auto f = classify({kBrowsec}, {}, {"browsec.exe"});
        QVERIFY(f.found());
        QVERIFY(!f.stoppable);
    }

    void browsecTunnelDownIsIgnored() {
        auto down = kBrowsec;
        down.up = false;
        QVERIFY(!classify({down}, {v4(10, 0)}, {"browbox.exe"}).found());
    }

    void mayaksOwnTunnelIsNeverAConflict() {
        QVERIFY(!classify({kMayak}, {v4(11, 1, 0), v4(11, 1, 0x80000000u)}, {}).found());
    }

    void unknownVirtualAdapterNeedsACatchAllRoute() {
        const auto other = adapter(34, "WireSock", "WireSock Virtual Adapter", 53);
        QVERIFY(!classify({other}, {v4(34, 24, 0x0A000000u)}, {}).found());
        const auto f = classify({other}, {v4(34, 1, 0x80000000u)}, {});
        QVERIFY(f.found());
        QCOMPARE(f.program, QStringLiteral("WireSock"));
        QVERIFY(!f.stoppable);
    }

    void splitDefaultHalvesAndV6DefaultCount() {
        const auto tap = adapter(7, "VPN client", "TAP-Windows Adapter V9", 6);
        QVERIFY(classify({tap}, {v4(7, 1, 0)}, {}).found());
        Route r6;
        r6.index = 7;
        r6.v6 = true;
        r6.prefixLength = 0;
        QVERIFY(classify({tap}, {r6}, {}).found());
        QVERIFY(!classify({tap}, {v4(7, 1, 0x40000000u)}, {}).found());
    }

    void windowsIpv6TransitionTunnelsAreNotAVpn() {
        Route r6;
        r6.index = 40;
        r6.v6 = true;
        r6.prefixLength = 0;
        for (const auto& name : {QStringLiteral("Teredo Tunneling Pseudo-Interface"),
                                 QStringLiteral("Microsoft IP-HTTPS Platform Adapter"),
                                 QStringLiteral("Microsoft 6to4 Adapter"), QStringLiteral("Microsoft ISATAP Adapter")}) {
            const auto t = adapter(40, QStringLiteral("Tunnel"), name, 131);
            QVERIFY2(!classify({t}, {r6}, {}).found(), qPrintable(name));
        }
    }

    void physicalAdapterWithDefaultRouteIsNotAVpn() {
        const auto pppoe = adapter(20, "Rostelecom", "WAN Miniport (PPPOE)", 23);
        QVERIFY(!classify({pppoe}, {v4(20, 0)}, {}).found());
    }

    void browsecIsPreferredOverOtherVpns() {
        const auto other = adapter(34, "WireSock", "WireSock Virtual Adapter", 53);
        const auto f = classify({other, kBrowsec}, {v4(34, 0)}, {"browbox.exe"});
        QCOMPARE(f.program, QStringLiteral("Browsec"));
    }

    void stopRequestAndReplyRoundTrip() {
        const QString id(64, QLatin1Char('a'));
        const auto line = stopRequestLine(id);
        QVERIFY(line.endsWith('\n'));
        const auto obj = QJsonDocument::fromJson(line).object();
        QCOMPARE(obj.value("type").toString(), QStringLiteral("mayakStopForeignVpn"));
        QCOMPARE(obj.value("requestId").toString(), id);

        int stopped = -1;
        QVERIFY(parseStopReply(reply(kOwner, id, 1), id, &stopped));
        QCOMPARE(stopped, 1);
    }

    void stopReplyForAnotherRequestOrOwnerIsIgnored() {
        const QString id(64, QLatin1Char('a'));
        const QString other(64, QLatin1Char('b'));
        int stopped = -1;
        QVERIFY(!parseStopReply(reply(kOwner, other, 1), id, &stopped));
        QVERIFY(!parseStopReply(reply(QStringLiteral("x"), id, 1), id, &stopped));
        QVERIFY(!parseStopReply(QJsonDocument(QJsonObject{{"type", "status"}}).toJson(), id, &stopped));
        QVERIFY(!parseStopReply("not json", id, &stopped));
        QCOMPARE(stopped, -1);
    }

    void prepareSplitTunnelRequestAndReply() {
        const QString id(64, QLatin1Char('a'));
        const auto line = prepareSplitTunnelRequestLine(id);
        QVERIFY(line.endsWith('\n'));
        const auto obj = QJsonDocument::fromJson(line).object();
        QCOMPARE(obj.value("type").toString(), QStringLiteral("mayakPrepareSplitTunnel"));
        QCOMPARE(obj.value("requestId").toString(), id);
        const auto answer = [](const QString& owner, const QString& req, const QString& result) {
            return QJsonDocument(QJsonObject{{"type", "mayakSplitTunnelPrepared"}, {"owner", owner},
                                             {"requestId", req}, {"result", result}}).toJson(QJsonDocument::Compact);
        };
        QString result;
        for (const char* r : {"ok", "amnezia_active", "amnezia_busy", "amnezia_holds", "mullvad", "unavailable"}) {
            QVERIFY(parsePrepareSplitTunnelReply(answer(kOwner, id, QString::fromLatin1(r)), id, &result));
            QCOMPARE(result, QString::fromLatin1(r));
        }
        result.clear();
        QVERIFY(!parsePrepareSplitTunnelReply(answer(kOwner, id, QStringLiteral("maybe")), id, &result));
        QVERIFY(!parsePrepareSplitTunnelReply(answer(kOwner, QString(64, QLatin1Char('b')), QStringLiteral("ok")), id, &result));
        QVERIFY(!parsePrepareSplitTunnelReply(answer(QStringLiteral("x"), id, QStringLiteral("ok")), id, &result));
        QVERIFY(!parsePrepareSplitTunnelReply(reply(kOwner, id, 1), id, &result)); // a stop reply is not an answer
        QVERIFY(result.isEmpty());
    }

#ifdef Q_OS_WINDOWS
    void serviceEndsOnlyBrowsecsCoreByPath() {
        using MayakForeignVpnStop::isKnownCore;
        QVERIFY(isKnownCore(winPath("C:/Users/A/AppData/Local/Programs/browsec-desktop/resources/xray/browbox.exe")));
        QVERIFY(isKnownCore(winPath("C:/USERS/A/APPDATA/LOCAL/PROGRAMS/BROWSEC-DESKTOP/RESOURCES/XRAY/BROWBOX.EXE")));
        QVERIFY(!isKnownCore(winPath("C:/Users/A/Downloads/browbox.exe")));
        QVERIFY(!isKnownCore(winPath("C:/Users/A/AppData/Local/Programs/browsec-desktop/resources/xray/browray.exe")));
        QVERIFY(!isKnownCore(winPath("C:/Users/A/AppData/Local/Programs/browsec-desktop/Browsec.exe")));
        QVERIFY(!isKnownCore(winPath("C:/Windows/System32/svchost.exe")));
        QVERIFY(!isKnownCore(QString()));
    }
#endif
};

QTEST_GUILESS_MAIN(TestMayakForeignVpn)
#include "testMayakForeignVpn.moc"
