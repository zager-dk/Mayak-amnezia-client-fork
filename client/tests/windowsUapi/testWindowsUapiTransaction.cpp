#include <QtTest>
#include <QJsonObject>
#include <QScopeGuard>
#include <optional>
#include "daemon/daemon.h"
#include "nativeApiFakes.h"
// Qt/platform headers are parsed first. Private access only seeds owned native
// teardown records; the operations exercised below are production methods.
#include "platforms/windows/daemon/windowstunnelservice.h"
#include "platforms/windows/daemon/windowsfirewall.h"
#define private public
#include "platforms/windows/daemon/windowsroutemonitor.h"
#undef private
#include "platforms/windows/daemon/wireguardutilswindows.h"

static InterfaceConfig config() {
  InterfaceConfig c;
  c.m_hopType = InterfaceConfig::SingleHop; c.m_killSwitchEnabled = false;
  c.m_privateKey = QString::fromLatin1(QByteArray(32, 'a').toBase64());
  c.m_serverPublicKey = QString::fromLatin1(QByteArray(32, 'b').toBase64());
  c.m_deviceIpv4Address = "10.8.0.2"; c.m_serverIpv4AddrIn = "192.0.2.4";
  c.m_serverIpv4Gateway = "10.8.0.1"; c.m_primaryDnsServer = "10.8.0.1";
  c.m_serverPort = 443; c.m_allowedIPAddressRanges = {IPAddress("0.0.0.0/0")};
  return c;
}
class FakeWg : public WireguardUtils {
public:
  FakeWg() : WireguardUtils(nullptr) {}
  bool exists = false, createOk = true, createPartial = true, peerOk = true, routeOk = true, stopOk = true;
  QStringList events;
  QList<PeerStatus> peers;
  bool interfaceExists() override { return exists; }
  bool addInterface(const InterfaceConfig&) override { events << "create"; exists = createOk || createPartial; return createOk; }
  bool deleteInterface() override { events << "stop"; if (stopOk) exists = false; return stopOk; }
  bool updatePeer(const InterfaceConfig&) override { events << "peer"; return peerOk; }
  bool deletePeer(const InterfaceConfig&) override { events << "deletePeer"; return true; }
  QList<PeerStatus> getPeerStatus() override { return peers; }
  bool updateRoutePrefix(const IPAddress&) override { events << "route"; return routeOk; }
  bool deleteRoutePrefix(const IPAddress&) override { events << "deleteRoute"; return true; }
  bool addExclusionRoute(const IPAddress&) override { events << "exclude"; return true; }
  bool deleteExclusionRoute(const IPAddress&) override { return true; }
  bool excludeLocalNetworks(const QList<IPAddress>&) override { return true; }
};
class FakeDns : public DnsUtils {
public:
  FakeDns() : DnsUtils(nullptr) {}
  bool updateOk = true, restoreOk = true; int updates = 0, restores = 0;
  bool updateResolvers(const QString&, const QList<QHostAddress>&) override { ++updates; return updateOk; }
  bool restoreResolvers() override { ++restores; return restoreOk; }
};
class FakeIp : public IPUtils {
public:
  FakeIp() : IPUtils(nullptr) {}
  bool addOk = true, mtuOk = true;
  bool addInterfaceIPs(const InterfaceConfig&) override { return addOk; }
  bool setMTUAndUp(const InterfaceConfig&) override { return mtuOk; }
};
class TestDaemon : public Daemon {
public:
  TestDaemon() : Daemon(nullptr) {}
  FakeWg wg; FakeDns dns; FakeIp ip;
  bool upOk = true, downOk = true; int prepares = 0, ups = 0, downs = 0;
  WireguardUtils* wgutils() const override { return const_cast<FakeWg*>(&wg); }
  DnsUtils* dnsutils() override { return &dns; }
  bool supportIPUtils() const override { return true; }
  IPUtils* iputils() override { return &ip; }
  void prepareActivation(const InterfaceConfig&, int = 0) override { ++prepares; }
  bool run(Op op, const InterfaceConfig&) override {
    if (op == Up) { ++ups; return upOk; }
    if (op == Down) { ++downs; return downOk; }
    return true;
  }
};
class NativeTestDaemon : public Daemon {
public:
  NativeTestDaemon() : Daemon(nullptr), fw(WindowsFirewall::create(nullptr)), wg(WireguardUtilsWindows::create(fw.get(), nullptr)) {}
  std::unique_ptr<WindowsFirewall> fw;
  std::unique_ptr<WireguardUtilsWindows> wg;
  FakeDns dns;
  WireguardUtils* wgutils() const override { return wg.get(); }
  DnsUtils* dnsutils() override { return &dns; }
};
// Production cleanup bodies are generated verbatim from the current source.
// No driver is opened and no real IOCTL is issued by this regression.
#include "logger.h"
#include "platforms/windows/daemon/windowssplittunnel.h"
static_assert(std::is_same_v<decltype(&WindowsSplitTunnel::stop), bool (WindowsSplitTunnel::*)()>);
namespace { Logger logger("ProductionCleanupFixture"); }
namespace splitfixture {
static bool running = false, clearOk = false, excludeOk = false;
static int clears = 0, starts = 0;
static BOOL deviceIoControl(HANDLE, DWORD, void*, DWORD, void*, DWORD, DWORD*, OVERLAPPED*) {
  ++clears;
  if (!clearOk) return FALSE;
  running = false;
  return TRUE;
}
}
struct SplitProbe {
  HANDLE m_driver = nullptr;
  bool start(int) { ++splitfixture::starts; splitfixture::running = true; return true; }
  bool excludeApps(const QStringList&) { return splitfixture::excludeOk; }
  bool isRunning() { return splitfixture::running; }
  bool stop();
};
class ProductionRunDaemon : public TestDaemon {
public:
  SplitProbe split;
  SplitProbe* m_splitTunnelManager = &split;
  int m_inetAdapterIndex = 5;
  bool run(Op op, const InterfaceConfig& config) override;
};
#define IOCTL_CLEAR_CONFIGURATION CTL_CODE(0x8000, 8, METHOD_NEITHER, FILE_ANY_ACCESS)
#define DeviceIoControl splitfixture::deviceIoControl
#include "productionCleanupBodies.inc"
#undef DeviceIoControl
#undef IOCTL_CLEAR_CONFIGURATION

class WindowsUapiTransactionTest : public QObject {
  Q_OBJECT
private slots:
  void init() { testapi::state = {}; }
  void productionDownClearFailureRetainsOwnerAndRetries() {
    splitfixture::running = false; splitfixture::clearOk = false; splitfixture::excludeOk = false;
    splitfixture::clears = splitfixture::starts = 0;
    ProductionRunDaemon d; auto c = config(); c.m_vpnDisabledApps = {"C:/synthetic.exe"};
    QVERIFY(!d.activateWithHealthContext(c, "owned-A"));
    QVERIFY(splitfixture::running); QCOMPARE(splitfixture::clears, 1);
    QCOMPARE(d.managedInspection()["state"].toString(), QString("unknown"));
    QCOMPARE(d.managedInspection()["controlIdentity"].toString(), QString("owned-A"));
    QVERIFY(!d.managedDeactivate("stale-B"));
    QVERIFY(!d.activateWithHealthContext(c, "owned-B"));
    QCOMPARE(splitfixture::clears, 1); QCOMPARE(splitfixture::starts, 1);
    QVERIFY(!d.managedDeactivate("owned-A")); QCOMPARE(splitfixture::clears, 2);
    QVERIFY(splitfixture::running);
    splitfixture::clearOk = true;
    QVERIFY(d.managedDeactivate("owned-A")); QVERIFY(!splitfixture::running);
    QCOMPARE(splitfixture::clears, 3); QCOMPARE(splitfixture::starts, 1);
    QCOMPARE(d.managedInspection()["state"].toString(), QString("off"));
    QVERIFY(d.managedInspection()["controlIdentity"].toString().isEmpty());
    QVERIFY(d.managedDeactivate("owned-A")); QCOMPARE(splitfixture::clears, 3);
  }
  void productionCommittedDownFailureCannotReportOff() {
    splitfixture::running = false; splitfixture::clearOk = false; splitfixture::excludeOk = true;
    splitfixture::clears = splitfixture::starts = 0;
    ProductionRunDaemon d; auto c = config(); c.m_vpnDisabledApps = {"C:/synthetic.exe"};
    QVERIFY(d.activateWithHealthContext(c, "owned-A")); QVERIFY(splitfixture::running);
    QVERIFY(!d.managedDeactivate("owned-A"));
    QCOMPARE(d.managedInspection()["state"].toString(), QString("unknown"));
    QCOMPARE(d.managedInspection()["controlIdentity"].toString(), QString("owned-A"));
    QVERIFY(splitfixture::running);
    splitfixture::clearOk = true;
    QVERIFY(d.managedDeactivate("owned-A")); QVERIFY(!splitfixture::running);
    QCOMPARE(d.managedInspection()["state"].toString(), QString("off"));
  }
  void productionNoAppsStopFailureIsNotSuccessfulUp() {
    splitfixture::running = true; splitfixture::clearOk = false; splitfixture::excludeOk = true;
    splitfixture::clears = splitfixture::starts = 0;
    ProductionRunDaemon d;
    QVERIFY(!d.activateWithHealthContext(config(), "owned-A"));
    QCOMPARE(d.managedInspection()["state"].toString(), QString("unknown"));
    QCOMPARE(d.managedInspection()["controlIdentity"].toString(), QString("owned-A"));
    splitfixture::clearOk = true;
    QVERIFY(d.managedDeactivate("owned-A")); QVERIFY(!splitfixture::running);
    QCOMPARE(d.managedInspection()["state"].toString(), QString("off"));
  }
  void exactSetFrames_data() {
    QTest::addColumn<QString>("reply"); QTest::addColumn<bool>("ok");
    QTest::newRow("success") << QString("errno=0\n\n") << true;
    for (const auto& pair : QList<QPair<const char*, QString>>{
      {"empty", ""}, {"missing", "public_key=abc\n\n"}, {"nonzero", "errno=5\n\n"},
      {"truncated", "errno=0\n"}, {"duplicate", "errno=0\nerrno=0\n\n"},
      {"malformed", "errno=00\n\n"}, {"trailing", "errno=0\n\nextra"},
      {"whitespace", " errno=0\n\n"}, {"extra_blank", "errno=0\n\n\n"}})
      QTest::newRow(pair.first) << pair.second << false;
  }
  void exactSetFrames() {
    QFETCH(QString, reply); QFETCH(bool, ok);
    WindowsTunnelService service;
    testapi::state.reply = reply.toUtf8();
    const auto actual = service.uapiCommand("set=1");
    QCOMPARE(WindowsTunnelService::setReplySucceeded(actual), ok);
    if (ok) QCOMPARE(actual, reply); // Production IO must not trim framing.
  }
  void failedIo_data() {
    QTest::addColumn<int>("failure");
    for (int i = 0; i < 7; ++i) QTest::newRow(qPrintable(QString::number(i))) << i;
  }
  void failedIo() {
    QFETCH(int, failure);
    if (failure == 0) testapi::state.openPipeOk = false;
    if (failure == 1) testapi::state.writeOk = false;
    if (failure == 2) testapi::state.shortWrite = true;
    if (failure == 3) testapi::state.readOk = false;
    if (failure == 4) testapi::state.zeroRead = true;
    if (failure == 5) testapi::state.pendingRead = true;
    if (failure == 6) { testapi::state.chunkSize = 2; testapi::state.reply = "errno=0\n"; }
    WindowsTunnelService service;
    QVERIFY(service.uapiCommand("set=1").isEmpty());
    QVERIFY(testapi::state.reads <= 5);
    if (failure == 5) QCOMPARE(testapi::state.cancels, 1);
  }
  void splitSuccessFrame() {
    WindowsTunnelService service; testapi::state.chunkSize = 2;
    QCOMPARE(service.uapiCommand("set=1"), QString("errno=0\n\n"));
  }
  void nativeCreationFailureRetainsHandle() {
    WindowsTunnelService service;
    testapi::state.describeOk = false; testapi::state.deleteOk = false;
    QVERIFY(!service.start("synthetic"));
    QVERIFY(service.interfaceExists());
    const int closed = testapi::state.closedServices;
    QVERIFY(!service.stop()); QCOMPARE(testapi::state.closedServices, closed);
    testapi::state.deleteOk = true;
    QVERIFY(service.stop()); QVERIFY(!service.interfaceExists());
    QVERIFY(service.stop()); QCOMPARE(testapi::state.creates, 1);
  }
  void nativeStopFailure() {
    WindowsTunnelService service; QVERIFY(service.start("synthetic"));
    testapi::state.stopOk = false;
    QVERIFY(!service.stop()); QVERIFY(service.interfaceExists()); QVERIFY(testapi::state.running);
    testapi::state.stopOk = true; QVERIFY(service.stop()); QVERIFY(!testapi::state.running);
  }
  void destructionAfterUnconfirmedStopClosesOnlyOwnHandles() {
    {
      WindowsTunnelService service; QVERIFY(service.start("synthetic"));
      testapi::state.stopOk = false;
      QVERIFY(!service.stop()); QVERIFY(testapi::state.running);
    }
    QVERIFY(testapi::state.running); QCOMPARE(testapi::state.deletes, 0);
    QCOMPARE(testapi::state.closedServices, 2); // Owned service + SCM; no stop ACK.
  }
  void preexistingNativeServicePreserved() {
    testapi::state.preexisting = true;
    { WindowsTunnelService service; QVERIFY(!service.start("synthetic")); QVERIFY(service.stop()); }
    QCOMPARE(testapi::state.creates, 0); QCOMPARE(testapi::state.controls, 0); QCOMPARE(testapi::state.deletes, 0);
  }
  void actualPeerSetFailureRollsBack_data() { exactSetFrames_data(); }
  void actualPeerSetFailureRollsBack() {
    QFETCH(QString, reply); QFETCH(bool, ok);
    auto fw = std::unique_ptr<WindowsFirewall>(WindowsFirewall::create(nullptr));
    auto wg = WireguardUtilsWindows::create(fw.get(), nullptr);
    QVERIFY(wg->addInterface(config()));
    testapi::state.reply = reply.toUtf8();
    QCOMPARE(wg->updatePeer(config()), ok);
    QVERIFY(wg->deleteInterface()); QVERIFY(!wg->interfaceExists());
  }
  void daemonPartialFailures_data() {
    QTest::addColumn<QString>("stage");
    for (const auto& stage : {"create-before", "create-after", "peer", "ip", "mtu", "dns", "route", "up"}) QTest::newRow(stage) << QString(stage);
  }
  void daemonPartialFailures() {
    QFETCH(QString, stage); TestDaemon d;
    if (stage.startsWith("create")) { d.wg.createOk = false; d.wg.createPartial = stage == "create-after"; }
    if (stage == "peer") d.wg.peerOk = false;
    if (stage == "ip") d.ip.addOk = false;
    if (stage == "mtu") d.ip.mtuOk = false;
    if (stage == "dns") d.dns.updateOk = false;
    if (stage == "route") d.wg.routeOk = false;
    if (stage == "up") d.upOk = false;
    QSignalSpy failed(&d, &Daemon::activationFailure);
    QVERIFY(!d.activateWithHealthContext(config(), "A"));
    QCOMPARE(d.wg.events.count("stop"), 1); QVERIFY(!d.wg.exists);
    QCOMPARE(d.managedInspection()["state"].toString(), QString("off"));
    QVERIFY(d.activeHealthContextId().isEmpty()); QVERIFY(!d.getStatus()["healthValid"].toBool());
    QVERIFY(d.managedDeactivate("A")); // Confirmed rollback ACK is idempotent.
    QVERIFY(!d.managedDeactivate("B")); QCOMPARE(failed.count(), 0);
  }
  void daemonUncertainCleanupRetainsIdentity_data() {
    QTest::addColumn<QString>("stage");
    for (const auto& stage : {"create", "stop", "dns", "down"}) QTest::newRow(stage) << QString(stage);
  }
  void daemonUncertainCleanupRetainsIdentity() {
    QFETCH(QString, stage); TestDaemon d;
    if (stage == "create") d.wg.createOk = false;
    else if (stage != "down") d.wg.peerOk = stage == "dns";
    if (stage == "dns") { d.dns.updateOk = false; d.dns.restoreOk = false; }
    else if (stage == "down") { d.upOk = false; d.downOk = false; }
    else d.wg.stopOk = false;
    QVERIFY(!d.activateWithHealthContext(config(), "A"));
    auto inspection = d.managedInspection();
    QCOMPARE(inspection["state"].toString(), QString("unknown"));
    QCOMPARE(inspection["controlIdentity"].toString(), QString("A"));
    const auto events = d.wg.events;
    QVERIFY(!d.managedDeactivate("B")); QCOMPARE(d.wg.events, events);
    QVERIFY(!d.activateWithHealthContext(config(), "B")); QCOMPARE(d.wg.events, events);
    QVERIFY(!d.managedDeactivate("A"));
    d.wg.stopOk = d.dns.restoreOk = d.downOk = true;
    QVERIFY(d.managedDeactivate("A"));
    QCOMPARE(d.managedInspection()["state"].toString(), QString("off"));
  }
  void preexistingManagedAPreserved() {
    TestDaemon d; QVERIFY(d.activateWithHealthContext(config(), "A"));
    WireguardUtils::PeerStatus peer(config().m_serverPublicKey);
    peer.m_handshake = 1000; peer.m_statsValid = true; peer.m_rxBytes = 40; peer.m_txBytes = 20;
    d.wg.peers = {peer};
    const auto before = d.getStatus(); const auto events = d.wg.events;
    const int prepares = d.prepares;
    QSignalSpy failure(&d, &Daemon::activationFailure);
    QVERIFY(!d.activateWithHealthContext(config(), "B"));
    QCOMPARE(d.getStatus(), before); QCOMPARE(d.activeHealthContextId(), QString("A"));
    QCOMPARE(d.wg.events, events); QCOMPARE(d.prepares, prepares); QCOMPARE(failure.count(), 0);
    QVERIFY(!d.managedDeactivate("B")); QCOMPARE(d.wg.events, events);
    QVERIFY(d.managedDeactivate("A")); QVERIFY(d.managedDeactivate("A"));
    QCOMPARE(d.wg.events.count("stop"), 1);
  }
  void unownedInterfacePreserved() {
    TestDaemon d; d.wg.exists = true;
    QVERIFY(!d.activateWithHealthContext(config(), "B"));
    QVERIFY(d.wg.exists); QVERIFY(d.wg.events.isEmpty()); QCOMPARE(d.prepares, 0);
  }
  void failedNativeStopCannotReportOff() {
    TestDaemon d; QVERIFY(d.activateWithHealthContext(config(), "A"));
    d.wg.stopOk = false; QVERIFY(!d.managedDeactivate("A"));
    QCOMPARE(d.managedInspection()["state"].toString(), QString("unknown"));
    QCOMPARE(d.managedInspection()["controlIdentity"].toString(), QString("A"));
    QVERIFY(d.wg.exists); QVERIFY(!d.getStatus()["healthValid"].toBool());
    d.wg.stopOk = true; QVERIFY(d.managedDeactivate("A"));
  }
  void routeCleanupFailureRetainsInputs() {
    WindowsRouteMonitor monitor(5, nullptr);
    auto row = new MIB_IPFORWARD_ROW2{}; row->InterfaceLuid.Value = 8;
    monitor.m_exclusionRoutes.insert(IPAddress("192.0.2.4"), row);
    testapi::state.routeDeleteResult = ERROR_ACCESS_DENIED;
    QVERIFY(!monitor.cleanup()); QCOMPARE(monitor.m_exclusionRoutes.size(), 1);
    testapi::state.routeDeleteResult = NO_ERROR;
    QVERIFY(monitor.cleanup()); QVERIFY(monitor.m_exclusionRoutes.isEmpty());
    QCOMPARE(testapi::state.routeDeletes, 2);
  }
  void repeatedPeerUpdatePreservesLegacySuccess() {
    auto fw = std::unique_ptr<WindowsFirewall>(WindowsFirewall::create(nullptr));
    auto wg = WireguardUtilsWindows::create(fw.get(), nullptr);
    QVERIFY(wg->addInterface(config())); QVERIFY(wg->updatePeer(config()));
    testapi::state.offset = 0;
    QVERIFY(wg->updatePeer(config())); QVERIFY(wg->deleteInterface());
  }
  void getReplyStillParsesPeerTelemetry() {
    auto fw = std::unique_ptr<WindowsFirewall>(WindowsFirewall::create(nullptr));
    auto wg = WireguardUtilsWindows::create(fw.get(), nullptr);
    testapi::state.reply = "public_key=" + QByteArray(32, 'b').toHex() +
      "\nrx_bytes=9\ntx_bytes=11\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\nerrno=0\n\n";
    const auto peers = wg->getPeerStatus(); QCOMPARE(peers.size(), 1);
    QVERIFY(peers.first().m_statsValid); QCOMPARE(peers.first().m_rxBytes, qint64(9));
    QCOMPARE(peers.first().m_handshake, qint64(0));
  }
  void zeroHandshakeIncludesGatewayWithoutConnected() {
    TestDaemon d; QVERIFY(d.activateWithHealthContext(config(), "A"));
    WireguardUtils::PeerStatus peer(config().m_serverPublicKey);
    peer.m_statsValid = true; d.wg.peers = {peer};
    const auto status = d.getStatus();
    QVERIFY(status["serverIpv4Gateway"].isString()); QVERIFY(!status["connected"].toBool());
    QCOMPARE(status["healthContextId"].toString(), QString("A"));
    QCOMPARE(status["generation"].toString(), QString("1"));
    QVERIFY(d.managedDeactivate("A"));
  }
  void actualNativeDaemonRollback() {
    NativeTestDaemon d;
    testapi::state.reply = "errno=5\n\n";
    testapi::state.stopOk = false;
    QVERIFY(!d.activateWithHealthContext(config(), "native-A"));
    QVERIFY(testapi::state.running);
    QCOMPARE(d.managedInspection()["state"].toString(), QString("unknown"));
    QCOMPARE(d.managedInspection()["controlIdentity"].toString(), QString("native-A"));
    const int controls = testapi::state.controls;
    QVERIFY(!d.managedDeactivate("stale-B")); QCOMPARE(testapi::state.controls, controls);
    testapi::state.stopOk = true;
    QVERIFY(d.managedDeactivate("native-A")); QVERIFY(!testapi::state.running);
    QCOMPARE(d.managedInspection()["state"].toString(), QString("off"));
  }
  void actualNativeCreationFailureRollback() {
    NativeTestDaemon d;
    testapi::state.describeOk = false; testapi::state.deleteOk = false;
    QVERIFY(!d.activateWithHealthContext(config(), "native-A"));
    QVERIFY(testapi::state.created);
    QCOMPARE(d.managedInspection()["controlIdentity"].toString(), QString("native-A"));
    testapi::state.deleteOk = true;
    QVERIFY(d.managedDeactivate("native-A")); QVERIFY(!testapi::state.created);
  }
  void actualNativeLuidFailureRollback() {
    NativeTestDaemon d; testapi::state.luidOk = false; testapi::state.stopOk = false;
    QVERIFY(!d.activateWithHealthContext(config(), "native-A"));
    QVERIFY(testapi::state.running);
    QCOMPARE(d.managedInspection()["controlIdentity"].toString(), QString("native-A"));
    testapi::state.stopOk = true;
    QVERIFY(d.managedDeactivate("native-A")); QVERIFY(!testapi::state.running);
  }
  void legacyReplacementFailureCleansNewInterface() {
    TestDaemon d; auto a = config();
    QVERIFY(d.activateWithHealthContext(a, QString()));
    auto b = a; b.m_privateKey = "different"; d.wg.peerOk = false;
    QVERIFY(!d.activateWithHealthContext(b, QString()));
    QVERIFY(!d.wg.exists); QCOMPARE(d.wg.events.count("stop"), 2);
    QCOMPARE(d.managedInspection()["state"].toString(), QString("off"));
  }
  void initialLegacyFailureCleansNativeState() {
    TestDaemon d; d.wg.peerOk = false;
    QVERIFY(!d.activateWithHealthContext(config(), QString()));
    QVERIFY(!d.wg.exists); QCOMPARE(d.wg.events.count("stop"), 1);
    QCOMPARE(d.managedInspection()["state"].toString(), QString("off"));
  }
  void trailingBytesInNextReadRejected() {
    WindowsTunnelService service;
    testapi::state.reply = "errno=0\n\ntrailing"; testapi::state.chunkSize = 9;
    QVERIFY(service.uapiCommand("set=1").isEmpty());
  }
  void bundledAbiContract() {
    const auto path = qEnvironmentVariable("MAYAK_TEST_TUNNEL_DLL");
    if (path.isEmpty()) QSKIP("Set MAYAK_TEST_TUNNEL_DLL to the exact packaged/staged tunnel.dll");
    QFile dll(path); QVERIFY(dll.open(QIODevice::ReadOnly)); const auto bytes = dll.readAll();
    const QByteArray prefix = "\\\\.\\pipe\\ProtectedPrefix\\Administrators\\AmneziaWG\\";
    QVERIFY(bytes.contains(prefix)); QVERIFY(!bytes.contains("\\Administrators\\MayakWG\\"));
    QCOMPARE(WindowsTunnelService::pipeName(), QString::fromLatin1(prefix) + "MayakVPN");
    QVERIFY(!WindowsTunnelService::pipeName().startsWith("\\\\.\\pipe\\ProtectedPrefix\\Administrators\\MayakWG\\"));
    qInfo() << "DLL_SHA256" << QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex();
  }
};
QTEST_GUILESS_MAIN(WindowsUapiTransactionTest)
#include "testWindowsUapiTransaction.moc"
