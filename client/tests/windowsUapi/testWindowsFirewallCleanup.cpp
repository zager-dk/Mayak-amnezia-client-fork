#include <QtTest>
#include <QMultiMap>
#include "nativeApiFakes.h"
#define private public
#include "platforms/windows/daemon/windowsfirewall.h"
#undef private
class WindowsFirewallCleanupTest : public QObject {
  Q_OBJECT
private slots:
  void init() { testapi::state = {}; }
  void retainsInputs_data() {
    QTest::addColumn<bool>("all"); QTest::addColumn<bool>("commitFailure");
    QTest::newRow("peer-delete") << false << false;
    QTest::newRow("peer-commit") << false << true;
    QTest::newRow("all-delete") << true << false;
    QTest::newRow("all-commit") << true << true;
  }
  void retainsInputs() {
    QFETCH(bool, all); QFETCH(bool, commitFailure);
    WindowsFirewall fw(nullptr, nullptr);
    fw.m_activeRules = {11, 12}; fw.m_peerRules.insert("A", 21); fw.m_peerRules.insert("B", 22);
    const auto rules = fw.m_peerRules; const auto active = fw.m_activeRules;
    if (commitFailure) testapi::state.wfpCommitResult = ERROR_ACCESS_DENIED;
    else testapi::state.wfpDeleteResult = ERROR_ACCESS_DENIED;
    QVERIFY(!(all ? fw.allowAllTraffic() : fw.disablePeerTraffic("A")));
    QCOMPARE(fw.m_peerRules, rules); QCOMPARE(fw.m_activeRules, active);
    QCOMPARE(testapi::state.wfpAborts, 1);
    testapi::state.wfpDeleteResult = testapi::state.wfpCommitResult = ERROR_SUCCESS;
    QVERIFY(all ? fw.allowAllTraffic() : fw.disablePeerTraffic("A"));
    if (all) { QVERIFY(fw.m_peerRules.isEmpty()); QVERIFY(fw.m_activeRules.isEmpty()); }
    else { QVERIFY(!fw.m_peerRules.contains("A")); QVERIFY(fw.m_peerRules.contains("B")); QCOMPARE(fw.m_activeRules, active); }
    QVERIFY(all ? fw.allowAllTraffic() : fw.disablePeerTraffic("A"));
  }
  void alreadyAbsentFilterIsIdempotent() {
    WindowsFirewall fw(nullptr, nullptr); fw.m_activeRules = {11}; fw.m_peerRules.insert("A", 21);
    testapi::state.wfpDeleteResult = FWP_E_FILTER_NOT_FOUND;
    QVERIFY(fw.allowAllTraffic()); QVERIFY(fw.m_activeRules.isEmpty()); QVERIFY(fw.m_peerRules.isEmpty());
  }
};
QTEST_GUILESS_MAIN(WindowsFirewallCleanupTest)
#include "testWindowsFirewallCleanup.moc"
