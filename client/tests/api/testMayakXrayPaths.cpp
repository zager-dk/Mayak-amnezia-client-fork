// Mayak 5.1.0.21 «4 пути»: admission xray_paths parsing and the coordinator's path sequence
// (AWG + Xray paths of ONE allocation, race order, proof rules). Isolated: no network, no VPN.
#include <QJsonArray>
#include <QJsonDocument>
#include <QTest>
#include <QUuid>
#include <deque>
#include <functional>
#include "core/controllers/api/mayakAdmissionClient.h"
#include "core/controllers/mayakAutoConnectCoordinator.h"

namespace ad = mayak::admission;
namespace ac = mayak::autoconnect;

namespace {
QString guid() { return QUuid::createUuid().toString(QUuid::WithoutBraces); }
const QString kHost = QStringLiteral("81.29.149.103");

QString clientJson(const QString &host, const QString &fp) {
    const QJsonObject user{{"id", guid()}, {"encryption", "none"}};
    const QJsonObject stream{{"network", "xhttp"}, {"security", "reality"},
        {"realitySettings", QJsonObject{{"fingerprint", fp}, {"serverName", "example.org"}, {"publicKey", "pk"}, {"shortId", "ab"}}},
        {"xhttpSettings", QJsonObject{{"host", "example.org"}, {"path", "/p"}, {"mode", "auto"}}}};
    const QJsonObject root{{"inbounds", QJsonArray{QJsonObject{{"listen", "127.0.0.1"}, {"port", 10808}, {"protocol", "socks"}}}},
        {"outbounds", QJsonArray{QJsonObject{{"protocol", "vless"},
            {"settings", QJsonObject{{"vnext", QJsonArray{QJsonObject{{"address", host}, {"port", 443}, {"users", QJsonArray{user}}}}}}},
            {"streamSettings", stream}}}}};
    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Compact));
}
QString vpnKey(const QString &host, const QString &fp, const QString &rootHost = QString(), const QString &containerFp = QString()) {
    const QJsonObject xray{{"port", "443"}, {"xray_fingerprint", containerFp.isEmpty() ? fp : containerFp},
                           {"last_config", clientJson(host, fp)}};
    const QJsonObject container{{"container", "amnezia-xray"}, {"xray", xray}};
    const QJsonObject root{{"config_version", 2}, {"hostName", rootHost.isEmpty() ? host : rootHost},
                           {"defaultContainer", "amnezia-xray"}, {"containers", QJsonArray{container}}};
    return "vpn://" + QString::fromUtf8(qCompress(QJsonDocument(root).toJson(QJsonDocument::Compact))
                                            .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}
QJsonObject pathsObject(const QStringList &fps, const QString &host = kHost) {
    QJsonArray paths;
    for (const auto &fp : fps) paths.append(QJsonObject{{"id", "xray-" + fp}, {"fingerprint", fp}, {"config", vpnKey(host, fp)}});
    return {{"schema", 1}, {"paths", paths}};
}
QByteArray acquireBody(const QJsonValue &paths) {
    QJsonObject body{{"allocation_id", guid()}, {"connect_before", QDateTime::currentDateTimeUtc().addSecs(30).toString(Qt::ISODate)},
                     {"config_revision", 14}, {"config", "vpn://awg"}};
    if (!paths.isUndefined()) body.insert("xray_paths", paths);
    return QJsonDocument(body).toJson(QJsonDocument::Compact);
}

// ---------- coordinator fixture ----------
struct ManualClock : ac::Clock {
    ac::Millis t = 1000000;
    ac::Millis now() const override { return t; }
};
struct FakeAdapter : ac::Adapter {
    ManualClock *clock = nullptr;
    std::vector<std::string> log;
    std::vector<ac::Path> paths;          // offered by acquire
    std::function<ac::RaceResult(const std::vector<ac::Path>&)> race; // empty: race not run
    std::function<bool(const ac::Path&)> works = [](const ac::Path&) { return true; };
    int releases = 0, proven = 0, stops = 0;
    std::string candidateEgress = "81.29.149.103";
    void fetchFresh(ac::CycleId c, ac::AttemptId a, ac::Millis, FetchDone done) override {
        log.push_back("fetch");
        ac::Snapshot s; s.schemaVersion = 1; s.revision = "1"; s.expiresAt = clock->now() + 3600000;
        s.candidates.push_back({guid().toStdString(), "81.29.149.103", 49963, true, {candidateEgress}});
        done(c, a, ac::FetchStatus::Success, s);
    }
    void acquire(ac::CycleId c, ac::AttemptId a, const ac::Candidate&, ac::Millis, AdmissionDone done) override {
        log.push_back("acquire");
        ac::AdmissionResult r; r.status = ac::AdmissionStatus::Admitted;
        r.allocation = {"alloc-1", "native", paths, true};
        done(c, a, r);
    }
    void start(ac::CycleId c, ac::AttemptId a, const ac::Allocation& allocation, const ac::Path& path, ac::Millis, StartDone done) override {
        log.push_back("start:" + path.id + "@" + allocation.id);
        done(c, a, {ac::StartStatus::Started});
    }
    void verifyOwnTunnel(ac::CycleId c, ac::AttemptId a, const ac::Path& path, const std::string& nonce,
                         const std::vector<std::string>&, ac::Millis, ProofDone done) override {
        log.push_back("verify:" + path.id);
        ac::ProofResult r;
        if (!works(path)) { done(c, a, r); return; }
        r.probeSucceeded = true;
        auto& e = r.evidence;
        e.certificateValid = true; e.nonceMatched = true; e.nonce = nonce; e.observedEgressIp = candidateEgress;
        if (path.kind == ac::PathKind::Awg) {
            e.ownPeerId = "peer"; e.handshakeAt = clock->now(); e.rxBytesBefore = 1; e.rxBytesAfter = 2; e.peerHandshakeObserved = true;
        } else {
            e.pathId = path.id; e.interfaceBound = true; e.probeStartedAt = clock->now();
        }
        done(c, a, r);
    }
    void racePaths(ac::CycleId c, ac::AttemptId a, const std::vector<ac::Path>& xray, const std::vector<std::string>&,
                   ac::Millis, RaceDone done) override {
        std::string ids; for (const auto& p : xray) ids += (ids.empty() ? "" : ",") + p.id;
        log.push_back("race:" + ids);
        if (!race) { done(c, a, {false, {}}); return; }
        done(c, a, race(xray));
    }
    void stopAndConfirm(ac::CycleId c, ac::AttemptId a, ac::Millis, StopDone done) override {
        ++stops; log.push_back("stop"); done(c, a, {true});
    }
    void releaseAllocation(ac::CycleId c, ac::AttemptId a, const std::string& id, BasicDone done) override {
        ++releases; log.push_back("release:" + id); done(c, a);
    }
    void reportProven(ac::CycleId c, ac::AttemptId a, const std::string&, BasicDone done) override {
        ++proven; log.push_back("proven"); done(c, a);
    }
    void cancelOwned(ac::CycleId, ac::AttemptId) override {}
};
const ac::Path kAwg{"awg", ac::PathKind::Awg};
ac::Path xp(const std::string& fp) { return {"xray-" + fp, ac::PathKind::Xray}; }
std::vector<std::string> starts(const FakeAdapter& f) {
    std::vector<std::string> out;
    for (const auto& line : f.log) if (line.rfind("start:", 0) == 0) out.push_back(line.substr(6, line.find('@') - 6));
    return out;
}
} // namespace

class XrayPathsTest : public QObject {
    Q_OBJECT
private slots:
    void acquireWithoutXrayPathsIsUnchanged() {
        ad::AcquireResponse r;
        QVERIFY(ad::parseAcquireResponse(acquireBody(QJsonValue(QJsonValue::Undefined)), &r));
        QVERIFY(!r.xrayPathsOffered);
        QVERIFY(r.xrayPaths.isEmpty());
    }
    void validXrayPathsKeepServerOrder() {
        ad::AcquireResponse r;
        QVERIFY(ad::parseAcquireResponse(acquireBody(pathsObject({"firefox", "safari", "chrome"})), &r));
        QVERIFY(r.xrayPathsOffered);
        QCOMPARE(r.xrayPaths.size(), 3);
        QCOMPARE(r.xrayPaths.at(0).id, QStringLiteral("xray-firefox"));
        QCOMPARE(r.xrayPaths.at(2).fingerprint, QStringLiteral("chrome"));
        ad::XrayPathConfig cfg;
        QVERIFY(ad::decodeXrayPathConfig(r.xrayPaths.at(0), kHost, &cfg));
        QCOMPARE(cfg.root.value("defaultContainer").toString(), QStringLiteral("amnezia-xray"));
    }
    void malformedXrayPathsNeverBreakTheAwgAllocation() {
        QJsonObject dup = pathsObject({"firefox", "firefox"});
        QJsonObject badSchema = pathsObject({"firefox"}); badSchema["schema"] = 2;
        QJsonObject unknownFp = pathsObject({"netscape"});
        QJsonObject idMismatch = pathsObject({"firefox"});
        { auto arr = idMismatch["paths"].toArray(); auto o = arr[0].toObject(); o["id"] = "xray-safari"; arr[0] = o; idMismatch["paths"] = arr; }
        QJsonObject tooMany = pathsObject({"firefox", "safari", "chrome", "ios", "edge"});
        QJsonObject stringSchema = pathsObject({"firefox"}); stringSchema["schema"] = "1";
        for (const QJsonValue &bad : {QJsonValue(dup), QJsonValue(badSchema), QJsonValue(unknownFp), QJsonValue(idMismatch),
                                      QJsonValue(tooMany), QJsonValue(stringSchema), QJsonValue(QJsonArray{}), QJsonValue("x")}) {
            ad::AcquireResponse r;
            QVERIFY(ad::parseAcquireResponse(acquireBody(bad), &r));
            QVERIFY(r.xrayPathsOffered);
            QVERIFY(r.xrayPaths.isEmpty());
            QVERIFY(!r.xrayPathsRejected.isEmpty());
        }
    }
    void pathConfigIsBoundToTheAdmittedHostAndFingerprint() {
        ad::XrayPath ok{"xray-firefox", "firefox", vpnKey(kHost, "firefox")};
        ad::XrayPathConfig cfg;
        QVERIFY(ad::decodeXrayPathConfig(ok, kHost, &cfg));
        QVERIFY(!ad::decodeXrayPathConfig(ok, QStringLiteral("81.29.149.104"), &cfg));          // other exit
        QVERIFY(!ad::decodeXrayPathConfig({"xray-firefox", "firefox", vpnKey("1.2.3.4", "firefox", kHost)}, kHost, &cfg)); // outbound elsewhere
        QVERIFY(!ad::decodeXrayPathConfig({"xray-firefox", "firefox", vpnKey(kHost, "chrome")}, kHost, &cfg));            // other fingerprint
        QVERIFY(!ad::decodeXrayPathConfig({"xray-firefox", "firefox", vpnKey(kHost, "firefox", {}, "chrome")}, kHost, &cfg));
        QVERIFY(!ad::decodeXrayPathConfig({"xray-firefox", "firefox", "vpn://not-base64!"}, kHost, &cfg));
    }
    void acquirePayloadAsksForPathsOnlyWhenRequested() {
        ad::Request req; req.action = "acquire"; req.attemptId = QStringLiteral("attempt_0123456789abcdef"); req.candidateId = guid();
        req.commonPayload = {{"auth_data", QJsonObject{{"api_key", "k"}}}, {"installation_uuid", "i"}, {"public_key", "p"},
                             {"mayak_paths", 7}};
        bool valid = false;
        QVERIFY(!ad::buildPayload(req, &valid).contains("mayak_paths"));
        QVERIFY(valid);
        req.requestPaths = true;
        const auto payload = ad::buildPayload(req, &valid);
        QVERIFY(payload.value("mayak_paths").isDouble());
        QCOMPARE(payload.value("mayak_paths").toInt(), 1);
        req.action = "release"; req.allocationId = guid();
        QVERIFY(!ad::buildPayload(req, &valid).contains("mayak_paths"));
    }

    // ---------- coordinator ----------
    void awgWorkingConnectsWithoutAnyXray() {
        ManualClock clock; FakeAdapter f; f.clock = &clock; f.paths = {kAwg, xp("firefox"), xp("safari")};
        ac::Coordinator c(clock, f); c.begin();
        QCOMPARE(c.status().state, ac::State::Connected);
        QCOMPARE(c.status().pathId, std::string("awg"));
        QCOMPARE(starts(f), std::vector<std::string>{"awg"});
        QCOMPARE(f.releases, 0);
    }
    void awgFailureMovesToRacedXrayOnTheSameAllocation() {
        ManualClock clock; FakeAdapter f; f.clock = &clock; f.paths = {kAwg, xp("firefox"), xp("safari"), xp("chrome")};
        f.works = [](const ac::Path& p) { return p.id == "xray-safari"; };
        f.race = [](const std::vector<ac::Path>&) { return ac::RaceResult{true, {"xray-safari", "xray-firefox"}}; };
        ac::Coordinator c(clock, f); c.begin();
        QCOMPARE(c.status().state, ac::State::Connected);
        QCOMPARE(c.status().pathId, std::string("xray-safari"));
        // AWG first, then the race over all Xray paths, then the fastest one; chrome dropped.
        QCOMPARE(starts(f), (std::vector<std::string>{"awg", "xray-safari"}));
        QVERIFY(std::find(f.log.begin(), f.log.end(), "race:xray-firefox,xray-safari,xray-chrome") != f.log.end());
        // The place on the exit is kept between paths: no release, every start names alloc-1.
        QCOMPARE(f.releases, 0);
        for (const auto& line : f.log) if (line.rfind("start:", 0) == 0) QVERIFY(line.find("@alloc-1") != std::string::npos);
        QCOMPARE(f.proven, 1);
    }
    void raceWinnerFailingFallsBackToTheNextRacedPath() {
        ManualClock clock; FakeAdapter f; f.clock = &clock; f.paths = {kAwg, xp("firefox"), xp("safari"), xp("chrome")};
        f.works = [](const ac::Path& p) { return p.id == "xray-firefox"; };
        f.race = [](const std::vector<ac::Path>&) { return ac::RaceResult{true, {"xray-safari", "xray-firefox"}}; };
        ac::Coordinator c(clock, f); c.begin();
        QCOMPARE(c.status().pathId, std::string("xray-firefox"));
        QCOMPARE(starts(f), (std::vector<std::string>{"awg", "xray-safari", "xray-firefox"}));
    }
    void raceWithNoAnswerDropsXrayAndReleases() {
        ManualClock clock; FakeAdapter f; f.clock = &clock; f.paths = {kAwg, xp("firefox"), xp("safari")};
        f.works = [](const ac::Path&) { return false; };
        f.race = [](const std::vector<ac::Path>&) { return ac::RaceResult{true, {}}; };
        ac::Coordinator c(clock, f); c.begin();
        QCOMPARE(c.status().state, ac::State::Failed);
        QCOMPARE(starts(f), std::vector<std::string>{"awg"});
        QCOMPARE(f.releases, 1);
    }
    void raceUnavailableTriesXrayInServerOrder() {
        ManualClock clock; FakeAdapter f; f.clock = &clock; f.paths = {kAwg, xp("firefox"), xp("safari")};
        f.works = [](const ac::Path& p) { return p.id == "xray-safari"; };
        ac::Coordinator c(clock, f); c.begin();
        QCOMPARE(c.status().pathId, std::string("xray-safari"));
        QCOMPARE(starts(f), (std::vector<std::string>{"awg", "xray-firefox", "xray-safari"}));
    }
    void xrayFirstOrderStillFallsBackToAwg() {
        ManualClock clock; FakeAdapter f; f.clock = &clock; f.paths = {xp("firefox"), xp("safari"), kAwg};
        f.works = [](const ac::Path& p) { return p.kind == ac::PathKind::Awg; };
        f.race = [](const std::vector<ac::Path>&) { return ac::RaceResult{true, {}}; };
        ac::Coordinator c(clock, f); c.begin();
        QCOMPARE(c.status().pathId, std::string("awg"));
        QCOMPARE(starts(f), std::vector<std::string>{"awg"});
    }
    void explicitEmptyPathsIsUnsupported() {
        ManualClock clock; FakeAdapter f; f.clock = &clock; f.paths = {};
        ac::Coordinator c(clock, f); c.begin();
        QCOMPARE(c.status().state, ac::State::Failed);
        QCOMPARE(c.status().error, ac::ErrorCategory::Unsupported);
        QVERIFY(starts(f).empty());
        QCOMPARE(f.releases, 1);
    }
    void xrayProofNeedsItsOwnInterfaceProbeAfterThePathStarted() {
        const ac::Candidate cand{"c", "81.29.149.103", 443, true, {"81.29.149.103"}};
        ac::OwnTunnelProof p; p.certificateValid = true; p.nonceMatched = true; p.nonce = "n"; p.observedEgressIp = "81.29.149.103";
        p.pathId = "xray-firefox"; p.interfaceBound = true; p.probeStartedAt = 100;
        QVERIFY(ac::Coordinator::xrayProofMatches(p, "n", cand, "xray-firefox", 100, 200));
        QVERIFY(!ac::Coordinator::xrayProofMatches(p, "n", cand, "xray-safari", 100, 200));   // another path
        QVERIFY(!ac::Coordinator::xrayProofMatches(p, "n", cand, "xray-firefox", 101, 200));  // probe before start
        QVERIFY(!ac::Coordinator::xrayProofMatches(p, "m", cand, "xray-firefox", 100, 200));  // nonce
        auto q = p; q.interfaceBound = false;
        QVERIFY(!ac::Coordinator::xrayProofMatches(q, "n", cand, "xray-firefox", 100, 200));
        q = p; q.observedEgressIp = "1.1.1.1";
        QVERIFY(!ac::Coordinator::xrayProofMatches(q, "n", cand, "xray-firefox", 100, 200));
        q = p; q.certificateValid = false;
        QVERIFY(!ac::Coordinator::xrayProofMatches(q, "n", cand, "xray-firefox", 100, 200));
        // An Xray proof can never stand in for an AWG proof (no peer telemetry).
        QVERIFY(!ac::Coordinator::proofMatches(p, "n", cand, 100, 200));
    }
    void cancelDuringRaceReleasesWithoutStartingATunnel() {
        ManualClock clock; FakeAdapter f; f.clock = &clock; f.paths = {xp("firefox"), xp("safari")};
        ac::Adapter::RaceDone held;
        struct HoldRace : FakeAdapter {
            ac::Adapter::RaceDone* slot = nullptr;
            void racePaths(ac::CycleId, ac::AttemptId, const std::vector<ac::Path>&, const std::vector<std::string>&,
                           ac::Millis, RaceDone done) override { *slot = std::move(done); log.push_back("race_held"); }
        } h; h.clock = &clock; h.paths = f.paths; h.slot = &held;
        ac::Coordinator c(clock, h); c.begin();
        QCOMPARE(c.status().state, ac::State::Racing);
        c.cancel();
        QCOMPARE(c.status().state, ac::State::Cancelled);
        QCOMPARE(h.releases, 1);
        QVERIFY(starts(h).empty());
        // A late race answer changes nothing.
        held(c.status().cycle, c.status().attempt, {true, {"xray-firefox"}});
        QVERIFY(starts(h).empty());
    }
    void raceDeadlineDropsXray() {
        ManualClock clock;
        struct HoldRace : FakeAdapter {
            void racePaths(ac::CycleId, ac::AttemptId, const std::vector<ac::Path>&, const std::vector<std::string>&,
                           ac::Millis, RaceDone) override { log.push_back("race_silent"); }
        } h; h.clock = &clock; h.paths = {kAwg, xp("firefox")};
        h.works = [](const ac::Path&) { return false; };
        ac::Coordinator c(clock, h); c.begin();
        QCOMPARE(c.status().state, ac::State::Racing);
        clock.t += ac::Coordinator::timing().raceMs;
        c.tick();
        QCOMPARE(c.status().state, ac::State::Failed);
        QCOMPARE(starts(h), std::vector<std::string>{"awg"});
        QCOMPARE(h.releases, 1);
    }
};

QTEST_GUILESS_MAIN(XrayPathsTest)
#include "testMayakXrayPaths.moc"
