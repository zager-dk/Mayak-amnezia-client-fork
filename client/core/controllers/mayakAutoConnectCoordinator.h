#pragma once

// Pure, thread-affine coordinator for selecting and proving an owned tunnel.
// One admitted allocation (one place on one exit) may be reached by several paths:
// the native AWG configuration and Xray containers of the same exit (5.1.0.21+).
// Production transport/platform adapters are deliberately not wired here.

#include <cstdint>
#include <functional>
#include <memory>
#include <map>
#include <string>
#include <tuple>
#include <vector>

namespace mayak::autoconnect {

using Millis = std::int64_t;
using CycleId = std::uint64_t;
using AttemptId = std::uint64_t;

struct Candidate {
    std::string id;
    std::string publicIpv4;
    std::uint16_t port = 0;
    bool preferred = false;
    std::vector<std::string> expectedEgressIps;
};

struct Snapshot {
    int schemaVersion = 0;
    std::string revision;
    Millis expiresAt = 0; // monotonic milliseconds in the injected clock domain
    std::vector<Candidate> candidates;
};
enum class FetchStatus { Success, NetworkError, AuthRevoked, AccountExpired, Unsupported, Malformed };

enum class AdmissionStatus { Admitted, Full, NotReady, Disabled, AuthRevoked,
                             AccountExpired, Unsupported, Malformed, NetworkError };
// A way to reach the admitted exit. Paths of one allocation share its place on the exit:
// switching paths never releases the allocation; proven/release always name it.
enum class PathKind { Awg, Xray };
struct Path {
    std::string id; // "awg" or "xray-<fingerprint>"
    PathKind kind = PathKind::Awg;
};
struct Allocation {
    std::string id;                 // opaque exact allocation handle
    std::string nativeConfiguration; // unchanged adapter-owned native AWG config
    std::vector<Path> paths;        // adapter order; empty means the single AWG path
    bool pathsExplicit = false;     // empty `paths` means none (e.g. "only Xray" without Xray)
};
// Race of the Xray paths of one allocation before any of them starts a tunnel.
// ran=false: the race could not run; the paths are tried in their given order.
// ran=true: only `passed` paths (in answer order) are tried; the rest are dropped.
struct RaceResult { bool ran = false; std::vector<std::string> passed; };
struct AdmissionResult {
    AdmissionStatus status = AdmissionStatus::NetworkError;
    Allocation allocation;
};
enum class StartStatus { Started, NetworkError, CryptoError, MalformedConfig, Unsupported };
struct StartResult { StartStatus status = StartStatus::NetworkError; };

// Proof is deliberately evidence-bearing. A generic HTTP/ping bool cannot be
// represented. The adapter must establish these facts for this device's peer;
// ownPeerId is trusted only because the future adapter enforces owned-peer scope.
struct OwnTunnelProof {
    bool certificateValid = false;
    bool nonceMatched = false;
    std::string nonce;
    std::string observedEgressIp;
    std::string ownPeerId;
    Millis handshakeAt = 0;
    std::uint64_t rxBytesBefore = 0;
    std::uint64_t rxBytesAfter = 0;
    bool counterReset = false;
    bool peerHandshakeObserved = false;
    // Adopted running session (cold-start adoption): its handshake may predate the attempt,
    // bounded by the adapter to WireGuard's live-session window (180 s before `now`).
    bool adoptedLiveSession = false;
    // Xray path: there is no peer telemetry. The adapter states which path the probe ran
    // through, that its socket was bound to that path's own tunnel interface, and when the
    // probe started (it must start after this path started).
    std::string pathId;
    bool interfaceBound = false;
    Millis probeStartedAt = 0;
};
struct ProofResult { bool probeSucceeded = false; OwnTunnelProof evidence; };
struct StopResult { bool confirmedDisconnected = false; };

enum class State { Idle, Fetching, Admitting, Racing, Starting, Verifying, Connected,
                   Stopping, Failed, Cancelled };
enum class ErrorCategory { None, Network, Capacity, NotReady, Disabled, AuthRevoked,
                           AccountExpired, Unsupported, Malformed, CryptoHealth,
                           ProofFailed, Deadline, StopUnconfirmed, Cancelled };
struct Status {
    State state = State::Idle;
    ErrorCategory error = ErrorCategory::None;
    CycleId cycle = 0;
    AttemptId attempt = 0;
    std::string candidateId;
    std::string pathId; // path of the current/connected tunnel; empty before a start
    bool switchingPath = false; // Stopping only to start the next path of the same allocation
};

// Phase budgets (milliseconds). Process-wide so tests can shorten them.
struct Timing {
    Millis fetchMs = 10000;
    Millis cycleMs = 30000;          // AWG-only allocation
    Millis cycleWithXrayMs = 50000;  // an allocation that also offers Xray paths
    Millis admitMs = 8000;           // acquire request
    Millis startMs = 8000;           // until the backend reports Started
    Millis awgVerifyMs = 6000;       // handshake + probe after Started
    Millis xrayVerifyMs = 8000;      // probe through the Xray tunnel after Started
    Millis raceMs = 6000;            // parallel check of the Xray paths
    Millis stopMs = 3000;
};

struct Clock { virtual ~Clock() = default; virtual Millis now() const = 0; };

// Adapter methods initiate operations promptly; completions and public commands
// may reenter synchronously on the owning thread. Observer receives a snapshot.
// Every ordinary effect is phase-token checked after notification; scoped cancel,
// stop and exact lease cleanup remain committed even if notification destroys
// the owner. Destruction suppresses notifications and performs only owned cleanup.
// Adapter arguments are borrowed only for the duration of the method call; copy
// them before retaining them asynchronously. Clock::now must be side-effect-free.
// Callbacks must return normally; throwing or an infinitely recursive client
// command stream is outside the lifecycle contract.
// Ownership/lifetime contract: Adapter and injected Clock outlive Coordinator
// and every pending callback/release cleanup; callbacks are marshalled to the owning thread;
// cancelOwned prevents a pending start from activating after cancellation and
// is scoped to its tags; stopAndConfirm is idempotent and scoped to its tags;
// releaseAllocation is scoped to the exact allocation and original tags. Late
// callbacks after Coordinator destruction are gated and may only perform exact
// lease cleanup through this still-live Adapter.
struct Adapter {
    using FetchDone = std::function<void(CycleId, AttemptId, FetchStatus, Snapshot)>;
    using AdmissionDone = std::function<void(CycleId, AttemptId, AdmissionResult)>;
    using StartDone = std::function<void(CycleId, AttemptId, StartResult)>;
    using ProofDone = std::function<void(CycleId, AttemptId, ProofResult)>;
    using StopDone = std::function<void(CycleId, AttemptId, StopResult)>;
    using BasicDone = std::function<void(CycleId, AttemptId)>;
    using RaceDone = std::function<void(CycleId, AttemptId, RaceResult)>;
    virtual ~Adapter() = default;
    virtual void fetchFresh(CycleId, AttemptId, Millis deadline, FetchDone) = 0;
    virtual void acquire(CycleId, AttemptId, const Candidate&, Millis deadline, AdmissionDone) = 0;
    // Starts exactly `path` of the allocation. At most one path runs at a time: the
    // previous path's stop was confirmed before this call.
    virtual void start(CycleId, AttemptId, const Allocation&, const Path& path, Millis deadline, StartDone) = 0;
    virtual void verifyOwnTunnel(CycleId, AttemptId, const Path& path, const std::string& nonce,
                                 const std::vector<std::string>& expectedEgress,
                                 Millis deadline, ProofDone) = 0;
    // Checks the given Xray paths in parallel WITHOUT a tunnel (no routes change) and
    // completes by `deadline`. Never evidence of a connection: only an order of paths.
    virtual void racePaths(CycleId, AttemptId, const std::vector<Path>& paths,
                           const std::vector<std::string>& expectedEgress, Millis deadline, RaceDone) = 0;
    virtual void stopAndConfirm(CycleId, AttemptId, Millis deadline, StopDone) = 0;
    virtual void releaseAllocation(CycleId, AttemptId, const std::string& exactAllocationId,
                                   BasicDone) = 0;
    virtual void reportProven(CycleId, AttemptId, const std::string& candidateId,
                              BasicDone) = 0;
    virtual void cancelOwned(CycleId, AttemptId) = 0;
};

class Coordinator final {
public:
    using Observer = std::function<void(const Status&)>;
    Coordinator(Clock&, Adapter&, Observer = {});
    ~Coordinator();
    Coordinator(const Coordinator&) = delete;
    Coordinator& operator=(const Coordinator&) = delete;
    void begin();
    void cancel();
    void tick(); // drive finite deadlines; caller schedules it on owning thread
    // Degradation policy: retry only after two failed probes AND observed own
    // telemetry degradation. API/control failures alone never disconnect.
    void onConnectedProbe(CycleId, bool probeSucceeded, bool ownTelemetryDegraded);
    // The platform's own repair (service watchdog: degraded own-peer telemetry, soft backend
    // replacements did not help) gave up: end this connected cycle like two degraded failures.
    void onOwnRepairExhausted(CycleId);
    const Status& status() const noexcept { return status_; }
    Millis overallDeadline() const noexcept { return overallDeadline_; }
    static bool isValidPublicIpv4(const std::string&);
    static bool proofMatches(const OwnTunnelProof&, const std::string& nonce,
                             const Candidate&, Millis attemptStarted, Millis now);
    static bool xrayProofMatches(const OwnTunnelProof&, const std::string& nonce, const Candidate&,
                                 const std::string& pathId, Millis pathStarted, Millis now);
    static Timing& timing();

private:
    // A successful admission transfers its exact handle here BEFORE deadline or
    // payload validation. All completion paths share this release-once owner.
    // No native configuration is retained by the callback lifetime ledger.
    struct AllocationOwner {
        Adapter* adapter;
        CycleId cycle;
        AttemptId attempt;
        std::string id;
        bool releaseRequested = false;
        bool backendClaimed = false; // only stop confirmation may release it
        void release(Adapter::BasicDone = {});
    };
    struct AdmissionLedger {
        Adapter* adapter = nullptr;
        using Key = std::tuple<CycleId, AttemptId, std::string>;
        std::map<Key, std::shared_ptr<AllocationOwner>> allocations;
        std::shared_ptr<AllocationOwner> accept(CycleId, AttemptId, const AdmissionResult&);
    };
    struct CallbackGate { Coordinator* owner = nullptr; };
    // Adapter-supplied callbacks are the completion ingress. In particular an
    // admission must carry the receipt owned by its original acquire callback.
    void onFetch(CycleId, AttemptId, FetchStatus, Snapshot);
    void onAdmission(CycleId, AttemptId, AdmissionResult, std::shared_ptr<AllocationOwner>);
    void onStart(CycleId, AttemptId, StartResult);
    void onProof(CycleId, AttemptId, ProofResult);
    void onStop(CycleId, AttemptId, StopResult);
    void onReport(CycleId, AttemptId);
    void onRace(CycleId, AttemptId, std::uint64_t pathSeq, RaceResult);
    struct Item { Candidate candidate; };
    // NextPath: stop the running path, keep the allocation, start the following path.
    enum class StopPurpose { Retry, Finish, Cancel, NextPath };
    struct PhaseToken {
        std::shared_ptr<CallbackGate> gate;
        std::uint64_t generation;
        bool valid() const;
    };
    PhaseToken publish(State, ErrorCategory = ErrorCategory::None);
    PhaseToken checkpoint() const;
    void cancelCurrent();
    void finishReleased();
    void fail(ErrorCategory);
    void tryNext();
    void beginStop(StopPurpose, ErrorCategory, std::shared_ptr<AllocationOwner> unusedAdmission = {});
    void releaseThen(StopPurpose, ErrorCategory);
    void startAttempt();
    void startPath();
    void beginRace();
    void failPath(ErrorCategory, bool fatalIfLast);
    const Path& currentPath() const { return paths_.at(pathIndex_); }
    std::string makeNonce();
    bool current(CycleId, AttemptId) const;

    Clock& clock_; Adapter& adapter_; std::shared_ptr<Observer> observer_; Status status_;
    std::shared_ptr<CallbackGate> callbackGate_;
    std::uint64_t transitionGeneration_ = 0;
    CycleId nextCycle_ = 0; AttemptId nextAttempt_ = 0;
    Millis overallDeadline_ = 0, snapshotExpiresAt_ = 0, attemptStarted_ = 0, phaseDeadline_ = 0;
    Millis pathStarted_ = 0;
    std::vector<Path> paths_; std::size_t pathIndex_ = 0; bool raced_ = false;
    std::uint64_t pathSeq_ = 0; // closes the ingress of a superseded path/race
    std::vector<Item> candidates_; std::size_t nextCandidate_ = 0;
    Candidate currentCandidate_; Allocation allocation_; std::string nonce_;
    std::shared_ptr<AllocationOwner> allocationOwner_;
    bool backendMayBeRunning_ = false, awaitingRelease_ = false;
    bool restartAfterStop_ = false;
    StopPurpose stopPurpose_ = StopPurpose::Finish;
    ErrorCategory pendingError_ = ErrorCategory::None;
    int degradedProbeFailures_ = 0;
};

} // namespace mayak::autoconnect
