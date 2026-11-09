#pragma once

// Pure, thread-affine coordinator for selecting and proving an owned AWG tunnel.
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
struct Allocation {
    std::string id;                 // opaque exact allocation handle
    std::string nativeConfiguration; // unchanged adapter-owned native AWG config
};
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
};
struct ProofResult { bool probeSucceeded = false; OwnTunnelProof evidence; };
struct StopResult { bool confirmedDisconnected = false; };

enum class State { Idle, Fetching, Admitting, Starting, Verifying, Connected,
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
    virtual ~Adapter() = default;
    virtual void fetchFresh(CycleId, AttemptId, Millis deadline, FetchDone) = 0;
    virtual void acquire(CycleId, AttemptId, const Candidate&, Millis deadline, AdmissionDone) = 0;
    virtual void start(CycleId, AttemptId, const Allocation&, Millis deadline, StartDone) = 0;
    virtual void verifyOwnTunnel(CycleId, AttemptId, const std::string& nonce,
                                 const std::vector<std::string>& expectedEgress,
                                 Millis deadline, ProofDone) = 0;
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
    struct Item { Candidate candidate; };
    enum class StopPurpose { Retry, Finish, Cancel };
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
    std::string makeNonce();
    bool current(CycleId, AttemptId) const;

    Clock& clock_; Adapter& adapter_; std::shared_ptr<Observer> observer_; Status status_;
    std::shared_ptr<CallbackGate> callbackGate_;
    std::uint64_t transitionGeneration_ = 0;
    CycleId nextCycle_ = 0; AttemptId nextAttempt_ = 0;
    Millis overallDeadline_ = 0, snapshotExpiresAt_ = 0, attemptStarted_ = 0, phaseDeadline_ = 0;
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
