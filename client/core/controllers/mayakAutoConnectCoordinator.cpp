#include "mayakAutoConnectCoordinator.h"

#include <algorithm>
#include <array>
#include <random>
#include <sstream>
#include <unordered_set>

namespace mayak::autoconnect {
namespace {
bool parseIpv4(const std::string& s, std::array<unsigned, 4>& out) {
    std::size_t start = 0;
    for (unsigned i = 0; i < 4; ++i) {
        const auto end = s.find('.', start);
        if ((i < 3 && end == std::string::npos) || (i == 3 && end != std::string::npos)) return false;
        const auto stop = end == std::string::npos ? s.size() : end;
        if (stop == start || stop - start > 3) return false;
        unsigned value = 0;
        for (auto p = start; p < stop; ++p) {
            if (s[p] < '0' || s[p] > '9') return false;
            value = value * 10 + static_cast<unsigned>(s[p] - '0');
        }
        if (value > 255) return false;
        out[i] = value;
        start = stop + 1;
    }
    return true;
}
bool in(const std::array<unsigned, 4>& a, unsigned x, unsigned y = 0) {
    return a[0] == x && a[1] == y;
}
} // namespace

void Coordinator::AllocationOwner::release(Adapter::BasicDone done) {
    if (releaseRequested) return;
    releaseRequested = true; // set before calling a potentially synchronous adapter
    adapter->releaseAllocation(cycle, attempt, id, done ? std::move(done) : [](CycleId, AttemptId) {});
}

std::shared_ptr<Coordinator::AllocationOwner> Coordinator::AdmissionLedger::accept(
        CycleId cycle, AttemptId attempt, const AdmissionResult& result) {
    if (result.status != AdmissionStatus::Admitted || result.allocation.id.empty()) return {};
    const Key key{cycle, attempt, result.allocation.id};
    auto& allocation = allocations[key];
    if (!allocation) allocation = std::make_shared<AllocationOwner>(AllocationOwner{
        adapter, cycle, attempt, result.allocation.id});
    return allocation;
}

Coordinator::Coordinator(Clock& clock, Adapter& adapter, Observer observer)
    : clock_(clock), adapter_(adapter), observer_(std::make_shared<Observer>(std::move(observer))), callbackGate_(std::make_shared<CallbackGate>()) {
    callbackGate_->owner = this;
}

Coordinator::~Coordinator() {
    // Detach first. Foreign code during cleanup cannot reenter a dying owner.
    auto gate = callbackGate_; gate->owner = nullptr;
    observer_.reset(); callbackGate_.reset();
    auto* adapter = &adapter_;
    const auto lease = allocationOwner_;
    const auto c = status_.cycle, a = status_.attempt;
    const auto deadline = clock_.now() + 3000;
    const bool active = status_.state != State::Idle && status_.state != State::Failed && status_.state != State::Cancelled;
    const bool stop = backendMayBeRunning_;
    // Everything after the first foreign call uses captured locals only. An
    // already committed stop/release operation retains its own shared lease.
    if (active) adapter->cancelOwned(c, a);
    if (stop && lease) {
        adapter->stopAndConfirm(lease->cycle, lease->attempt, deadline,
            [lease](CycleId x, AttemptId y, StopResult result) {
                if (x == lease->cycle && y == lease->attempt && result.confirmedDisconnected) lease->release();
            });
    } else if (lease && !lease->backendClaimed) lease->release();
}

bool Coordinator::PhaseToken::valid() const {
    return gate->owner && gate->owner->transitionGeneration_ == generation;
}
Coordinator::PhaseToken Coordinator::checkpoint() const { return {callbackGate_, transitionGeneration_}; }
Coordinator::PhaseToken Coordinator::publish(State state, ErrorCategory error) {
    status_.state = state; status_.error = error; ++transitionGeneration_;
    const auto token = checkpoint();
    const auto observer = observer_; const auto snapshot = status_;
    if (observer && *observer) (*observer)(snapshot);
    return token; // do not access this after calling foreign code
}
bool Coordinator::current(CycleId c, AttemptId a) const {
    return c == status_.cycle && a == status_.attempt && c != 0;
}

void Coordinator::begin() {
    if (status_.state == State::Connected) return; // preserve a healthy owned tunnel
    if (status_.state == State::Failed && status_.error == ErrorCategory::StopUnconfirmed) return;
    if (status_.state == State::Stopping) { restartAfterStop_ = true; return; }
    if (status_.state == State::Fetching || status_.state == State::Admitting ||
        status_.state == State::Starting || status_.state == State::Verifying ||
        status_.state == State::Stopping) {
        restartAfterStop_ = true;
        cancelCurrent();
        return; // cancellation owns both immediate and deferred restart
    }
    status_.cycle = ++nextCycle_; status_.attempt = ++nextAttempt_;
    status_.candidateId.clear(); status_.error = ErrorCategory::None;
    candidates_.clear(); nextCandidate_ = 0; allocation_ = {}; allocationOwner_.reset();
    awaitingRelease_ = false;
    backendMayBeRunning_ = false; nonce_.clear(); degradedProbeFailures_ = 0;
    overallDeadline_ = 0;
    phaseDeadline_ = clock_.now() + 10000;
    if (!publish(State::Fetching).valid()) return;
    const auto c = status_.cycle, a = status_.attempt;
    std::weak_ptr<CallbackGate> weak = callbackGate_;
    adapter_.fetchFresh(c, a, phaseDeadline_, [weak, c, a](CycleId x, AttemptId y, FetchStatus result, Snapshot s) {
        if (x != c || y != a) return;
        if (auto gate = weak.lock(); gate && gate->owner) gate->owner->onFetch(x, y, result, std::move(s));
    });
}

void Coordinator::onFetch(CycleId c, AttemptId a, FetchStatus result, Snapshot snapshot) {
    if (!current(c, a) || status_.state != State::Fetching) return;
    if (clock_.now() >= phaseDeadline_) { fail(ErrorCategory::Deadline); return; }
    if (result != FetchStatus::Success) {
        switch (result) {
        case FetchStatus::NetworkError: fail(ErrorCategory::Network); return;
        case FetchStatus::AuthRevoked: fail(ErrorCategory::AuthRevoked); return;
        case FetchStatus::AccountExpired: fail(ErrorCategory::AccountExpired); return;
        case FetchStatus::Unsupported: fail(ErrorCategory::Unsupported); return;
        case FetchStatus::Malformed: fail(ErrorCategory::Malformed); return;
        case FetchStatus::Success: break;
        }
    }
    const Millis now = clock_.now();
    if (snapshot.schemaVersion != 1 || snapshot.revision.empty() || snapshot.expiresAt <= now ||
        snapshot.candidates.empty() || snapshot.candidates.size() > 3) {
        fail(ErrorCategory::Malformed); return;
    }
    // The 30 s selection budget starts once a fresh candidate snapshot exists.
    snapshotExpiresAt_ = snapshot.expiresAt;
    overallDeadline_ = std::min(now + 30000, snapshotExpiresAt_);
    std::unordered_set<std::string> ids, ips;
    for (const auto& candidate : snapshot.candidates) {
        if (candidate.id.empty() || candidate.port == 0 || candidate.expectedEgressIps.empty() ||
            !isValidPublicIpv4(candidate.publicIpv4) || !ids.insert(candidate.id).second ||
            !ips.insert(candidate.publicIpv4).second) continue;
        bool egressValid = true;
        for (const auto& ip : candidate.expectedEgressIps)
            if (!isValidPublicIpv4(ip)) egressValid = false;
        if (!egressValid) continue;
        candidates_.push_back({candidate});
    }
    if (candidates_.empty()) { fail(ErrorCategory::Malformed); return; }
    // Preserve server ordering. Publish only the actual candidate admission.
    tryNext();
}

void Coordinator::tryNext() {
    if (clock_.now() >= snapshotExpiresAt_) { fail(ErrorCategory::Deadline); return; }
    if (clock_.now() >= overallDeadline_) { fail(ErrorCategory::Deadline); return; }
    if (nextCandidate_ >= candidates_.size()) { fail(pendingError_ == ErrorCategory::None ? ErrorCategory::Network : pendingError_); return; }
    currentCandidate_ = candidates_[nextCandidate_++].candidate;
    status_.candidateId = currentCandidate_.id;
    status_.attempt = ++nextAttempt_;
    attemptStarted_ = clock_.now(); phaseDeadline_ = std::min(overallDeadline_, attemptStarted_ + 8000);
    nonce_ = makeNonce();
    if (!publish(State::Admitting).valid()) return;
    const auto candidate = currentCandidate_;
    const auto c = status_.cycle, a = status_.attempt;
    // The per-acquire ledger lives exactly as long as its callback (including
    // copied/late callbacks), rather than accumulating tombstones across cycles.
    auto gate = callbackGate_;
    auto ledger = std::make_shared<AdmissionLedger>(); ledger->adapter = &adapter_;
    adapter_.acquire(c, a, candidate, phaseDeadline_, [gate, ledger, c, a](CycleId x, AttemptId y, AdmissionResult r) {
        auto lease = ledger->accept(c, a, r);
        if (x != c || y != a) { if (lease && !lease->backendClaimed) lease->release(); return; }
        if (gate->owner) gate->owner->onAdmission(x, y, std::move(r), std::move(lease));
        else if (lease && !lease->backendClaimed) lease->release();
    });
}

void Coordinator::onAdmission(CycleId c, AttemptId a, AdmissionResult r, std::shared_ptr<AllocationOwner> lease) {
    // A repeated delivery of an accepted result cannot release the active lease.
    if (lease && lease == allocationOwner_) return;
    if (!current(c, a) || status_.state != State::Admitting) {
        if (lease && !lease->backendClaimed) lease->release();
        return;
    }
    if (clock_.now() >= phaseDeadline_) {
        beginStop(StopPurpose::Retry, ErrorCategory::Deadline, std::move(lease)); return;
    }
    switch (r.status) {
    case AdmissionStatus::Admitted:
        if (!lease || lease->releaseRequested || r.allocation.nativeConfiguration.empty()) {
            fail(ErrorCategory::Malformed);
            if (lease && !lease->backendClaimed) lease->release();
            return;
        }
        allocation_ = std::move(r.allocation); allocationOwner_ = std::move(lease);
        startAttempt(); return;
    case AdmissionStatus::Full: pendingError_ = ErrorCategory::Capacity; tryNext(); return;
    case AdmissionStatus::NotReady: pendingError_ = ErrorCategory::NotReady; tryNext(); return;
    case AdmissionStatus::Disabled: pendingError_ = ErrorCategory::Disabled; tryNext(); return;
    case AdmissionStatus::NetworkError: pendingError_ = ErrorCategory::Network; tryNext(); return;
    case AdmissionStatus::AuthRevoked: fail(ErrorCategory::AuthRevoked); return;
    case AdmissionStatus::AccountExpired: fail(ErrorCategory::AccountExpired); return;
    case AdmissionStatus::Unsupported: fail(ErrorCategory::Unsupported); return;
    case AdmissionStatus::Malformed: fail(ErrorCategory::Malformed); return;
    }
}

void Coordinator::startAttempt() {
    if (!publish(State::Starting).valid()) return;
    // Commit backend ownership immediately before the start effect. A Starting
    // observer may cancel an accepted lease before any backend effect exists.
    backendMayBeRunning_ = true; allocationOwner_->backendClaimed = true;
    const auto allocation = allocation_;
    const auto c = status_.cycle, a = status_.attempt;
    std::weak_ptr<CallbackGate> weak = callbackGate_;
    adapter_.start(c, a, allocation, phaseDeadline_, [weak, c, a](CycleId x, AttemptId y, StartResult r) {
        if (x != c || y != a) return;
        if (auto gate = weak.lock(); gate && gate->owner) gate->owner->onStart(x, y, r);
        // A timeout/cancel/destruction already owns the one stop operation.
        // cancelOwned prevents a pending start from activating after that stop.
    });
}
void Coordinator::onStart(CycleId c, AttemptId a, StartResult r) {
    if (!current(c, a) || status_.state != State::Starting) return;
    if (r.status == StartStatus::Started) {
        backendMayBeRunning_ = true;
        if (clock_.now() >= phaseDeadline_) { beginStop(StopPurpose::Retry, ErrorCategory::Deadline); return; }
        if (!publish(State::Verifying).valid()) return;
        const auto nonce = nonce_; const auto egress = currentCandidate_.expectedEgressIps;
        const auto cycle = status_.cycle, attempt = status_.attempt;
        std::weak_ptr<CallbackGate> weak = callbackGate_;
        adapter_.verifyOwnTunnel(cycle, attempt, nonce, egress, phaseDeadline_,
            [weak, cycle, attempt](CycleId x, AttemptId y, ProofResult p) {
                if (x != cycle || y != attempt) return;
                if (auto gate = weak.lock(); gate && gate->owner) gate->owner->onProof(x, y, std::move(p));
            });
        return;
    }
    pendingError_ = (r.status == StartStatus::CryptoError) ? ErrorCategory::CryptoHealth :
                    (r.status == StartStatus::MalformedConfig) ? ErrorCategory::Malformed :
                    (r.status == StartStatus::Unsupported) ? ErrorCategory::Unsupported : ErrorCategory::Network;
    beginStop((r.status == StartStatus::Unsupported || r.status == StartStatus::MalformedConfig)
                  ? StopPurpose::Finish : StopPurpose::Retry, pendingError_);
}

bool Coordinator::proofMatches(const OwnTunnelProof& p, const std::string& nonce,
                               const Candidate& candidate, Millis started, Millis now) {
    return p.certificateValid && p.nonceMatched && p.nonce == nonce && !nonce.empty() &&
           p.peerHandshakeObserved && !p.ownPeerId.empty() && !p.counterReset &&
           p.rxBytesAfter > p.rxBytesBefore && p.handshakeAt >= started && p.handshakeAt <= now &&
           std::find(candidate.expectedEgressIps.begin(), candidate.expectedEgressIps.end(), p.observedEgressIp) != candidate.expectedEgressIps.end();
}
void Coordinator::onProof(CycleId c, AttemptId a, ProofResult p) {
    if (!current(c, a) || status_.state != State::Verifying) return;
    if (clock_.now() >= phaseDeadline_ || !p.probeSucceeded || !proofMatches(p.evidence, nonce_, currentCandidate_, attemptStarted_, clock_.now())) {
        beginStop(StopPurpose::Retry, clock_.now() >= phaseDeadline_ ? ErrorCategory::Deadline : ErrorCategory::ProofFailed); return;
    }
    if (!publish(State::Connected).valid()) return;
    const auto candidateId = currentCandidate_.id;
    const auto cycle = status_.cycle, attempt = status_.attempt;
    std::weak_ptr<CallbackGate> weak = callbackGate_;
    adapter_.reportProven(cycle, attempt, candidateId, [weak](CycleId x, AttemptId y) {
        if (auto gate = weak.lock(); gate && gate->owner) gate->owner->onReport(x, y);
    });
}
void Coordinator::onReport(CycleId c, AttemptId a) { if (!current(c, a) || status_.state != State::Connected) return; }
void Coordinator::finishReleased() {
    allocation_ = {}; allocationOwner_.reset(); awaitingRelease_ = false;
    const auto purpose = stopPurpose_; const auto error = pendingError_;
    if (restartAfterStop_) {
        restartAfterStop_ = false;
        if (!publish(State::Cancelled, ErrorCategory::Cancelled).valid()) return;
        begin();
    } else if (purpose == StopPurpose::Cancel) publish(State::Cancelled, ErrorCategory::Cancelled);
    else if (purpose == StopPurpose::Retry) tryNext();
    else fail(error);
}

void Coordinator::releaseThen(StopPurpose purpose, ErrorCategory error) {
    stopPurpose_ = purpose; pendingError_ = error;
    if (!allocationOwner_) { finishReleased(); return; }
    const auto lease = allocationOwner_;
    if (lease->releaseRequested) return; // an existing release owns completion
    awaitingRelease_ = true;
    if (status_.state != State::Stopping) phaseDeadline_ = clock_.now() + 3000;
    std::weak_ptr<CallbackGate> weak = callbackGate_;
    // Exact cleanup was committed by a confirmed stop or an unstarted lease.
    // It must execute even if the observer changes phase or destroys the owner.
    publish(State::Stopping);
    lease->release([weak, lease](CycleId x, AttemptId y) {
        auto gate = weak.lock(); if (!gate || !gate->owner) return;
        auto* owner = gate->owner;
        if (x != lease->cycle || y != lease->attempt || !owner->current(x, y) ||
            owner->allocationOwner_ != lease || owner->status_.state != State::Stopping || !owner->awaitingRelease_) return;
        owner->awaitingRelease_ = false;
        if (owner->clock_.now() >= owner->phaseDeadline_) {
            owner->allocation_ = {}; owner->allocationOwner_.reset();
            owner->fail(ErrorCategory::StopUnconfirmed); return;
        }
        owner->finishReleased();
    });
}
void Coordinator::beginStop(StopPurpose purpose, ErrorCategory error, std::shared_ptr<AllocationOwner> unusedAdmission) {
    const auto c = status_.cycle, a = status_.attempt;
    auto* adapter = &adapter_;
    const auto lease = allocationOwner_;
    const bool stop = backendMayBeRunning_;
    const bool connected = status_.state == State::Connected;
    backendMayBeRunning_ = false; // commit one scoped stop before notification
    stopPurpose_ = purpose; pendingError_ = error;
    phaseDeadline_ = (purpose == StopPurpose::Cancel || connected || !overallDeadline_) ? clock_.now() + 3000 :
        std::min(overallDeadline_ ? overallDeadline_ : clock_.now() + 8000, clock_.now() + 3000);
    const auto deadline = phaseDeadline_;
    std::weak_ptr<CallbackGate> weak = callbackGate_;
    const auto token = publish(State::Stopping, error);
    // These scoped cleanup effects remain valid independently of token/owner.
    // The old completion ingress is already closed before either external call.
    if (unusedAdmission && !unusedAdmission->backendClaimed) unusedAdmission->release();
    adapter->cancelOwned(c, a);
    if (stop && lease) {
        adapter->stopAndConfirm(lease->cycle, lease->attempt, deadline, [weak, lease](CycleId x, AttemptId y, StopResult r) {
            if (x != lease->cycle || y != lease->attempt) return;
            if (auto gate = weak.lock(); gate && gate->owner) gate->owner->onStop(x, y, r);
            if (r.confirmedDisconnected) lease->release();
        });
    } else if (token.valid()) {
        auto* owner = token.gate->owner;
        owner->releaseThen(owner->stopPurpose_, owner->pendingError_);
    } else if (lease && !lease->backendClaimed) lease->release();
}
void Coordinator::onStop(CycleId c, AttemptId a, StopResult r) {
    if (!current(c, a) || status_.state != State::Stopping || awaitingRelease_) return;
    if (!r.confirmedDisconnected || clock_.now() >= phaseDeadline_) { fail(ErrorCategory::StopUnconfirmed); return; }
    releaseThen(stopPurpose_, pendingError_);
}
void Coordinator::fail(ErrorCategory e) {
    status_.candidateId.clear(); publish(State::Failed, e);
}

void Coordinator::cancel() {
    restartAfterStop_ = false; // explicit user cancel supersedes a queued restart
    if (status_.state == State::Idle || status_.state == State::Failed || status_.state == State::Cancelled) {
        ++transitionGeneration_; return;
    }
    cancelCurrent();
}
void Coordinator::cancelCurrent() {
    if (status_.state == State::Stopping) {
        stopPurpose_ = StopPurpose::Cancel; pendingError_ = ErrorCategory::Cancelled;
        return; // the committed stop/release remains mandatory
    }
    beginStop(StopPurpose::Cancel, ErrorCategory::Cancelled);
}

void Coordinator::tick() {
    if (status_.state == State::Fetching && clock_.now() >= phaseDeadline_) {
        const auto c = status_.cycle, a = status_.attempt; auto* adapter = &adapter_;
        fail(ErrorCategory::Deadline); // close ingress before inline cancellation result
        adapter->cancelOwned(c, a); // scoped cleanup; no continuation
        return;
    }
    if ((status_.state == State::Admitting || status_.state == State::Starting || status_.state == State::Verifying) && clock_.now() >= phaseDeadline_) {
        beginStop(StopPurpose::Retry, ErrorCategory::Deadline);
    } else if (status_.state == State::Stopping && clock_.now() >= phaseDeadline_) fail(ErrorCategory::StopUnconfirmed);
}

void Coordinator::onConnectedProbe(CycleId c, bool success, bool ownTelemetryDegraded) {
    if (c != status_.cycle || status_.state != State::Connected) return;
    if (success) { degradedProbeFailures_ = 0; return; }
    if (ownTelemetryDegraded) ++degradedProbeFailures_;
    else degradedProbeFailures_ = 0;
    if (degradedProbeFailures_ >= 2) {
        backendMayBeRunning_ = true;
        beginStop(StopPurpose::Finish, ErrorCategory::ProofFailed);
    }
}

std::string Coordinator::makeNonce() {
    std::random_device rd;
    std::ostringstream out;
    out << std::hex;
    for (int i = 0; i < 8; ++i) out.width(8), out.fill('0'), out << static_cast<std::uint32_t>(rd());
    return out.str();
}

bool Coordinator::isValidPublicIpv4(const std::string& text) {
    std::array<unsigned, 4> a{};
    if (!parseIpv4(text, a)) return false;
    if (a[0] == 0 || a[0] == 10 || a[0] == 127 || a[0] >= 224) return false;
    if ((a[0] == 100 && a[1] >= 64 && a[1] <= 127) || in(a, 169, 254) || (in(a, 172) && a[1] >= 16 && a[1] <= 31) || in(a, 192, 168)) return false;
    if (in(a, 192, 0) || in(a, 192, 2) || in(a, 198, 18) || in(a, 198, 19) || in(a, 198, 51) || in(a, 203, 0)) return false;
    return true;
}

} // namespace mayak::autoconnect
