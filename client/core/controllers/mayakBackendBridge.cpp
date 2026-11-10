#include "mayakBackendBridge.h"
#include <QTimer>
#include <QRandomGenerator>
#include <QThread>
#include <QHash>
#include <chrono>

namespace {
using B = MayakBackendBridge;
// Shared state has no application dependencies. All reads/writes except gate
// atomics occur on the facade thread. Worker callbacks only enqueue values.
struct Call { bool finished = false; bool ownsGate = false; };
int delayTo(B::Millis deadline) {
    return int(qBound<qint64>(qint64(0), deadline - B::monotonicMillis(), qint64(0x7fffffff)));
}
}
struct MayakBackendBridge::State {
    Port port;
    QHash<QString, Ticket> tickets;
    QHash<QString, AwgHealthContext> contexts;
    QHash<QString, PermissionDone> permissionPreparations;
    explicit State(Port p) : port(std::move(p)) {}
};
MayakBackendBridge::Millis MayakBackendBridge::monotonicMillis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
QString MayakBackendBridge::randomRequestId() {
    QByteArray bytes(32, Qt::Uninitialized);
    for (int i = 0; i < 32; i += 4) {
        const quint32 value = QRandomGenerator::system()->generate();
        memcpy(bytes.data() + i, &value, sizeof(value));
    }
    return QString::fromLatin1(bytes.toHex());
}
MayakBackendBridge::MayakBackendBridge(Port port, QObject* parent)
    : QObject(parent), m_state(std::make_shared<State>(std::move(port))) {
    const QPointer<MayakBackendBridge> self(this);
    const auto s = m_state;
    if (!s->port.owner || !s->port.observe) return;
    QMetaObject::invokeMethod(s->port.owner, [s, self] {
        if (!self || !s->port.owner) return;
        s->port.observe(self, [self](Ticket t, AwgTunnelHealth h) {
            if (!self) return;
            QMetaObject::invokeMethod(self, [self, t, h] {
                if (!self) return;
                const auto s = self->m_state;
                if (!s->tickets.contains(t.opaqueAttempt) || !s->tickets.value(t.opaqueAttempt).same(t) ||
                    t.gate->cancellationRequested.load() || !s->contexts.value(t.opaqueAttempt).matches(h)) return;
                emit self->health(t, h);
            }, Qt::QueuedConnection);
        }, [self](Result r) {
            if (!self) return;
            QMetaObject::invokeMethod(self, [self, r] {
                if (!self) return;
                const auto s = self->m_state;
                if (!s->tickets.contains(r.ticket.opaqueAttempt) || !s->tickets.value(r.ticket.opaqueAttempt).same(r.ticket)) return;
                if (r.outcome == Outcome::ConfirmedDown) {
                    s->contexts.remove(r.ticket.opaqueAttempt);
                    s->tickets.remove(r.ticket.opaqueAttempt);
                    emit self->backendDown(r);
                } else emit self->error(r);
            }, Qt::QueuedConnection);
        });
        if (s->port.observeNetwork) s->port.observeNetwork(self, [self](Ticket t, bool available) {
            if (!self) return;
            QMetaObject::invokeMethod(self, [self, t, available] {
                if (!self) return;
                const auto s = self->m_state;
                if (!s->tickets.contains(t.opaqueAttempt) || !s->tickets.value(t.opaqueAttempt).same(t) ||
                    t.gate->cancellationRequested.load()) return;
                emit self->networkChanged(t, available);
            }, Qt::QueuedConnection);
        });
        if (s->port.observeResume) s->port.observeResume(self, [self](Ticket t, bool replaced, bool available) {
            if (!self) return;
            QMetaObject::invokeMethod(self, [self, t, replaced, available] {
                if (!self) return;
                const auto s = self->m_state;
                if (!s->tickets.contains(t.opaqueAttempt) || !s->tickets.value(t.opaqueAttempt).same(t) ||
                    t.gate->cancellationRequested.load()) return;
                emit self->resumed(t, replaced, available);
            }, Qt::QueuedConnection);
        });
        if (s->port.observeUserStop) s->port.observeUserStop(self, [self](Ticket t) {
            if (!self) return;
            QMetaObject::invokeMethod(self, [self, t] {
                if (!self) return;
                const auto s = self->m_state;
                if (!s->tickets.contains(t.opaqueAttempt) || !s->tickets.value(t.opaqueAttempt).same(t)) return;
                emit self->userStopped(t);
            }, Qt::QueuedConnection);
        });
        if (s->port.observeVisibility) s->port.observeVisibility(self, [self](bool visible) {
            if (!self) return;
            QMetaObject::invokeMethod(self, [self, visible] { if (self) emit self->visibilityChanged(visible); },
                                      Qt::QueuedConnection);
        });
        if (s->port.observeFailover) s->port.observeFailover(self, [self](Ticket t) {
            if (!self) return;
            QMetaObject::invokeMethod(self, [self, t] {
                if (!self) return;
                const auto s = self->m_state;
                if (!s->tickets.contains(t.opaqueAttempt) || !s->tickets.value(t.opaqueAttempt).same(t) ||
                    t.gate->cancellationRequested.load()) return;
                emit self->failoverRequested(t);
            }, Qt::QueuedConnection);
        });
    }, Qt::QueuedConnection);
}
MayakBackendBridge::~MayakBackendBridge() {
    const auto s = m_state;
    const auto permissionIds = s->permissionPreparations.keys();
    s->permissionPreparations.clear();
    if (s->port.owner && s->port.cancelPermissionPreparation) {
        for (const QString &requestId : permissionIds) QMetaObject::invokeMethod(s->port.owner,
            [s, requestId] { if (s->port.cancelPermissionPreparation) s->port.cancelPermissionPreparation(requestId); },
            Qt::QueuedConnection);
    }
    for (const Ticket& t : s->tickets) {
        t.gate->cancel();
        if (s->port.owner) QMetaObject::invokeMethod(s->port.owner, [s, t] {
            if (s->port.cancel) s->port.cancel(t);
            if (t.gate->state.load() == StartGate::ActivationCommitted && s->port.stop)
                s->port.stop(t, randomRequestId(), monotonicMillis() + 3000, [](Result) {});
        }, Qt::QueuedConnection);
    }
}
void MayakBackendBridge::startPrepared(Ticket t, QString id, QJsonObject config, Millis deadline, Done done) {
    Q_ASSERT(QThread::currentThread() == thread());
    const auto s = m_state;
    const QPointer<MayakBackendBridge> self(this);
    auto call = std::make_shared<Call>();
    auto finish = [self, call, done, t, deadline](Result r) {
        if (!self || call->finished) return;
        call->finished = true;
        r.ticket = t;
        if (monotonicMillis() >= deadline) r.outcome = Outcome::Deadline;
        if (r.outcome == Outcome::Started && t.gate->cancellationRequested.load()) r.outcome = Outcome::Cancelled;
        if (r.outcome == Outcome::Started) {
            self->m_state->contexts.insert(t.opaqueAttempt, r.expected);
            emit self->activated(r);
            if (!self) return;
            if (t.gate->cancellationRequested.load()) r.outcome = Outcome::Cancelled;
        }
        if (r.outcome != Outcome::Started && call->ownsGate) t.gate->cancel();
        if (done) done(r);
    };
    if (!t.valid() || s->tickets.contains(t.opaqueAttempt) || !s->tickets.isEmpty()) {
        finish({t, Outcome::Busy}); return;
    }
    call->ownsGate = true;
    s->tickets.insert(t.opaqueAttempt, t);
    QTimer::singleShot(delayTo(deadline), this, [finish, call, t] {
        if (call->finished) return;
        t.gate->cancel();
        finish({t, Outcome::Deadline});
    });
    if (!s->port.owner || !s->port.start) { finish({t, Outcome::Unknown}); return; }
    QMetaObject::invokeMethod(s->port.owner, [s, self, t, id, config, deadline, finish] {
        if (!self) { t.gate->cancel(); return; }
        if (monotonicMillis() >= deadline) t.gate->cancel();
        if (t.gate->state.load() == StartGate::Cancelled) {
            QMetaObject::invokeMethod(self, [finish, t] { finish({t, Outcome::Cancelled}); }, Qt::QueuedConnection); return;
        }
        s->port.start(t, id, config, deadline, [self, finish](Result r) {
            if (self) QMetaObject::invokeMethod(self, [finish, r] { finish(r); }, Qt::QueuedConnection);
        });
    }, Qt::QueuedConnection);
}
void MayakBackendBridge::cancel(Ticket t) {
    if (!t.valid()) return;
    t.gate->cancel(); // Linearizes before queued dispatch, including destruction.
    const auto s = m_state;
    if (s->port.owner && s->port.cancel) QMetaObject::invokeMethod(s->port.owner,
        [s, t] { s->port.cancel(t); }, Qt::QueuedConnection);
}
void MayakBackendBridge::stopAndConfirm(Ticket t, Millis deadline, Done done) {
    Q_ASSERT(QThread::currentThread() == thread());
    cancel(t);
    deadline = qMin(deadline, monotonicMillis() + 3000);
    const auto s = m_state;
    const QPointer<MayakBackendBridge> self(this);
    const QString nonce = randomRequestId();
    auto call = std::make_shared<Call>();
    auto finish = [self, call, done, t, nonce, deadline](Result r) {
        if (!self || call->finished || r.requestId != nonce || !r.ticket.same(t)) return;
        call->finished = true;
        if (monotonicMillis() >= deadline) r.outcome = Outcome::Deadline;
        if (r.outcome == Outcome::ConfirmedDown) {
            self->m_state->contexts.remove(t.opaqueAttempt);
            self->m_state->tickets.remove(t.opaqueAttempt);
        }
        if (done) done(r);
    };
    QTimer::singleShot(delayTo(deadline), this, [finish, t, nonce] { Result r{t, Outcome::Deadline}; r.requestId = nonce; finish(r); });
    if (!s->port.owner || !s->port.stop) { Result r{t, Outcome::Unknown}; r.requestId = nonce; finish(r); return; }
    QMetaObject::invokeMethod(s->port.owner, [s, self, t, nonce, deadline, finish] {
        s->port.stop(t, nonce, deadline, [self, finish](Result r) {
            if (self) QMetaObject::invokeMethod(self, [finish, r] { finish(r); }, Qt::QueuedConnection);
        });
    }, Qt::QueuedConnection);
}
void MayakBackendBridge::inspectOwnBackend(Millis deadline, Inspected done) {
    Q_ASSERT(QThread::currentThread() == thread());
    const auto s = m_state;
    for (const auto& t : s->tickets) cancel(t); // Off barrier invalidates pending first.
    const QPointer<MayakBackendBridge> self(this);
    const QString nonce = randomRequestId();
    auto call = std::make_shared<Call>();
    auto finish = [self, call, done, nonce, deadline](Inspection r) {
        if (!self || call->finished || r.requestId != nonce) return;
        call->finished = true;
        if (monotonicMillis() >= deadline) r.state = OwnState::Unknown;
        if (r.state == OwnState::Off) {
            for (auto it = self->m_state->tickets.begin(); it != self->m_state->tickets.end();) {
                if (it->gate->state.load() == StartGate::Cancelled) it = self->m_state->tickets.erase(it); else ++it;
            }
        }
        if (r.state == OwnState::Active && r.recoveryTicket.valid()) self->m_state->tickets.insert(r.recoveryTicket.opaqueAttempt, r.recoveryTicket);
        if (done) done(r);
    };
    QTimer::singleShot(delayTo(deadline), this, [finish, nonce] { finish({OwnState::Unknown, nonce, {}}); });
    if (!s->port.owner || !s->port.inspect) { finish({OwnState::Unknown, nonce, {}}); return; }
    QMetaObject::invokeMethod(s->port.owner, [s, self, nonce, deadline, finish] {
        s->port.inspect(nonce, deadline, [self, finish](Inspection r) {
            if (self) QMetaObject::invokeMethod(self, [finish, r] { finish(r); }, Qt::QueuedConnection);
        });
    }, Qt::QueuedConnection);
}
void MayakBackendBridge::probe(Ticket t, MayakTunnelProbeRequest request, Millis deadline, Probed done) {
    Q_ASSERT(QThread::currentThread() == thread());
    const auto s = m_state;
    const QPointer<MayakBackendBridge> self(this);
    auto call = std::make_shared<Call>();
    auto finish = [self, call, done, t, deadline](Ticket actual, bool ok, MayakTunnelProbeProof proof, QString error) {
        if (!self || call->finished || !actual.same(t)) return;
        call->finished = true;
        if (monotonicMillis() >= deadline || !self->m_state->tickets.value(t.opaqueAttempt).same(t) ||
            t.gate->cancellationRequested.load() || t.gate->state.load() != StartGate::ActivationCommitted) { ok = false; error = QStringLiteral("cancelled-or-expired"); }
        if (done) done(t, ok, proof, error);
    };
    QTimer::singleShot(delayTo(deadline), this, [finish, t] { finish(t, false, {}, QStringLiteral("deadline")); });
    if (!s->port.owner || !s->port.probe) { finish(t, false, {}, QStringLiteral("unavailable")); return; }
    QMetaObject::invokeMethod(s->port.owner, [s, self, t, request, deadline, finish] {
        s->port.probe(t, request, deadline, [self, finish](Ticket t, bool ok, MayakTunnelProbeProof p, QString e) {
            if (self) QMetaObject::invokeMethod(self, [finish, t, ok, p, e] { finish(t, ok, p, e); }, Qt::QueuedConnection);
        });
    }, Qt::QueuedConnection);
}

bool MayakBackendBridge::canRecover() const { return bool(m_state->port.recover); }
void MayakBackendBridge::recover(Ticket t, Millis deadline, Done done) {
    Q_ASSERT(QThread::currentThread() == thread());
    const auto s = m_state;
    const QPointer<MayakBackendBridge> self(this);
    const QString nonce = randomRequestId();
    auto call = std::make_shared<Call>();
    auto finish = [self, call, done, t, nonce, deadline](Result r) {
        if (!self || call->finished || r.requestId != nonce || !r.ticket.same(t)) return;
        call->finished = true;
        if (monotonicMillis() >= deadline && r.outcome == Outcome::Started) r.outcome = Outcome::Deadline;
        if (r.outcome == Outcome::Started && (!self->m_state->tickets.value(t.opaqueAttempt).same(t) ||
            t.gate->cancellationRequested.load())) r.outcome = Outcome::Cancelled;
        if (done) done(r);
    };
    const auto fail = [t, nonce](Outcome outcome) { Result r{t, outcome}; r.requestId = nonce; return r; };
    // Only the committed, uncancelled current ticket may be recovered; never a recovery ticket.
    if (!t.valid() || !s->tickets.value(t.opaqueAttempt).same(t) || t.gate->cancellationRequested.load() ||
        t.gate->state.load() != StartGate::ActivationCommitted || t.opaqueAttempt.startsWith(QStringLiteral("recovery:"))) {
        finish(fail(Outcome::Failed)); return;
    }
    QTimer::singleShot(delayTo(deadline), this, [finish, fail] { finish(fail(Outcome::Deadline)); });
    if (!s->port.owner || !s->port.recover) { finish(fail(Outcome::Unknown)); return; }
    QMetaObject::invokeMethod(s->port.owner, [s, self, t, nonce, deadline, finish] {
        s->port.recover(t, nonce, deadline, [self, finish](Result r) {
            if (self) QMetaObject::invokeMethod(self, [finish, r] { finish(r); }, Qt::QueuedConnection);
        });
    }, Qt::QueuedConnection);
}

bool MayakBackendBridge::canRace() const { return bool(m_state->port.raceStart) && bool(m_state->port.raceStop); }
void MayakBackendBridge::raceStart(QString requestId, QJsonObject xrayConfig, Millis deadline, std::function<void(bool)> done) {
    Q_ASSERT(QThread::currentThread() == thread());
    const auto s = m_state;
    const QPointer<MayakBackendBridge> self(this);
    auto call = std::make_shared<Call>();
    auto finish = [self, call, done](bool ok) {
        if (!self || call->finished) return;
        call->finished = true;
        if (done) done(ok);
    };
    if (!s->port.owner || !s->port.raceStart) { finish(false); return; }
    QTimer::singleShot(delayTo(deadline), this, [finish] { finish(false); });
    QMetaObject::invokeMethod(s->port.owner, [s, self, requestId, xrayConfig, deadline, finish] {
        s->port.raceStart(requestId, xrayConfig, deadline, [self, finish](bool ok) {
            if (self) QMetaObject::invokeMethod(self, [finish, ok] { finish(ok); }, Qt::QueuedConnection);
        });
    }, Qt::QueuedConnection);
}
void MayakBackendBridge::raceStop(QString requestId, Millis deadline, std::function<void(bool)> done) {
    Q_ASSERT(QThread::currentThread() == thread());
    const auto s = m_state;
    const QPointer<MayakBackendBridge> self(this);
    auto call = std::make_shared<Call>();
    auto finish = [self, call, done](bool ok) {
        if (!self || call->finished) return;
        call->finished = true;
        if (done) done(ok);
    };
    if (!s->port.owner || !s->port.raceStop) { finish(false); return; }
    QTimer::singleShot(delayTo(deadline), this, [finish] { finish(false); });
    QMetaObject::invokeMethod(s->port.owner, [s, self, requestId, deadline, finish] {
        s->port.raceStop(requestId, deadline, [self, finish](bool ok) {
            if (self) QMetaObject::invokeMethod(self, [finish, ok] { finish(ok); }, Qt::QueuedConnection);
        });
    }, Qt::QueuedConnection);
}

bool MayakBackendBridge::canAdopt() const { return bool(m_state->port.adopt); }
void MayakBackendBridge::adopt(Ticket recovery, Ticket fresh, QString identity, QJsonObject config, Millis deadline, Done done) {
    Q_ASSERT(QThread::currentThread() == thread());
    const auto s = m_state;
    const QPointer<MayakBackendBridge> self(this);
    const QString nonce = randomRequestId();
    auto call = std::make_shared<Call>();
    auto finish = [self, call, done, recovery, fresh, nonce, deadline](Result r) {
        if (!self || call->finished || r.requestId != nonce || !r.ticket.same(fresh)) return;
        call->finished = true;
        if (monotonicMillis() >= deadline && r.outcome == Outcome::Started) r.outcome = Outcome::Deadline;
        if (r.outcome == Outcome::Started && fresh.gate->cancellationRequested.load()) r.outcome = Outcome::Cancelled;
        if (r.outcome == Outcome::Started) {
            // The single owned ticket becomes the attempt's full ticket.
            self->m_state->tickets.remove(recovery.opaqueAttempt);
            self->m_state->tickets.insert(fresh.opaqueAttempt, fresh);
            self->m_state->contexts.insert(fresh.opaqueAttempt, r.expected);
            emit self->activated(r);
            if (!self) return;
        } else fresh.gate->cancel();
        if (done) done(r);
    };
    const auto fail = [fresh, nonce](Outcome outcome) { Result r{fresh, outcome}; r.requestId = nonce; return r; };
    // Only the inspected recovery authority may be exchanged, once, for a never-used attempt ticket.
    if (!recovery.valid() || !s->tickets.value(recovery.opaqueAttempt).same(recovery) ||
        !recovery.opaqueAttempt.startsWith(QStringLiteral("recovery:")) || identity.isEmpty() ||
        !fresh.valid() || fresh.opaqueAttempt.startsWith(QStringLiteral("recovery:")) ||
        s->tickets.contains(fresh.opaqueAttempt) || !fresh.gate->commit()) {
        finish(fail(Outcome::Failed)); return;
    }
    QTimer::singleShot(delayTo(deadline), this, [finish, fail] { finish(fail(Outcome::Deadline)); });
    if (!s->port.owner || !s->port.adopt) { finish(fail(Outcome::Unknown)); return; }
    QMetaObject::invokeMethod(s->port.owner, [s, self, recovery, fresh, identity, config, nonce, deadline, finish] {
        s->port.adopt(recovery, fresh, identity, config, nonce, deadline, [self, finish](Result r) {
            if (self) QMetaObject::invokeMethod(self, [finish, r] { finish(r); }, Qt::QueuedConnection);
        });
    }, Qt::QueuedConnection);
}

void MayakBackendBridge::preparePermissions(QString requestId, PermissionDone done) {
    Q_ASSERT(QThread::currentThread() == thread());
    const auto s = m_state;
    if (requestId.isEmpty() || !done || s->permissionPreparations.contains(requestId)) {
        if (done) done(requestId, PermissionResult::Unavailable);
        return;
    }
    s->permissionPreparations.insert(requestId, done);
#ifndef Q_OS_ANDROID
    if (!s->port.preparePermissions) {
        QMetaObject::invokeMethod(this, [self = QPointer<MayakBackendBridge>(this), requestId] {
            if (!self) return;
            const auto callback = self->m_state->permissionPreparations.take(requestId);
            if (callback) callback(requestId, PermissionResult::Ready);
        }, Qt::QueuedConnection);
        return;
    }
#endif
    if (!s->port.owner || !s->port.preparePermissions) {
        s->permissionPreparations.remove(requestId);
#ifdef Q_OS_ANDROID
        done(requestId, PermissionResult::Unavailable);
#else
        done(requestId, PermissionResult::Ready);
#endif
        return;
    }
    const QPointer<MayakBackendBridge> self(this);
    QMetaObject::invokeMethod(s->port.owner, [s, self, requestId] {
        if (!self || !s->port.owner || !s->port.preparePermissions) return;
        s->port.preparePermissions(requestId, [self, requestId](QString actualId, PermissionResult result) {
            if (!self || actualId != requestId) return;
            QMetaObject::invokeMethod(self, [self, requestId, result] {
                if (!self) return;
                const auto callback = self->m_state->permissionPreparations.take(requestId);
                if (callback) callback(requestId, result);
            }, Qt::QueuedConnection);
        });
    }, Qt::QueuedConnection);
}

void MayakBackendBridge::cancelPermissionPreparation(const QString &requestId) {
    Q_ASSERT(QThread::currentThread() == thread());
    if (requestId.isEmpty()) return;
    const auto s = m_state;
    s->permissionPreparations.remove(requestId);
    if (s->port.owner && s->port.cancelPermissionPreparation)
        QMetaObject::invokeMethod(s->port.owner, [s, requestId] {
            if (s->port.cancelPermissionPreparation) s->port.cancelPermissionPreparation(requestId);
        }, Qt::QueuedConnection);
}
