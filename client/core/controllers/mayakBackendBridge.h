#pragma once
#include <QObject>
#include <QPointer>
#include <QJsonObject>
#include <atomic>
#include <functional>
#include <memory>
#include "core/utils/awgTunnelHealth.h"
#include "core/utils/mayakTunnelProbe.h"

// Deadlines use monotonicMillis(). Methods belong to the facade QObject thread;
// the shared gate may be invalidated synchronously from any thread.
class MayakBackendBridge final : public QObject {
    Q_OBJECT
public:
    using Millis = qint64;
    struct StartGate {
        enum State { Pending, Cancelled, ActivationCommitted };
        std::atomic<State> state { Pending };
        std::atomic<bool> cancellationRequested { false };
        bool commit() { State s = Pending; return !cancellationRequested.load() && state.compare_exchange_strong(s, ActivationCommitted); }
        void cancel() { cancellationRequested.store(true); State s = Pending; state.compare_exchange_strong(s, Cancelled); }
    };
    struct Ticket {
        QString opaqueAttempt;
        std::shared_ptr<StartGate> gate;
        bool valid() const { return !opaqueAttempt.isEmpty() && bool(gate); }
        bool same(const Ticket& t) const { return opaqueAttempt == t.opaqueAttempt && gate == t.gate; }
    };
    enum class Outcome { Started, Cancelled, ConfirmedDown, Failed, Unknown, Deadline, Busy };
    enum class OwnState { Active, Off, Unknown };
    enum class PermissionResult { Ready, Denied, Unavailable };
    struct Result {
        Ticket ticket;
        Outcome outcome = Outcome::Unknown;
        AwgHealthContext expected;
        QString requestId;
        QString detail;
    };
    struct Inspection {
        OwnState state = OwnState::Unknown;
        QString requestId;
        QString ownControlIdentity; // Recovery identity only, never trusted proof.
        Ticket recoveryTicket; // Only usable for stopAndConfirm, never start/proof.
    };
    using Done = std::function<void(Result)>;
    using Inspected = std::function<void(Inspection)>;
    using Probed = std::function<void(Ticket, bool, MayakTunnelProbeProof, QString)>;
    using PermissionDone = std::function<void(QString, PermissionResult)>;
    // Functions run ONLY on owner. Production owner retains committed activation
    // and transport after facade timeout/destruction until genuine Down, or keeps
    // unresolved authority until process exit. Native start must commit the gate
    // immediately before activation. Cancellation never claims backend Off.
    struct Port {
        QPointer<QObject> owner;
        std::function<void(Ticket, QString, QJsonObject, Millis, Done)> start;
        std::function<void(Ticket)> cancel;
        std::function<void(Ticket, QString, Millis, Done)> stop;
        std::function<void(QString, Millis, Inspected)> inspect;
        std::function<void(Ticket, MayakTunnelProbeRequest, Millis, Probed)> probe;
        std::function<void(QObject*, std::function<void(Ticket, AwgTunnelHealth)>, Done)> observe;
        std::function<void(QString, PermissionDone)> preparePermissions;
        std::function<void(QString)> cancelPermissionPreparation;
    };
    explicit MayakBackendBridge(Port port, QObject* parent = nullptr);
    ~MayakBackendBridge() override;
    static Millis monotonicMillis();
    static QString randomRequestId(); // 32 system-random bytes encoded as hex.
    void startPrepared(Ticket ticket, QString serverId, QJsonObject awgConfig, Millis deadline, Done done);
    void cancel(Ticket ticket);
    void stopAndConfirm(Ticket ticket, Millis deadline, Done done);
    void inspectOwnBackend(Millis deadline, Inspected done);
    void probe(Ticket ticket, MayakTunnelProbeRequest request, Millis deadline, Probed done);
    void preparePermissions(QString requestId, PermissionDone done);
    void cancelPermissionPreparation(const QString &requestId);
signals:
    void activated(const MayakBackendBridge::Result& activation);
    void health(const MayakBackendBridge::Ticket& ticket, const AwgTunnelHealth& health);
    void error(const MayakBackendBridge::Result& error);
    // Separate cleanup event may be late; operation callback never revives.
    void backendDown(const MayakBackendBridge::Result& result);
private:
    struct State;
    std::shared_ptr<State> m_state;
};
