#ifndef IPCCLIENT_H
#define IPCCLIENT_H

#include <QLocalSocket>
#include <QObject>
#include <QDeadlineTimer>
#include <limits>
#include <type_traits>
#include <utility>

#include "rep_ipc_interface_replica.h"
#include "rep_ipc_process_interface_replica.h"

class IpcClient : public QObject
{
    Q_OBJECT
public:
    explicit IpcClient(QObject *parent = nullptr);

    static IpcClient& Instance();

    static QSharedPointer<IpcInterfaceReplica> Interface();
    static QSharedPointer<IpcProcessInterfaceReplica> CreatePrivilegedProcess();

    template <typename Func>
    static auto withInterface(Func func)
    {
        QSharedPointer<IpcInterfaceReplica> iface = Instance().m_interface;
        using ReturnType = decltype(func(std::declval<QSharedPointer<IpcInterfaceReplica>>()));

        if (iface.isNull() || !iface->waitForSource(1000) || !iface->isReplicaValid()) {
            qWarning() << "IpcClient::withInterface(): Service is not running";

            if constexpr (std::is_void_v<ReturnType>)
                return;
            else
                return ReturnType{};
        }

        return func(iface);
    }

    template <typename OnSuccess, typename OnFailure>
    static auto withInterface(OnSuccess onSuccess, OnFailure onFailure)
    {
        QSharedPointer<IpcInterfaceReplica> iface = Instance().m_interface;
        if (iface.isNull() || !iface->waitForSource(1000) || !iface->isReplicaValid()) {
            return onFailure();
        }

        return onSuccess(iface);
    }
    // New bounded callers share their existing monotonic total deadline. Legacy
    // withInterface overloads retain their original source-wait behavior above.
    template <typename Func>
    static auto withInterfaceUntil(const QDeadlineTimer &deadline, Func func)
    {
        using ReturnType = decltype(func(std::declval<QSharedPointer<IpcInterfaceReplica>>()));
        const auto unavailable = []() -> ReturnType {
            if constexpr (!std::is_void_v<ReturnType>) return ReturnType{};
        };
        if (deadline.hasExpired()) return unavailable();
        // Replica creation and use remain on this worker's thread-local client.
        QSharedPointer<IpcInterfaceReplica> iface = Instance().m_interface;
        const qint64 remaining = deadline.remainingTime();
        if (iface.isNull() || remaining <= 0 ||
            !iface->waitForSource(static_cast<int>(qMin<qint64>(remaining, std::numeric_limits<int>::max()))) ||
            !iface->isReplicaValid() || deadline.hasExpired()) return unavailable();
        return func(iface);
    }

signals:

private:
    QRemoteObjectNode m_node;
    QSharedPointer<IpcInterfaceReplica> m_interface;
};

#endif // IPCCLIENT_H
