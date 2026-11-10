#include "mayakForeignVpn.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalSocket>
#include <QRandomGenerator>
#include <QTimer>
#include <QElapsedTimer>
#include <memory>

#ifdef Q_OS_WINDOWS
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <tlhelp32.h>
#endif

namespace mayak::foreignvpn {
namespace {

constexpr auto kOwner = "MayakVpnAwgLifecycleV1";
constexpr auto kDaemonPipe = "\\\\.\\pipe\\MayakVpnAwgLifecycleV1";

bool isBrowsec(const QString& text) {
    return text.contains(QLatin1String("browbox")) || text.contains(QLatin1String("browsec"));
}

// Windows' own IPv6 transition tunnels are not a third-party VPN (review 5120 note).
bool isSystemIpv6Tunnel(const QString& text) {
    for (const char* mark : {"teredo", "ip-https", "iphttps", "6to4", "isatap"})
        if (text.contains(QLatin1String(mark))) return true;
    return false;
}

bool isVirtual(const Adapter& a, const QString& text) {
    if (isSystemIpv6Tunnel(text)) return false;
    if (a.ifType == 53 || a.ifType == 131) return true;
    for (const char* mark : {"wintun", "wireguard", "tap-windows", "tunnel"})
        if (text.contains(QLatin1String(mark))) return true;
    return false;
}

// A default route or the 0/1 + 128/1 pair that VPNs use to win over the real default.
bool capturesAll(const Route& r) {
    if (r.v6) return r.prefixLength <= 1;
    if (r.prefixLength == 0) return true;
    return r.prefixLength == 1 && (r.v4Destination == 0 || r.v4Destination == 0x80000000u);
}

}  // namespace

Finding classify(const QList<Adapter>& adapters, const QList<Route>& routes,
                 const QStringList& processNames) {
    const bool browboxRunning = processNames.contains(QStringLiteral("browbox.exe"));
    auto own = [](const Adapter& a) {
        return a.alias.contains(QLatin1String("MayakVPN"), Qt::CaseInsensitive);
    };
    // Browsec's tunnel counts as soon as it is up, whatever routes it uses.
    for (const auto& a : adapters) {
        if (!a.up || own(a)) continue;
        if (isBrowsec((a.alias + u' ' + a.description).toLower()))
            return {QStringLiteral("Browsec"), a.alias, browboxRunning};
    }
    for (const auto& a : adapters) {
        if (!a.up || own(a)) continue;
        if (!isVirtual(a, (a.alias + u' ' + a.description).toLower())) continue;
        for (const auto& r : routes)
            if (r.index == a.index && capturesAll(r)) return {a.alias, a.alias, false};
    }
    return {};
}

#ifdef Q_OS_WINDOWS
namespace {

QList<Adapter> readAdapters() {
    QList<Adapter> out;
    ULONG size = 32 * 1024;
    QByteArray buffer;
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int i = 0; i < 4 && rc == ERROR_BUFFER_OVERFLOW; ++i) {
        buffer.resize(int(size));
        rc = GetAdaptersAddresses(AF_UNSPEC,
                                  GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                      GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_UNICAST,
                                  nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),
                                  &size);
    }
    if (rc != NO_ERROR) return out;
    for (auto* p = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()); p; p = p->Next) {
        Adapter a;
        a.index = p->IfIndex ? p->IfIndex : p->Ipv6IfIndex;
        a.alias = QString::fromWCharArray(p->FriendlyName ? p->FriendlyName : L"");
        a.description = QString::fromWCharArray(p->Description ? p->Description : L"");
        a.ifType = p->IfType;
        a.up = p->OperStatus == IfOperStatusUp;
        out.append(a);
    }
    return out;
}

QList<Route> readRoutes() {
    QList<Route> out;
    PMIB_IPFORWARD_TABLE2 table = nullptr;
    if (GetIpForwardTable2(AF_UNSPEC, &table) != NO_ERROR || !table) return out;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto& row = table->Table[i];
        Route r;
        r.index = row.InterfaceIndex;
        r.prefixLength = row.DestinationPrefix.PrefixLength;
        const auto& addr = row.DestinationPrefix.Prefix;
        if (addr.si_family == AF_INET6) {
            r.v6 = true;
        } else if (addr.si_family == AF_INET) {
            const auto& b = addr.Ipv4.sin_addr.S_un.S_un_b;
            r.v4Destination = (quint32(b.s_b1) << 24) | (quint32(b.s_b2) << 16) |
                              (quint32(b.s_b3) << 8) | quint32(b.s_b4);
        } else {
            continue;
        }
        out.append(r);
    }
    FreeMibTable(table);
    return out;
}

QStringList readProcessNames() {
    QStringList out;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    for (BOOL ok = Process32FirstW(snapshot, &entry); ok; ok = Process32NextW(snapshot, &entry))
        out.append(QString::fromWCharArray(entry.szExeFile).toLower());
    CloseHandle(snapshot);
    return out;
}

}  // namespace

Finding detect() { return classify(readAdapters(), readRoutes(), readProcessNames()); }
#else
Finding detect() { return {}; }
#endif

QByteArray stopRequestLine(const QString& requestId) {
    QJsonObject obj{{QStringLiteral("type"), QLatin1String(kStopCommand)},
                    {QStringLiteral("requestId"), requestId}};
    return QJsonDocument(obj).toJson(QJsonDocument::Compact) + '\n';
}

bool parseStopReply(const QByteArray& line, const QString& requestId, int* stopped) {
    const auto doc = QJsonDocument::fromJson(line.trimmed());
    if (!doc.isObject()) return false;
    const auto obj = doc.object();
    if (obj.value(QStringLiteral("type")).toString() != QLatin1String(kStopReply)) return false;
    if (obj.value(QStringLiteral("owner")).toString() != QLatin1String(kOwner)) return false;
    if (requestId.isEmpty() || obj.value(QStringLiteral("requestId")).toString() != requestId)
        return false;
    const auto count = obj.value(QStringLiteral("stopped"));
    if (!count.isDouble()) return false;
    if (stopped) *stopped = qMax(0, count.toInt());
    return true;
}

void requestStop(QObject* ctx, std::function<void(bool, int)> done, int timeoutMs) {
#ifndef Q_OS_WINDOWS
    QTimer::singleShot(0, ctx, [done] { done(false, 0); });
    return;
#else
    QByteArray raw(32, Qt::Uninitialized);
    QRandomGenerator::system()->generate(reinterpret_cast<quint32*>(raw.data()),
                                         reinterpret_cast<quint32*>(raw.data() + raw.size()));
    const QString id = QString::fromLatin1(raw.toHex());

    auto* socket = new QLocalSocket(ctx);
    auto* timer = new QTimer(socket);
    timer->setSingleShot(true);
    auto finished = std::make_shared<bool>(false);
    auto buffer = std::make_shared<QByteArray>();
    auto finish = [socket, done, finished](bool replied, int stopped) {
        if (*finished) return;
        *finished = true;
        done(replied, stopped);
        socket->abort();
        socket->deleteLater();
    };
    QObject::connect(socket, &QLocalSocket::connected, socket, [socket, id] {
        socket->write(stopRequestLine(id));
        socket->flush();
    });
    QObject::connect(socket, &QLocalSocket::readyRead, socket, [socket, buffer, id, finish] {
        buffer->append(socket->readAll());
        for (qsizetype pos; (pos = buffer->indexOf('\n')) >= 0;) {
            const QByteArray line = buffer->left(pos);
            buffer->remove(0, pos + 1);
            int stopped = 0;
            if (parseStopReply(line, id, &stopped)) { finish(true, stopped); return; }
        }
        if (buffer->size() > 64 * 1024) finish(false, 0);
    });
    QObject::connect(socket, &QLocalSocket::errorOccurred, socket, [finish] { finish(false, 0); });
    QObject::connect(timer, &QTimer::timeout, socket, [finish] { finish(false, 0); });
    timer->start(timeoutMs);
    socket->connectToServer(QLatin1String(kDaemonPipe));
#endif
}

int stopXrayLeftoverBlocking(int timeoutMs) {
#ifndef Q_OS_WINDOWS
    Q_UNUSED(timeoutMs);
    return -1;
#else
    QByteArray raw(32, Qt::Uninitialized);
    QRandomGenerator::system()->generate(reinterpret_cast<quint32*>(raw.data()),
                                         reinterpret_cast<quint32*>(raw.data() + raw.size()));
    const QString id = QString::fromLatin1(raw.toHex());
    QLocalSocket socket;
    socket.connectToServer(QLatin1String(kDaemonPipe));
    if (!socket.waitForConnected(timeoutMs)) return -1;
    socket.write(QJsonDocument(QJsonObject{{QStringLiteral("type"), QStringLiteral("mayakStopXrayLeftover")},
        {QStringLiteral("requestId"), id}}).toJson(QJsonDocument::Compact) + '\n');
    socket.flush();
    QByteArray buffer;
    QElapsedTimer elapsed; elapsed.start();
    while (elapsed.elapsed() < timeoutMs && socket.waitForReadyRead(int(qMax<qint64>(1, timeoutMs - elapsed.elapsed())))) {
        buffer.append(socket.readAll());
        for (qsizetype pos; (pos = buffer.indexOf('\n')) >= 0;) {
            const auto doc = QJsonDocument::fromJson(buffer.left(pos).trimmed());
            buffer.remove(0, pos + 1);
            const auto obj = doc.object();
            if (obj.value(QStringLiteral("type")).toString() == QStringLiteral("mayakXrayLeftoverStopped") &&
                obj.value(QStringLiteral("owner")).toString() == QLatin1String(kOwner) &&
                obj.value(QStringLiteral("requestId")).toString() == id && obj.value(QStringLiteral("stopped")).isDouble())
                return qMax(0, obj.value(QStringLiteral("stopped")).toInt());
        }
        if (buffer.size() > 64 * 1024) return -1;
    }
    return -1;
#endif
}

}  // namespace mayak::foreignvpn
