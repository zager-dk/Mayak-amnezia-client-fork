#pragma once

#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>
#include <functional>

// Another VPN that is active on this Windows PC while Mayak connects.
// Windows (unlike Android) lets several VPNs run at once; a second tunnel that
// captures all traffic can keep Mayak's handshake from reaching the exit. Mayak
// only reads adapter and route tables to notice it. Stopping is limited to
// known cores (Browsec's browbox.exe) and runs in the Mayak service only after
// the user pressed the button.
namespace mayak::foreignvpn {

struct Adapter {
    quint32 index = 0;
    QString alias;        // e.g. "browbox-tun-<uuid>"
    QString description;  // e.g. "sing-tun Tunnel"
    quint32 ifType = 0;   // IANA ifType: 53 prop. virtual, 131 tunnel
    bool up = false;
};

struct Route {
    quint32 index = 0;
    bool v6 = false;
    quint8 prefixLength = 0;
    quint32 v4Destination = 0;  // host byte order, IPv4 only
};

struct Finding {
    QString program;         // "Browsec", or the adapter name for an unknown VPN
    QString adapter;
    bool stoppable = false;  // Mayak's service knows how to stop this core
    bool found() const { return !adapter.isEmpty(); }
};

// Pure decision used by detect(); processNames are lower-case image names.
Finding classify(const QList<Adapter>& adapters, const QList<Route>& routes,
                 const QStringList& processNames);

// Windows: reads the live adapter, route and process tables. Elsewhere: nothing found.
Finding detect();

// Line protocol with the Mayak service (daemon pipe).
inline constexpr const char* kStopCommand = "mayakStopForeignVpn";
inline constexpr const char* kStopReply = "mayakForeignVpnStopped";
QByteArray stopRequestLine(const QString& requestId);
// True only for a reply to this request; *stopped is the number of cores ended.
bool parseStopReply(const QByteArray& line, const QString& requestId, int* stopped);

// Asks the Mayak service to stop known foreign VPN cores. done(replied, stopped)
// runs once on ctx's thread; replied=false when the service did not answer in time.
void requestStop(QObject* ctx, std::function<void(bool replied, int stopped)> done,
                 int timeoutMs = 4000);

}  // namespace mayak::foreignvpn
