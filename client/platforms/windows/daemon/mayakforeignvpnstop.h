#pragma once

#include <QString>

// Mayak service: ends known foreign VPN cores on the user's request (button in the app).
// Only Browsec's tunnel core is known: <...>\browsec-desktop\resources\xray\browbox.exe.
// Nothing named by the caller is ever terminated; the list is fixed here.
namespace MayakForeignVpnStop {

// True when a full image path is Browsec's tunnel core.
bool isKnownCore(const QString& imagePath);

// Terminates every running known core and waits briefly for each to exit.
// Returns the number of processes that exited.
int stopKnownCores();
// Mayak Xray path: ends tun2socks processes started from this installation's own tun2socks
// executable (a tunnel left by an app that ended). Never touches any other program.
int stopOwnTun2Socks();

// AmneziaVPN ships the same split tunnel driver as Mayak (same MULLVADSPLITTUNNEL device). While its copy is
// loaded, Mayak's own copy cannot start and app exclusions fail. Releases it for Mayak: stops AmneziaVPN-service
// (it holds the device open) and then AmneziaVPN's driver, and starts AmneziaVPN-service again. Only the exact
// services of an AmneziaVPN installation (checked by their binary paths) are touched; their start settings are
// not changed. While Mayak holds the device, AmneziaVPN's own app exclusions do not work.
struct AmneziaSplitTunnelState {
    bool driverRunning = false;  // AmneziaVPN's copy of the driver holds the device
    bool vpnActive = false;      // AmneziaVPN runs a VPN right now: never stopped by Mayak
    bool servicePending = false; // AmneziaVPN-service is starting/stopping (e.g. its installer)
};
AmneziaSplitTunnelState amneziaSplitTunnelState();
// Mayak's own driver file is next to the service (create() registers it when needed), so a takeover can work.
// Its registration is NOT required: the driver code removes it whenever the Mayak service stops.
bool mayakDriverFileExists();
// Mullvad VPN is installed (its service exists): its driver must never be taken over.
bool mullvadInstalled();
struct AmneziaSplitTunnelRelease {
    bool driverStopped = false;
    bool serviceStopRequested = false; // always restart it with restartAmneziaService() afterwards
};
// Precondition: amneziaSplitTunnelState() reported driverRunning, !vpnActive, !servicePending.
AmneziaSplitTunnelRelease releaseAmneziaSplitTunnel();
void restartAmneziaService();

}  // namespace MayakForeignVpnStop
