#include "mayakforeignvpnstop.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <iterator>

#include <windows.h>
#include <tlhelp32.h>
#include <QScopeGuard>

#include "logger.h"
#include "../../../core/utils/utilities.h"

namespace {
Logger logger("MayakForeignVpnStop");
constexpr DWORD kExitWaitMs = 1500;
constexpr DWORD kServiceWaitMs = 10000;

const wchar_t* kAmneziaDriver = L"AmneziaVPNSplitTunnel";
const wchar_t* kAmneziaService = L"AmneziaVPN-service";

QString binaryPathOf(SC_HANDLE service) {
    DWORD needed = 0;
    QueryServiceConfigW(service, nullptr, 0, &needed);
    if (needed == 0) return {};
    QByteArray buffer(int(needed), 0);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
    if (!QueryServiceConfigW(service, config, needed, &needed) || !config->lpBinaryPathName) return {};
    return QDir::fromNativeSeparators(QString::fromWCharArray(config->lpBinaryPathName)).toLower().remove(QLatin1Char('"'));
}

DWORD stateOf(SC_HANDLE service) {
    SERVICE_STATUS status{};
    return QueryServiceStatus(service, &status) ? status.dwCurrentState : 0;
}

bool waitForState(SC_HANDLE service, DWORD wanted, DWORD timeoutMs) {
    for (DWORD waited = 0; waited <= timeoutMs; waited += 100) {
        if (stateOf(service) == wanted) return true;
        Sleep(100);
    }
    return stateOf(service) == wanted;
}

// Sends STOP and waits. *requested tells whether the stop was actually accepted by the service.
bool stopAndWait(SC_HANDLE service, bool* requested = nullptr) {
    if (requested) *requested = false;
    if (stateOf(service) == SERVICE_STOPPED) return true;
    SERVICE_STATUS status{};
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) return stateOf(service) == SERVICE_STOPPED;
    if (requested) *requested = true;
    return waitForState(service, SERVICE_STOPPED, kServiceWaitMs);
}

bool isAmneziaPath(const QString& path) { return path.contains(QLatin1String("/amneziavpn/")); }

// AmneziaVPN's own tunnels: its WireGuard/AWG tunnel service, or its Xray/OpenVPN helper processes.
bool amneziaVpnActive(SC_HANDLE scm) {
    if (SC_HANDLE tunnel = OpenServiceW(scm, L"AmneziaWGTunnel$AmneziaVPN", SERVICE_QUERY_STATUS)) {
        const DWORD state = stateOf(tunnel);
        CloseServiceHandle(tunnel);
        if (state != 0 && state != SERVICE_STOPPED) return true;
    }
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return true; // unknown: never assume it is idle
    bool active = false;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    for (BOOL ok = Process32FirstW(snapshot, &entry); ok && !active; ok = Process32NextW(snapshot, &entry)) {
        if (_wcsicmp(entry.szExeFile, L"tun2socks.exe") != 0 && _wcsicmp(entry.szExeFile, L"openvpn.exe") != 0) continue;
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
        if (!process) continue;
        wchar_t image[MAX_PATH * 2] = {};
        DWORD length = DWORD(std::size(image));
        if (QueryFullProcessImageNameW(process, 0, image, &length))
            active = isAmneziaPath(QDir::fromNativeSeparators(QString::fromWCharArray(image, int(length))).toLower());
        CloseHandle(process);
    }
    CloseHandle(snapshot);
    return active;
}
}  // namespace

namespace MayakForeignVpnStop {

bool isKnownCore(const QString& imagePath) {
    const QString path = QDir::fromNativeSeparators(imagePath).toLower();
    return path.endsWith(QLatin1String("/browsec-desktop/resources/xray/browbox.exe"));
}

int stopKnownCores() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    int stopped = 0;
    int seen = 0;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    for (BOOL ok = Process32FirstW(snapshot, &entry); ok; ok = Process32NextW(snapshot, &entry)) {
        if (_wcsicmp(entry.szExeFile, L"browbox.exe") != 0) continue;
        HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                     FALSE, entry.th32ProcessID);
        if (!process) continue;
        wchar_t image[MAX_PATH * 2] = {};
        DWORD length = DWORD(std::size(image));
        const bool known = QueryFullProcessImageNameW(process, 0, image, &length) &&
                           isKnownCore(QString::fromWCharArray(image, int(length)));
        if (known) {
            ++seen;
            if (TerminateProcess(process, 1) &&
                WaitForSingleObject(process, kExitWaitMs) == WAIT_OBJECT_0)
                ++stopped;
        }
        CloseHandle(process);
    }
    CloseHandle(snapshot);
    logger.info() << QStringLiteral("MayakNet event=foreign_vpn_stop program=browsec seen=%1 stopped=%2")
                         .arg(seen).arg(stopped);
    return stopped;
}

int stopOwnTun2Socks() {
    const QString own = QDir::cleanPath(QDir::fromNativeSeparators(Utils::tun2socksPath())).toLower();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE || own.isEmpty()) {
        if (snapshot != INVALID_HANDLE_VALUE) CloseHandle(snapshot);
        return 0;
    }
    int stopped = 0, seen = 0;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    for (BOOL ok = Process32FirstW(snapshot, &entry); ok; ok = Process32NextW(snapshot, &entry)) {
        if (_wcsicmp(entry.szExeFile, L"tun2socks.exe") != 0) continue;
        HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                     FALSE, entry.th32ProcessID);
        if (!process) continue;
        wchar_t image[MAX_PATH * 2] = {};
        DWORD length = DWORD(std::size(image));
        const bool ours = QueryFullProcessImageNameW(process, 0, image, &length) &&
            QDir::cleanPath(QDir::fromNativeSeparators(QString::fromWCharArray(image, int(length)))).toLower() == own;
        if (ours) {
            ++seen;
            if (TerminateProcess(process, 1) && WaitForSingleObject(process, kExitWaitMs) == WAIT_OBJECT_0) ++stopped;
        }
        CloseHandle(process);
    }
    CloseHandle(snapshot);
    logger.info() << QStringLiteral("MayakNet event=xray_leftover_tun2socks seen=%1 stopped=%2").arg(seen).arg(stopped);
    return stopped;
}

bool mayakDriverFileExists() {
    return QFileInfo::exists(QCoreApplication::applicationDirPath() + QStringLiteral("/mullvad-split-tunnel.sys"));
}

bool mullvadInstalled() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    auto closeScm = qScopeGuard([scm] { CloseServiceHandle(scm); });
    SC_HANDLE service = OpenServiceW(scm, L"MullvadVPN", SERVICE_QUERY_STATUS);
    if (!service) return GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST;
    CloseServiceHandle(service);
    return true;
}

AmneziaSplitTunnelState amneziaSplitTunnelState() {
    AmneziaSplitTunnelState state;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return state;
    auto closeScm = qScopeGuard([scm] { CloseServiceHandle(scm); });
    SC_HANDLE driver = OpenServiceW(scm, kAmneziaDriver, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    if (!driver) return state; // AmneziaVPN is not installed: nothing holds the device
    auto closeDriver = qScopeGuard([driver] { CloseServiceHandle(driver); });
    if (!binaryPathOf(driver).endsWith(QLatin1String("/amneziavpn/mullvad-split-tunnel.sys"))) return state;
    state.driverRunning = stateOf(driver) == SERVICE_RUNNING;
    if (!state.driverRunning) return state;
    state.vpnActive = amneziaVpnActive(scm);
    if (SC_HANDLE service = OpenServiceW(scm, kAmneziaService, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)) {
        const DWORD s = stateOf(service);
        state.servicePending = isAmneziaPath(binaryPathOf(service)) && s != SERVICE_RUNNING && s != SERVICE_STOPPED;
        CloseServiceHandle(service);
    }
    return state;
}

AmneziaSplitTunnelRelease releaseAmneziaSplitTunnel() {
    AmneziaSplitTunnelRelease result;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return result;
    auto closeScm = qScopeGuard([scm] { CloseServiceHandle(scm); });
    const DWORD access = SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP;
    SC_HANDLE driver = OpenServiceW(scm, kAmneziaDriver, access);
    if (!driver) return result;
    auto closeDriver = qScopeGuard([driver] { CloseServiceHandle(driver); });
    if (!binaryPathOf(driver).endsWith(QLatin1String("/amneziavpn/mullvad-split-tunnel.sys"))) return result;
    // The AmneziaVPN service keeps the device open; the driver can stop only after it is closed.
    if (SC_HANDLE service = OpenServiceW(scm, kAmneziaService, access)) {
        if (isAmneziaPath(binaryPathOf(service)) && stateOf(service) == SERVICE_RUNNING)
            stopAndWait(service, &result.serviceStopRequested);
        CloseServiceHandle(service);
    }
    result.driverStopped = stopAndWait(driver);
    logger.info() << QStringLiteral("MayakNet event=split_tunnel_release amnezia_service_stop_requested=%1 amnezia_driver_stopped=%2")
                         .arg(result.serviceStopRequested ? 1 : 0).arg(result.driverStopped ? 1 : 0);
    return result;
}

void restartAmneziaService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return;
    auto closeScm = qScopeGuard([scm] { CloseServiceHandle(scm); });
    SC_HANDLE service = OpenServiceW(scm, kAmneziaService, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START);
    if (!service) return;
    auto closeService = qScopeGuard([service] { CloseServiceHandle(service); });
    if (!isAmneziaPath(binaryPathOf(service))) return;
    // AmneziaVPN keeps working; its own copy of the driver stays unloaded while Mayak's is loaded.
    // A stop that is still in progress is awaited first, so the service is never left stopped by Mayak.
    if (stateOf(service) == SERVICE_STOP_PENDING) waitForState(service, SERVICE_STOPPED, kServiceWaitMs);
    const bool started = stateOf(service) == SERVICE_RUNNING || StartServiceW(service, 0, nullptr);
    logger.info() << QStringLiteral("MayakNet event=split_tunnel_release amnezia_service_restarted=%1").arg(started ? 1 : 0);
}

}  // namespace MayakForeignVpnStop
