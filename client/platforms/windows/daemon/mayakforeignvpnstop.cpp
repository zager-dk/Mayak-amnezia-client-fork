#include "mayakforeignvpnstop.h"

#include <QDir>
#include <iterator>

#include <windows.h>
#include <tlhelp32.h>

#include "logger.h"
#include "../../../core/utils/utilities.h"

namespace {
Logger logger("MayakForeignVpnStop");
constexpr DWORD kExitWaitMs = 1500;
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

}  // namespace MayakForeignVpnStop
