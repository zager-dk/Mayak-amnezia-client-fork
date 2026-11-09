/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "windowstunnelservice.h"

#include <Windows.h>

#include <QDateTime>
#include <QElapsedTimer>
#include <QScopeGuard>

#include "leakdetector.h"
#include "logger.h"
#include "platforms/windows/windowscommons.h"
#include "platforms/windows/windowsutils.h"
#include "windowsdaemon.h"

#define TUNNEL_NAMED_PIPE \
  "\\\\."                 \
  "\\pipe\\ProtectedPrefix\\Administrators\\AmneziaWG\\MayakVPN"

constexpr uint32_t WINDOWS_TUNNEL_MONITOR_TIMEOUT_MSEC = 2000;

namespace {
Logger logger("WindowsTunnelService");
}  // namespace

static bool stopAndDeleteTunnelService(SC_HANDLE service);
static bool waitForServiceStatus(SC_HANDLE service, DWORD expectedStatus);

WindowsTunnelService::WindowsTunnelService(QObject* parent) : QObject(parent) {
  MZ_COUNT_CTOR(WindowsTunnelService);
  logger.debug() << "WindowsTunnelService created.";

  m_scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
  if (m_scm == nullptr) {
    WindowsUtils::windowsLog("Failed to open SCManager");
  }

  connect(&m_timer, &QTimer::timeout, this, &WindowsTunnelService::timeout);
}

WindowsTunnelService::~WindowsTunnelService() {
  MZ_COUNT_DTOR(WindowsTunnelService);
  if (!stop()) {
    // Object destruction cannot retain a retry handle. Shut down the logger
    // without claiming native teardown; live stop() callers retain ownership.
    m_timer.stop();
    if (m_logworker) {
      m_logthread.quit();
      m_logthread.wait();
      m_logworker = nullptr;
    }
    if (m_service) CloseServiceHandle((SC_HANDLE)m_service);
    m_service = nullptr;
  }
  CloseServiceHandle((SC_HANDLE)m_scm);
}

bool WindowsTunnelService::stop() {
  // Retain the owned handle after failure so the exact service can be retried.
  if (m_service && !stopAndDeleteTunnelService((SC_HANDLE)m_service)) return false;
  if (m_service) CloseServiceHandle((SC_HANDLE)m_service);
  m_service = nullptr;
  m_timer.stop();
  if (m_logworker) {
    m_logthread.quit();
    m_logthread.wait();
    m_logworker = nullptr;
  }
  return true;
}

bool WindowsTunnelService::interfaceExists() {
  if (m_service) return true; // Includes stopped/unknown state awaiting deletion.
  SC_HANDLE service = OpenService((SC_HANDLE)m_scm, TUNNEL_SERVICE_NAME, SERVICE_QUERY_STATUS);
  if (service) { CloseServiceHandle(service); return true; }
  return GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST;
}

QString WindowsTunnelService::pipeName() { return QStringLiteral(TUNNEL_NAMED_PIPE); }

bool WindowsTunnelService::setReplySucceeded(const QString& reply) {
  // Preserve and validate the entire frame. No whitespace or extra records.
  return reply == QStringLiteral("errno=0\n\n");
}

bool WindowsTunnelService::isRunning() {
  if (m_service == nullptr) {
    return false;
  }

  SERVICE_STATUS status;
  if (!QueryServiceStatus((SC_HANDLE)m_service, &status)) {
    return false;
  }

  return status.dwCurrentState == SERVICE_RUNNING;
}

void WindowsTunnelService::timeout() {
  if (m_service == nullptr) {
    logger.error() << "The service doesn't exist";
    emit backendFailure();
    return;
  }

  SERVICE_STATUS status;
  if (!QueryServiceStatus((SC_HANDLE)m_service, &status)) {
    WindowsUtils::windowsLog("Failed to retrieve the service status");
    emit backendFailure();
    return;
  }

  if (status.dwCurrentState == SERVICE_RUNNING) {
    // The service is active
    return;
  }

  logger.debug() << "The service is not active";
  emit backendFailure();
}

bool WindowsTunnelService::start(const QString& configData) {
  logger.debug() << "Starting the tunnel service";

  // Never adopt or terminate a preexisting service, even if it shares our name.
  if (interfaceExists()) return false;
  SC_HANDLE scm = (SC_HANDLE)m_scm;
  SC_HANDLE service = nullptr;
  auto guard = qScopeGuard([&] {
    // CreateService may succeed before a later setup step fails. Preserve the
    // handle before cleanup, and preserve it on cleanup failure for exact retry.
    if (service) {
      m_service = service;
      stop();
    }
  });

  QString serviceCmdline;
  {
    QTextStream out(&serviceCmdline);
    out << "\"" << qApp->applicationFilePath() << "\" tunneldaemon \""
        << configData << "\"";
  }

  logger.debug() << "Service:" << qApp->applicationFilePath();

  service = CreateService(scm, TUNNEL_SERVICE_NAME, L"Mayak VPN (tunnel)",
                          SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                          SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                          (const wchar_t*)serviceCmdline.utf16(), nullptr, 0,
                          TEXT("Nsi\0TcpIp\0"), nullptr, nullptr);
  if (!service) {
    WindowsUtils::windowsLog("Failed to create the tunnel service");
    return false;
  }

  SERVICE_DESCRIPTION sd = {
      (wchar_t*)L"Manages the Mayak VPN tunnel connection"};

  if (!ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &sd)) {
    WindowsUtils::windowsLog(
        "Failed to set the description to the tunnel service");
    return false;
  }

  SERVICE_SID_INFO ssi;
  ssi.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
  if (!ChangeServiceConfig2(service, SERVICE_CONFIG_SERVICE_SID_INFO, &ssi)) {
    WindowsUtils::windowsLog("Failed to set the SID to the tunnel service");
    return false;
  }

  if (!StartService(service, 0, nullptr)) {
    WindowsUtils::windowsLog("Failed to start the service");
    return false;
  }

  if (waitForServiceStatus(service, SERVICE_RUNNING)) {
    logger.debug() << "The tunnel service is up and running";
    guard.dismiss();
    m_service = service;
    m_logworker = new WindowsTunnelLogger(WindowsCommons::tunnelLogFile());
    m_logworker->moveToThread(&m_logthread);
    connect(&m_logthread, &QThread::finished, m_logworker, &QObject::deleteLater);
    m_logthread.start();
    m_timer.start(WINDOWS_TUNNEL_MONITOR_TIMEOUT_MSEC);
    return true;
  }

  logger.error() << "Failed to run the tunnel service";

  SERVICE_STATUS status;
  if (!QueryServiceStatus(service, &status)) {
    WindowsUtils::windowsLog("Failed to retrieve the service status");
    return false;
  }

  logger.debug() << "The tunnel service exited with status:"
                 << status.dwWin32ExitCode << "-" << exitCodeToFailure(&status);

  return false;
}

static bool stopAndDeleteTunnelService(SC_HANDLE service) {
  SERVICE_STATUS status;
  if (!QueryServiceStatus(service, &status)) {
    WindowsUtils::windowsLog("Failed to retrieve the service status");
    return false;
  }

  logger.debug() << "The current service is stopped:"
                 << (status.dwCurrentState == SERVICE_STOPPED);

  if (status.dwCurrentState != SERVICE_STOPPED) {
    logger.debug() << "The service is not stopped yet.";
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
      WindowsUtils::windowsLog("Failed to control the service");
      return false;
    }

    if (!waitForServiceStatus(service, SERVICE_STOPPED)) {
      logger.error() << "Unable to stop the service";
      return false;
    }
  }

  logger.debug() << "Proceeding with the deletion";

  if (!DeleteService(service) && GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE) {
    WindowsUtils::windowsLog("Failed to delete the service");
    return false;
  }

  return true;
}

QString WindowsTunnelService::uapiCommand(const QString& command) {
  // One bounded transaction; never turn partial IO into an acknowledgement.
  QElapsedTimer deadline;
  deadline.start();
  const QString name = pipeName();
  const auto tunnelName = reinterpret_cast<LPCWSTR>(name.utf16());
  if (!WaitNamedPipeW(tunnelName, 1000)) return {};
  HANDLE pipe = CreateFileW(tunnelName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                            OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
  if (pipe == INVALID_HANDLE_VALUE) return {};
  auto pipeGuard = qScopeGuard([&] { CloseHandle(pipe); });
  DWORD mode = PIPE_READMODE_BYTE;
  if (!SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr)) return {};
  HANDLE event = CreateEvent(nullptr, TRUE, FALSE, nullptr);
  if (!event) return {};
  auto eventGuard = qScopeGuard([&] { CloseHandle(event); });
  const auto transfer = [&](bool writing, char* data, DWORD size, DWORD& count) {
    OVERLAPPED operation = {};
    operation.hEvent = event;
    ResetEvent(event);
    count = 0;
    BOOL ok = writing ? WriteFile(pipe, data, size, &count, &operation)
                      : ReadFile(pipe, data, size, &count, &operation);
    if (!ok && GetLastError() != ERROR_IO_PENDING) return false;
    if (!ok) {
      const qint64 remaining = 1000 - deadline.elapsed();
      if (remaining <= 0 || WaitForSingleObject(event, DWORD(remaining)) != WAIT_OBJECT_0) {
        CancelIoEx(pipe, &operation);
        // Drain cancellation before stack OVERLAPPED/event storage is released.
        GetOverlappedResult(pipe, &operation, &count, TRUE);
        return false;
      }
      if (!GetOverlappedResult(pipe, &operation, &count, FALSE)) return false;
    }
    return deadline.elapsed() <= 1000;
  };
  QByteArray message = command.toUtf8();
  while (!message.endsWith("\n\n")) message.append('\n');
  DWORD written = 0;
  if (!transfer(true, message.data(), DWORD(message.size()), written) ||
      written != DWORD(message.size())) return {};
  QByteArray reply;
  while (!reply.contains("\n\n")) {
    char buffer[512];
    DWORD read = 0;
    if (!transfer(false, buffer, sizeof(buffer), read) || read == 0) return {};
    reply.append(buffer, read);
    if (reply.size() > 1024 * 1024) return {};
  }
  if (!reply.endsWith("\n\n") || reply.indexOf("\n\n") != reply.size() - 2) return {};
  // Reject already buffered trailing records even when the terminator and
  // trailing bytes arrived in different reads. This connection is never reused.
  DWORD available = 0;
  if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) {
    if (GetLastError() != ERROR_BROKEN_PIPE) return {};
  } else if (available != 0) return {};
  return QString::fromUtf8(reply);
}

// static
static bool waitForServiceStatus(SC_HANDLE service, DWORD expectedStatus) {
  int tries = 0;
  while (tries < 30) {
    SERVICE_STATUS status;
    if (!QueryServiceStatus(service, &status)) {
      WindowsUtils::windowsLog("Failed to retrieve the service status");
      return false;
    }

    if (status.dwCurrentState == expectedStatus) {
      return true;
    }

    logger.warning() << "The service is not in the right status yet.";

    Sleep(1000);
    ++tries;
  }

  return false;
}

// static
QString WindowsTunnelService::exitCodeToFailure(const void* status) {
  const SERVICE_STATUS* st = static_cast<const SERVICE_STATUS*>(status);
  if (st->dwWin32ExitCode != ERROR_SERVICE_SPECIFIC_ERROR) {
    return WindowsUtils::getErrorMessage(st->dwWin32ExitCode);
  }

  // The order of this error code is taken from wireguard.
  switch (st->dwServiceSpecificExitCode) {
    case 0:
      return "No error";
    case 1:
      return "Error when opening the ringlogger log file";
    case 2:
      return "Error while loading the WireGuard configuration file from "
             "path.";
    case 3:
      return "Error while creating a WinTun device.";
    case 4:
      return "Error while listening on a named pipe.";
    case 5:
      return "Error while resolving DNS hostname endpoints.";
    case 6:
      return "Error while manipulating firewall rules.";
    case 7:
      return "Error while setting the device configuration.";
    case 8:
      return "Error while binding sockets to default routes.";
    case 9:
      return "Unable to set interface addresses, routes, dns, and/or "
             "interface settings.";
    case 10:
      return "Error while determining current executable path.";
    case 11:
      return "Error while opening the NUL file.";
    case 12:
      return "Error while attempting to track tunnels.";
    case 13:
      return "Error while attempting to enumerate current sessions.";
    case 14:
      return "Error while dropping privileges.";
    case 15:
      return "Windows internal error.";
    default:
      return QString("Unknown error (%1)").arg(st->dwServiceSpecificExitCode);
  }
}
