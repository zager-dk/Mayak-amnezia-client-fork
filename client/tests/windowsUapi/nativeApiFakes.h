#pragma once
// Forced into the test copies of production .cpp files only. No host SCM,
// named pipe, routing or WFP mutation is used by these deterministic fixtures.
#include <winsock2.h>
#include <Windows.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <fwpmu.h>
#include <QByteArray>
#include <QList>
#include <QtCore>
// Keep private-method linkage identical in every fixture translation unit;
// MSVC encodes access in symbols used by the terminal-failure regression.
#define private public
#include "platforms/windows/daemon/windowstunnelservice.h"
#undef private
namespace testapi {
struct State {
  bool preexisting = false, created = false, running = false;
  bool terminalStart = false;
  DWORD serviceExitCode = ERROR_SUCCESS, serviceSpecificExitCode = 0;
  bool createOk = true, describeOk = true, startOk = true, stopOk = true, deleteOk = true;
  bool openPipeOk = true, writeOk = true, shortWrite = false, readOk = true;
  bool zeroRead = false, pendingRead = false, luidOk = true;
  int creates = 0, controls = 0, deletes = 0, closedServices = 0, changes = 0;
  int reads = 0, writes = 0, cancels = 0, routeDeletes = 0;
  int wfpDeletes = 0, wfpCommits = 0, wfpAborts = 0;
  int sleeps = 0;
  DWORD error = ERROR_SUCCESS, routeDeleteResult = NO_ERROR;
  DWORD wfpDeleteResult = ERROR_SUCCESS, wfpCommitResult = ERROR_SUCCESS;
  QByteArray reply = "errno=0\n\n";
  int offset = 0, chunkSize = 512;
};
inline State state;
inline SC_HANDLE scm() { return reinterpret_cast<SC_HANDLE>(1); }
inline SC_HANDLE openService() {
  if (state.preexisting) return reinterpret_cast<SC_HANDLE>(2);
  state.error = ERROR_SERVICE_DOES_NOT_EXIST; return nullptr;
}
inline SC_HANDLE createService() {
  ++state.creates;
  if (!state.createOk) return nullptr;
  state.created = true; return reinterpret_cast<SC_HANDLE>(2);
}
inline BOOL changeService() { ++state.changes; return state.describeOk; }
inline BOOL startService() { state.running = state.startOk && !state.terminalStart; return state.startOk; }
inline BOOL queryService(SERVICE_STATUS* status) {
  *status = {};
  status->dwCurrentState = state.running ? SERVICE_RUNNING : SERVICE_STOPPED;
  status->dwWin32ExitCode = state.serviceExitCode;
  status->dwServiceSpecificExitCode = state.serviceSpecificExitCode;
  return TRUE;
}
inline BOOL controlService(SERVICE_STATUS* status) {
  ++state.controls;
  if (!state.stopOk) return FALSE;
  state.running = false; return queryService(status);
}
inline BOOL deleteService() {
  ++state.deletes;
  if (!state.deleteOk) return FALSE;
  state.created = false; return TRUE;
}
inline BOOL closeService() { ++state.closedServices; return TRUE; }
inline HANDLE openPipe() { return state.openPipeOk ? reinterpret_cast<HANDLE>(3) : INVALID_HANDLE_VALUE; }
inline BOOL write(DWORD length, DWORD* written) {
  ++state.writes; *written = state.shortWrite ? length - 1 : length; return state.writeOk;
}
inline BOOL read(void* buffer, DWORD length, DWORD* count) {
  ++state.reads; *count = 0;
  if (state.pendingRead) { state.error = ERROR_IO_PENDING; return FALSE; }
  if (!state.readOk) return FALSE;
  if (state.zeroRead) return TRUE;
  int bytes = qMin(qMin(int(length), state.chunkSize), int(state.reply.size()) - state.offset);
  if (bytes <= 0) return FALSE;
  memcpy(buffer, state.reply.constData() + state.offset, bytes);
  state.offset += bytes; *count = bytes; return TRUE;
}
inline DWORD aliasLuid(NET_LUID* luid) { luid->Value = 5; return state.luidOk ? NO_ERROR : ERROR_NOT_FOUND; }
inline DWORD luidIndex(NET_IFINDEX* index) { *index = 5; return NO_ERROR; }
inline DWORD deleteRoute() { ++state.routeDeletes; return state.routeDeleteResult; }
inline DWORD interfaceTable(PMIB_IPINTERFACE_TABLE* table) {
  *table = static_cast<PMIB_IPINTERFACE_TABLE>(calloc(1, sizeof(MIB_IPINTERFACE_TABLE))); return NO_ERROR;
}
inline DWORD routeTable(PMIB_IPFORWARD_TABLE2* table) {
  *table = static_cast<PMIB_IPFORWARD_TABLE2>(calloc(1, sizeof(MIB_IPFORWARD_TABLE2))); return NO_ERROR;
}
}
#undef OpenSCManager
#define OpenSCManager(...) testapi::scm()
#undef OpenService
#define OpenService(...) testapi::openService()
#undef CreateService
#define CreateService(...) testapi::createService()
#undef ChangeServiceConfig2
#define ChangeServiceConfig2(...) testapi::changeService()
#undef StartService
#define StartService(...) testapi::startService()
#define CloseServiceHandle(...) testapi::closeService()
#define QueryServiceStatus(service, status) testapi::queryService(status)
#define ControlService(service, control, status) testapi::controlService(status)
#define DeleteService(...) testapi::deleteService()
#define Sleep(...) (++testapi::state.sleeps)
#define GetLastError() (testapi::state.error)
#define WaitNamedPipeW(...) TRUE
#define CreateFileW(...) testapi::openPipe()
#define SetNamedPipeHandleState(...) TRUE
#undef CreateEvent
#define CreateEvent(...) reinterpret_cast<HANDLE>(4)
#define ResetEvent(...) TRUE
#define CloseHandle(...) TRUE
#define WriteFile(pipe, data, length, written, overlapped) testapi::write(length, written)
#define ReadFile(pipe, data, length, count, overlapped) testapi::read(data, length, count)
#define WaitForSingleObject(...) WAIT_TIMEOUT
#define CancelIoEx(...) (++testapi::state.cancels, TRUE)
#define GetOverlappedResult(...) FALSE
#define PeekNamedPipe(pipeArg, bufferArg, sizeArg, readArg, available, leftArg) (*(available) = DWORD(testapi::state.reply.size() - testapi::state.offset), TRUE)
#define ConvertInterfaceAliasToLuid(alias, luid) testapi::aliasLuid(luid)
#define ConvertInterfaceLuidToIndex(luid, index) testapi::luidIndex(index)
#define NotifyRouteChange2(family, callback, context, initial, handle) (*(handle) = reinterpret_cast<HANDLE>(6), NO_ERROR)
#define CancelMibChangeNotify2(...) NO_ERROR
#define GetIpInterfaceTable(family, table) testapi::interfaceTable(table)
#define GetIpForwardTable2(family, table) testapi::routeTable(table)
#define FreeMibTable(table) free(table)
#define CreateIpForwardEntry2(...) NO_ERROR
#define DeleteIpForwardEntry2(...) testapi::deleteRoute()
#ifdef TEST_NATIVE_FIREWALL
// Seed/inspect teardown inputs without adding a production testing API.
#include <QtCore>
#include <QHostAddress>
#define private public
#include "platforms/windows/daemon/windowsfirewall.h"
#undef private
#define FwpmTransactionBegin0(...) ERROR_SUCCESS
#define FwpmTransactionCommit0(...) (++testapi::state.wfpCommits, testapi::state.wfpCommitResult)
#define FwpmTransactionAbort0(...) (++testapi::state.wfpAborts, ERROR_SUCCESS)
#define FwpmFilterDeleteById0(...) (++testapi::state.wfpDeletes, testapi::state.wfpDeleteResult)
#define FwpmEngineClose0(...) ERROR_SUCCESS
#endif
