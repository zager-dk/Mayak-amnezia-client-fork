#include <QCoreApplication>
#include "platforms/windows/daemon/windowstunnellogger.h"
#include "platforms/windows/windowsutils.h"
#include "platforms/windows/windowscommons.h"
#include "platforms/windows/daemon/windowsfirewall.h"
QString WindowsCommons::tunnelLogFile() { return {}; }
void WindowsUtils::windowsLog(const QString&) {}
QString WindowsUtils::getErrorMessage(quint32) { return {}; }
WindowsTunnelLogger::WindowsTunnelLogger(const QString&, QObject* parent) : QObject(parent) {}
WindowsTunnelLogger::~WindowsTunnelLogger() = default;
void WindowsTunnelLogger::timeout() {}
#ifndef TEST_NATIVE_FIREWALL
// WFP policy is independently tested in test_windows_firewall_cleanup; the
// transaction fixture only needs a deterministic collaborator for the backend.
WindowsFirewall::WindowsFirewall(HANDLE session, QObject* parent) : QObject(parent), m_sessionHandle(session) {}
WindowsFirewall::~WindowsFirewall() = default;
WindowsFirewall* WindowsFirewall::create(QObject* parent) { return new WindowsFirewall(nullptr, parent); }
bool WindowsFirewall::allowAllTraffic() { return true; }
bool WindowsFirewall::enableInterface(int) { return true; }
bool WindowsFirewall::enablePeerTraffic(const InterfaceConfig&) { return true; }
bool WindowsFirewall::disablePeerTraffic(const QString&) { return true; }
bool WindowsFirewall::disableKillSwitch() { return true; }
bool WindowsFirewall::enableLanBypass(const QList<IPAddress>&) { return true; }
#endif
