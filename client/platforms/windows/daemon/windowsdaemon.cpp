/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "windowsdaemon.h"

#include <Windows.h>
#include <qassert.h>

#include <QCoreApplication>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLocalSocket>
#include <QNetworkInterface>
#include <QTextStream>
#include <QtGlobal>

#include "daemon/daemonerrors.h"
#include "dnsutilswindows.h"
#include "leakdetector.h"
#include "logger.h"
#include "platforms/windows/daemon/windowsfirewall.h"
#include "platforms/windows/daemon/windowssplittunnel.h"
#include "windowsfirewall.h"
#include "mayakforeignvpnstop.h"

#include "core/utils/networkUtilities.h"

namespace {
Logger logger("WindowsDaemon");
}

WindowsDaemon::WindowsDaemon() : Daemon(nullptr) {
  MZ_COUNT_CTOR(WindowsDaemon);
  m_firewallManager = WindowsFirewall::create(this);
  Q_ASSERT(m_firewallManager != nullptr);

  m_wgutils = WireguardUtilsWindows::create(m_firewallManager, this);
  m_dnsutils = new DnsUtilsWindows(this);
  m_splitTunnelManager = WindowsSplitTunnel::create(m_firewallManager);

  connect(m_wgutils.get(), &WireguardUtilsWindows::backendFailure, this,
          &WindowsDaemon::monitorBackendFailure);
  connect(this, &WindowsDaemon::activationFailure,
          [this]() { m_firewallManager->disableKillSwitch(); });
}

WindowsDaemon::~WindowsDaemon() {
  MZ_COUNT_DTOR(WindowsDaemon);
  logger.debug() << "Daemon released";
}

void WindowsDaemon::prepareActivation(const InterfaceConfig& config, int inetAdapterIndex) {
  // Before creating the interface we need to check which adapter
  // routes to the server endpoint
  if (inetAdapterIndex == 0) {
      auto serveraddr = QHostAddress(config.m_serverIpv4AddrIn);
      m_inetAdapterIndex = NetworkUtilities::AdapterIndexTo(serveraddr);
  } else {
      m_inetAdapterIndex = inetAdapterIndex;
  }
}

QString WindowsDaemon::mayakPrepareSplitTunnel() {
  if (m_splitTunnelManager) return QStringLiteral("ok");
  // Only a real Mullvad installation is "mullvad". WindowsSplitTunnel::detectConflict() also reports a device
  // taken by AmneziaVPN while Mayak's driver is unregistered (every Mayak service stop unregisters it), which is
  // exactly the case the release below fixes; create() runs that check again after the release.
  if (MayakForeignVpnStop::mullvadInstalled()) return QStringLiteral("mullvad");
  const auto amnezia = MayakForeignVpnStop::amneziaSplitTunnelState();
  if (amnezia.driverRunning && amnezia.vpnActive) return QStringLiteral("amnezia_active");
  if (amnezia.driverRunning && amnezia.servicePending) return QStringLiteral("amnezia_busy");
  const qint64 now = QDateTime::currentMSecsSinceEpoch();
  const bool recentlyFailed = m_splitTunnelTakeoverFailedAt && now - m_splitTunnelTakeoverFailedAt < 10 * 60 * 1000;
  MayakForeignVpnStop::AmneziaSplitTunnelRelease released;
  // Release AmneziaVPN's copy only when Mayak's own copy is installed and can take the device.
  if (amnezia.driverRunning && !recentlyFailed && MayakForeignVpnStop::mayakDriverFileExists())
    released = MayakForeignVpnStop::releaseAmneziaSplitTunnel();
  m_splitTunnelManager = WindowsSplitTunnel::create(m_firewallManager);
  if (released.serviceStopRequested) MayakForeignVpnStop::restartAmneziaService();
  if (!m_splitTunnelManager && amnezia.driverRunning) m_splitTunnelTakeoverFailedAt = now;
  logger.info() << QStringLiteral("MayakNet event=split_tunnel_prepare amnezia_driver=%1 released=%2 ok=%3")
                       .arg(amnezia.driverRunning ? 1 : 0).arg(released.driverStopped ? 1 : 0).arg(m_splitTunnelManager ? 1 : 0);
  if (m_splitTunnelManager) return QStringLiteral("ok");
  return amnezia.driverRunning ? QStringLiteral("amnezia_holds") : QStringLiteral("unavailable");
}

bool WindowsDaemon::ensureSplitTunnel() {
  return m_splitTunnelManager != nullptr || mayakPrepareSplitTunnel() == QStringLiteral("ok");
}

void WindowsDaemon::activateSplitTunnel(const InterfaceConfig& config, int vpnAdapterIndex) {
    if (m_splitTunnelManager == nullptr && config.m_vpnDisabledApps.length() > 0) ensureSplitTunnel();
    if (m_splitTunnelManager == nullptr) {
        if (config.m_vpnDisabledApps.length() > 0) {
            logger.error() << "Split tunnel manager is not initialized";
            emit backendFailure(DaemonError::ERROR_SPLIT_TUNNEL_INIT_FAILURE);
        }
        return;
    }

  if (config.m_vpnDisabledApps.length() > 0) {
      if (!m_splitTunnelManager->start(m_inetAdapterIndex, vpnAdapterIndex)) {
          logger.error() << "Failed to start split tunnel";
          emit backendFailure(DaemonError::ERROR_SPLIT_TUNNEL_START_FAILURE);
          return;
      }
      if (!m_splitTunnelManager->excludeApps(config.m_vpnDisabledApps)) {
          logger.error() << "Failed to apply split tunnel app exclusions";
          emit backendFailure(DaemonError::ERROR_SPLIT_TUNNEL_EXCLUDE_FAILURE);
          return;
      }
      if (!m_splitTunnelManager->isRunning()) {
          logger.error() << "Split tunnel did not reach running state";
          emit backendFailure(DaemonError::ERROR_SPLIT_TUNNEL_START_FAILURE);
      }
  } else if (!m_splitTunnelManager->stop()) {
      logger.error() << "Failed to stop split tunnel";
      emit backendFailure();
  }
}

bool WindowsDaemon::run(Op op, const InterfaceConfig& config) {
  // Mayak: without the driver nothing was excluded, so there is nothing to undo. Failing Down here left the
  // service in an uncertain teardown forever ("Служба VPN не отвечает" until the service restarted).
  if (!m_splitTunnelManager && op == Down) return true;
  if (!m_splitTunnelManager && config.m_vpnDisabledApps.length() > 0) ensureSplitTunnel();
  if (!m_splitTunnelManager) {
    if (config.m_vpnDisabledApps.length() > 0) {
      // The Client has sent us a list of disabled apps, but we failed
      // to init the the split tunnel driver.
      // So let the client know this was not possible
      logger.error() << "Split tunnel manager is not initialized";
      emit backendFailure(DaemonError::ERROR_SPLIT_TUNNEL_INIT_FAILURE);
      return false;
    }
    return true;
  }

  if (op == Down) {
    return m_splitTunnelManager->stop();
  }
  if (config.m_vpnDisabledApps.length() > 0) {
    if (!m_splitTunnelManager->start(m_inetAdapterIndex)) {
      logger.error() << "Split tunnel start failed";
      emit backendFailure(DaemonError::ERROR_SPLIT_TUNNEL_START_FAILURE);
      return false;
    };
    if (!m_splitTunnelManager->excludeApps(config.m_vpnDisabledApps)) {
      logger.error() << "Split tunnel app exclusion failed";
      emit backendFailure(DaemonError::ERROR_SPLIT_TUNNEL_EXCLUDE_FAILURE);
      return false;
    };
    // Now the driver should be running (State == 4)
    if (!m_splitTunnelManager->isRunning()) {
      logger.error() << "Split tunnel did not reach running state";
      emit backendFailure(DaemonError::ERROR_SPLIT_TUNNEL_START_FAILURE);
      return false;
    }
    return true;
  }
  return m_splitTunnelManager->stop();
}

void WindowsDaemon::monitorBackendFailure() {
  logger.warning() << "Tunnel service is down";

  emit backendFailure();
  deactivate();
}
