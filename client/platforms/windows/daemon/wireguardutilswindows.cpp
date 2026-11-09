/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "wireguardutilswindows.h"

#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2ipdef.h>

#include <limits>

#include <QFileInfo>

#include "leakdetector.h"
#include "logger.h"
#include "windowsfirewall.h"

#pragma comment(lib, "iphlpapi.lib")

namespace {
Logger logger("WireguardUtilsWindows");
};  // namespace

std::unique_ptr<WireguardUtilsWindows> WireguardUtilsWindows::create(
    WindowsFirewall* fw, QObject* parent) {
  if (!fw) {
    logger.error() << "WireguardUtilsWindows::create: no wfp handle";
    return {};
  }

  // Can't use make_unique here as the Constructor is private :(
  auto utils = new WireguardUtilsWindows(parent, fw);
  return std::unique_ptr<WireguardUtilsWindows>(utils);
}

WireguardUtilsWindows::WireguardUtilsWindows(QObject* parent, WindowsFirewall* fw)
    : WireguardUtils(parent), m_tunnel(this), m_firewall(fw) {
  MZ_COUNT_CTOR(WireguardUtilsWindows);
  logger.debug() << "WireguardUtilsWindows created.";

  connect(&m_tunnel, &WindowsTunnelService::backendFailure, this,
          [&] { emit backendFailure(); });
}

WireguardUtilsWindows::~WireguardUtilsWindows() {
  MZ_COUNT_DTOR(WireguardUtilsWindows);
  logger.debug() << "WireguardUtilsWindows destroyed.";
}

QList<WireguardUtils::PeerStatus> WireguardUtilsWindows::getPeerStatus() {
  QString reply = m_tunnel.uapiCommand("get=1");
  PeerStatus status;
  QList<PeerStatus> peerList;
  bool hasRxBytes = false, hasTxBytes = false;
  bool hasSeconds = false, hasNanos = false, invalidNumbers = false;
  qint64 seconds = 0, nanoseconds = 0;
  // UAPI numeric fields are unsigned decimal text within our signed DTO range.
  const auto parseNumber = [](const QString& text, qint64* result) {
    if (text.isEmpty()) return false;
    qint64 number = 0;
    for (const QChar c : text) {
      if (c < QLatin1Char('0') || c > QLatin1Char('9')) return false;
      const int digit = c.unicode() - '0';
      if (number > (std::numeric_limits<qint64>::max() - digit) / 10) return false;
      number = number * 10 + digit;
    }
    *result = number;
    return true;
  };
  const auto finishPeer = [&] {
    if (status.m_pubkey.isEmpty()) return;
    // Compute once, only after both independently validated components exist.
    status.m_hasHandshake = !invalidNumbers && hasSeconds && hasNanos &&
        nanoseconds < 1000000000 &&
        seconds <= (std::numeric_limits<qint64>::max() - nanoseconds / 1000000) / 1000;
    status.m_handshake = status.m_hasHandshake ? seconds * 1000 + nanoseconds / 1000000 : 0;
    status.m_statsValid = !invalidNumbers && hasRxBytes && hasTxBytes && status.m_hasHandshake;
    peerList.append(status);
  };
  for (const QString& line : reply.split('\n')) {
    int eq = line.indexOf('=');
    if (eq <= 0) {
      continue;
    }
    QString name = line.left(eq);
    QString value = line.mid(eq + 1);

    if (name == "public_key") {
      finishPeer();
      QByteArray pubkey = QByteArray::fromHex(value.toUtf8());
      status = PeerStatus(pubkey.toBase64());
      hasRxBytes = hasTxBytes = hasSeconds = hasNanos = invalidNumbers = false;
      seconds = nanoseconds = 0;
    } else if (!status.m_pubkey.isEmpty()) {
      // A duplicate or malformed field poisons this peer, regardless of order.
      auto readNumber = [&](bool& seen, qint64& number) {
        if (seen || !parseNumber(value, &number)) invalidNumbers = true;
        seen = true;
      };
      if (name == "tx_bytes") readNumber(hasTxBytes, status.m_txBytes);
      else if (name == "rx_bytes") readNumber(hasRxBytes, status.m_rxBytes);
      else if (name == "last_handshake_time_sec") readNumber(hasSeconds, seconds);
      else if (name == "last_handshake_time_nsec") readNumber(hasNanos, nanoseconds);
    }
  }
  finishPeer();

  return peerList;
}

bool WireguardUtilsWindows::addInterface(const InterfaceConfig& config) {
  if (m_tunnel.interfaceExists() || m_routeMonitor || m_firewallTouched || !m_firewallPeers.isEmpty()) return false;
  QStringList addresses;
  for (const IPAddress& ip : config.m_allowedIPAddressRanges) {
    addresses.append(ip.toString());
  }

  QMap<QString, QString> extraConfig;
  extraConfig["Table"] = "off";
  QString configString = config.toWgConf(extraConfig);
  if (configString.isEmpty()) {
    logger.error() << "Failed to create a config file";
    return false;
  }

  // We don't want to pass a peer just yet, that will happen later with
  // a UAPI command in WireguardUtilsWindows::updatePeer(), so truncate
  // the config file to remove the [Peer] section.
  qsizetype peerStart = configString.indexOf("[Peer]", 0, Qt::CaseSensitive);
  if (peerStart >= 0) {
    configString.truncate(peerStart);
  }

  if (!m_tunnel.start(configString)) {
    logger.error() << "Failed to activate the tunnel service";
    return false;
  }

  // Determine the interface LUID
  NET_LUID luid;
  QString ifAlias = interfaceName();
  DWORD result = ConvertInterfaceAliasToLuid((wchar_t*)ifAlias.utf16(), &luid);
  if (result != 0) {
    logger.error() << "Failed to lookup LUID:" << result;
    return false;
  }
  m_luid = luid.Value;
  m_routeMonitor = new WindowsRouteMonitor(luid.Value, this);

  if (config.m_killSwitchEnabled) {
    // Enable the windows firewall
    NET_IFINDEX ifindex;
    if (ConvertInterfaceLuidToIndex(&luid, &ifindex) != NO_ERROR) return false;
    m_firewallTouched = true;
    if (!m_firewall->allowAllTraffic() || !m_firewall->enableInterface(ifindex)) return false;
  }

  logger.debug() << "Registration completed";
  return true;
}

bool WireguardUtilsWindows::deleteInterface() {
  // Keep the firewall and cleanup inputs while native stop is unconfirmed.
  if (!m_tunnel.stop()) return false;
  bool success = true;
  if (m_routeMonitor) {
    if (m_routeMonitor->cleanup()) {
      delete m_routeMonitor;
      m_routeMonitor = nullptr;
    } else success = false;
  }
  for (auto i = m_firewallPeers.begin(); i != m_firewallPeers.end();) {
    if (m_firewall->disablePeerTraffic(*i)) i = m_firewallPeers.erase(i);
    else { success = false; ++i; }
  }
  if (m_firewallTouched) {
    if (m_firewall->allowAllTraffic() && m_firewall->disableKillSwitch()) m_firewallTouched = false;
    else success = false;
  }
  if (success) m_luid = 0;
  return success;
}

bool WireguardUtilsWindows::updatePeer(const InterfaceConfig& config) {
  QByteArray publicKey =
      QByteArray::fromBase64(qPrintable(config.m_serverPublicKey));
  QByteArray pskKey =
      QByteArray::fromBase64(qPrintable(config.m_serverPskKey));

  if (config.m_killSwitchEnabled) {
    // Enable the windows firewall for this peer.
    m_firewallPeers.insert(config.m_serverPublicKey);
    if (!m_firewall->enablePeerTraffic(config)) return false;
  }
  logger.debug() << "Configuring peer";

  // Update/create the peer config
  QString message;
  QTextStream out(&message);
  out << "set=1\n";
  out << "public_key=" << QString(publicKey.toHex()) << "\n";
  if (!config.m_serverPskKey.isNull()) {
    out << "preshared_key=" << QString(pskKey.toHex()) << "\n";
  }
  if (!config.m_serverIpv4AddrIn.isNull()) {
    out << "endpoint=" << config.m_serverIpv4AddrIn << ":";
  } else if (!config.m_serverIpv6AddrIn.isNull()) {
    out << "endpoint=[" << config.m_serverIpv6AddrIn << "]:";
  } else {
    logger.warning() << "Failed to create peer with no endpoints";
    return false;
  }
  out << config.m_serverPort << "\n";

  out << "replace_allowed_ips=true\n";
  if (!config.m_persistentKeepalive.isEmpty()) {
    out << "persistent_keepalive_interval=" << config.m_persistentKeepalive << "\n";
  }
  for (const IPAddress& ip : config.m_allowedIPAddressRanges) {
    out << "allowed_ip=" << ip.toString() << "\n";
  }

  // Exclude the server address, except for multihop exit servers.
  if (m_routeMonitor && config.m_hopType != InterfaceConfig::MultiHopExit) {
    for (const QString& endpoint : {config.m_serverIpv4AddrIn, config.m_serverIpv6AddrIn}) {
      const IPAddress prefix(endpoint);
      if (!endpoint.isEmpty() && !m_routeMonitor->hasExclusionRoute(prefix) &&
          !m_routeMonitor->addExclusionRoute(prefix)) return false;
    }
  }

  const QString reply = m_tunnel.uapiCommand(message);
  if (!WindowsTunnelService::setReplySucceeded(reply)) {
    logger.error() << "WireGuard peer configuration was rejected or not acknowledged";
    return false;
  }
  return true;
}

bool WireguardUtilsWindows::deletePeer(const InterfaceConfig& config) {
  QByteArray publicKey =
      QByteArray::fromBase64(qPrintable(config.m_serverPublicKey));

  bool success = true;
  // Clear exclusion routes for this peer.
  if (m_routeMonitor && config.m_hopType != InterfaceConfig::MultiHopExit) {
    success = m_routeMonitor->deleteExclusionRoute(IPAddress(config.m_serverIpv4AddrIn)) && success;
    success = m_routeMonitor->deleteExclusionRoute(IPAddress(config.m_serverIpv6AddrIn)) && success;
  }

  // Disable the windows firewall for this peer.
  if (m_firewall->disablePeerTraffic(config.m_serverPublicKey)) m_firewallPeers.remove(config.m_serverPublicKey);
  else success = false;

  QString message;
  QTextStream out(&message);
  out << "set=1\n";
  out << "public_key=" << QString(publicKey.toHex()) << "\n";
  out << "remove=true\n";

  return WindowsTunnelService::setReplySucceeded(m_tunnel.uapiCommand(message)) && success;
}

void WireguardUtilsWindows::buildMibForwardRow(const IPAddress& prefix,
                                               void* row) {
  MIB_IPFORWARD_ROW2* entry = (MIB_IPFORWARD_ROW2*)row;
  InitializeIpForwardEntry(entry);

  // Populate the next hop
  if (prefix.type() == QAbstractSocket::IPv6Protocol) {
    InetPtonA(AF_INET6, qPrintable(prefix.address().toString()),
              &entry->DestinationPrefix.Prefix.Ipv6.sin6_addr);
    entry->DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
    entry->DestinationPrefix.PrefixLength = prefix.prefixLength();
  } else {
    InetPtonA(AF_INET, qPrintable(prefix.address().toString()),
              &entry->DestinationPrefix.Prefix.Ipv4.sin_addr);
    entry->DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    entry->DestinationPrefix.PrefixLength = prefix.prefixLength();
  }
  entry->InterfaceLuid.Value = m_luid;
  entry->NextHop.si_family = entry->DestinationPrefix.Prefix.si_family;

  // Set the rest of the flags for a static route.
  entry->ValidLifetime = 0xffffffff;
  entry->PreferredLifetime = 0xffffffff;
  entry->Metric = 0;
  entry->Protocol = MIB_IPPROTO_NETMGMT;
  entry->Loopback = false;
  entry->AutoconfigureAddress = false;
  entry->Publish = false;
  entry->Immortal = false;
  entry->Age = 0;
}

bool WireguardUtilsWindows::updateRoutePrefix(const IPAddress& prefix) {
  if (m_routeMonitor && (prefix.prefixLength() == 0)) {
    // If we are setting up a default route, instruct the route monitor to
    // capture traffic to all non-excluded destinations
    m_routeMonitor->setDetaultRouteCapture(true);
  }
  // Build the route
  
  MIB_IPFORWARD_ROW2 entry;
  buildMibForwardRow(prefix, &entry);

  // Install the route
  DWORD result = CreateIpForwardEntry2(&entry);
  if (result == ERROR_OBJECT_ALREADY_EXISTS) {
    return true;
  }

  // Case for ipv6 route with disabled ipv6
  if (prefix.address().protocol() == QAbstractSocket::IPv6Protocol
      && result == ERROR_NOT_FOUND) {
    return true;
  }

  if (result != NO_ERROR) {
    logger.error() << "Failed to create route to"
                   << prefix.toString()
                   << "result:" << result;
  }
  return result == NO_ERROR;
}

bool WireguardUtilsWindows::deleteRoutePrefix(const IPAddress& prefix) {
  if (m_routeMonitor && (prefix.prefixLength() == 0)) {
    // Deactivate the route capture feature.
    m_routeMonitor->setDetaultRouteCapture(false);
  }
  // Build the route
  
  MIB_IPFORWARD_ROW2 entry;
  buildMibForwardRow(prefix, &entry);

  // Install the route
  DWORD result = DeleteIpForwardEntry2(&entry);
  if (result == ERROR_NOT_FOUND) {
    return true;
  }
  if (result != NO_ERROR) {
    logger.error() << "Failed to delete route to"
                   << prefix.toString()
                   << "result:" << result;
  }
  return result == NO_ERROR;
}

bool WireguardUtilsWindows::addExclusionRoute(const IPAddress& prefix) {
  return m_routeMonitor && m_routeMonitor->addExclusionRoute(prefix);
}

bool WireguardUtilsWindows::deleteExclusionRoute(const IPAddress& prefix) {
  return !m_routeMonitor || m_routeMonitor->deleteExclusionRoute(prefix);
}

bool WireguardUtilsWindows::excludeLocalNetworks(
    const QList<IPAddress>& addresses) {
  // If the interface isn't up then something went horribly wrong.
  Q_ASSERT(m_routeMonitor);
  // For each destination - attempt to exclude it from the VPN tunnel.
  bool result = true;
  for (const IPAddress& prefix : addresses) {
    if (!m_routeMonitor->addExclusionRoute(prefix)) {
      result = false;
    }
  }
  // Permit LAN traffic through the firewall.
  if (!m_firewall->enableLanBypass(addresses)) {
    result = false;
  }

  return result;
}
