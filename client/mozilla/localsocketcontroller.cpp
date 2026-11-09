/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#include "localsocketcontroller.h"

#include <stdint.h>

#include <QCoreApplication>
#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLocalSocket>
#include <QObject>
#include <QStandardPaths>
#include <QStringList>
#include <QTimer>
#include <QUuid>
#include <QPointer>

#include "leakdetector.h"
#include "logger.h"
#include "daemon/daemonerrors.h"

#include "core/utils/protocolEnum.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"

// How many times do we try to reconnect.
constexpr int MAX_CONNECTION_RETRY = 10;

// How long do we wait between one try and the next one.
constexpr int CONNECTION_RETRY_TIMER_MSEC = 500;

namespace {
Logger logger("LocalSocketController");
}

LocalSocketController::LocalSocketController() {
  MZ_COUNT_CTOR(LocalSocketController);

  m_socket = new QLocalSocket(this);
  connect(m_socket, &QLocalSocket::connected, this,
          &LocalSocketController::daemonConnected);
  connect(m_socket, &QLocalSocket::disconnected, this,
          [&] { errorOccurred(QLocalSocket::PeerClosedError); });
  connect(m_socket, &QLocalSocket::errorOccurred, this,
          &LocalSocketController::errorOccurred);
  connect(m_socket, &QLocalSocket::readyRead, this,
          &LocalSocketController::readData);

  m_initializingTimer.setSingleShot(true);
  connect(&m_initializingTimer, &QTimer::timeout, this,
          &LocalSocketController::initializeInternal);
}

LocalSocketController::~LocalSocketController() {
  MZ_COUNT_DTOR(LocalSocketController);
}

void LocalSocketController::errorOccurred(
    QLocalSocket::LocalSocketError error) {
  logger.error() << "Error occurred:" << error;

  if (m_daemonState == eInitializing) {
    if (m_initializingRetry++ < MAX_CONNECTION_RETRY) {
      m_initializingTimer.start(CONNECTION_RETRY_TIMER_MSEC);
      return;
    }

    const QPointer<LocalSocketController> owner(this);
    const quint64 generation = m_healthGeneration;
    const quint64 requestSerial = m_statusRequestSerial;
    emit initialized(false, false, QDateTime());
    if (!owner || owner->m_healthGeneration != generation ||
        owner->m_statusRequestSerial != requestSerial) return;
  }

  qCritical() << "ControllerError";
  disconnectInternal();
}

void LocalSocketController::disconnectInternal() {
  // We're still eReady as the Deamon is alive
  // and can make a new connection.
  m_daemonState = eReady;
  m_initializingRetry = 0;
  m_initializingTimer.stop();
  ++m_healthGeneration;
  m_healthActive = false;
  m_statusRequestPending = false;
  m_pendingStatusId.clear();
  m_expectedHealth = {};
  emit disconnected();
}

void LocalSocketController::initialize(const Device* device, const Keys* keys) {
  logger.debug() << "Initializing";

  Q_UNUSED(device);
  Q_UNUSED(keys);

  Q_ASSERT(m_daemonState == eUnknown);
  m_initializingRetry = 0;

  initializeInternal();
}

void LocalSocketController::initializeInternal() {
  m_daemonState = eInitializing;

#ifdef MZ_WINDOWS
  QString path = "\\\\.\\pipe\\MayakVpnAwgLifecycleV1";
#else
  QString path = "/var/run/amneziavpn/daemon.socket";
  if (!QFileInfo::exists(path)) {
    path = "/tmp/amneziavpn.socket";
  }
#endif

  logger.debug() << "Connecting to:" << path;
  m_socket->connectToServer(path);
}

void LocalSocketController::daemonConnected() {
  logger.debug() << "Daemon connected";
  Q_ASSERT(m_daemonState == eInitializing);
  checkStatus();
}

void LocalSocketController::activate(const QJsonObject &rawConfig) {
  ++m_healthGeneration;
  m_connectedGeneration = 0;
  m_healthActive = true;
  m_statusRequestPending = false;
  m_pendingStatusId.clear();
  m_expectedHealth = {};
  m_expectedHealth.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
  QString protocolName = rawConfig.value("protocol").toString();

  int splitTunnelType = rawConfig.value("splitTunnelType").toInt();
  QJsonArray splitTunnelSites = rawConfig.value("splitTunnelSites").toArray();

  int appSplitTunnelType = rawConfig.value(amnezia::configKey::appSplitTunnelType).toInt();
  QJsonArray splitTunnelApps = rawConfig.value(amnezia::configKey::splitTunnelApps).toArray();
  QJsonArray allowedDns = rawConfig.value(amnezia::configKey::allowedDnsServers).toArray();

  QJsonObject wgConfig = rawConfig.value(protocolName + "_config_data").toObject();
  m_activePeerPublicKey = wgConfig.value(amnezia::configKey::serverPubKey).toString();
  m_expectedHealth.peerPublicKey = QString::fromLatin1(QByteArray::fromBase64(m_activePeerPublicKey.toLatin1()).toHex());
  m_expectedHealth.endpoint = AwgHealthContext::endpointForHost(
      wgConfig.value(amnezia::configKey::hostName).toString(), wgConfig.value(amnezia::configKey::port).toInt());

  QJsonObject json;
  json.insert("type", "activate");
  json.insert("healthContextId", m_expectedHealth.id);
  //  json.insert("hopindex", QJsonValue((double)hop.m_hopindex));
  json.insert("privateKey", wgConfig.value(amnezia::configKey::clientPrivKey));
  json.insert("deviceIpv4Address", wgConfig.value(amnezia::configKey::clientIp));
  m_deviceIpv4 = wgConfig.value(amnezia::configKey::clientIp).toString();

  // set up IPv6 unique-local-address, ULA, with "fd00::/8" prefix, not globally routable.
  // this will be default IPv6 gateway, OS recognizes that IPv6 link is local and switches to IPv4.
  // Otherwise some OSes (Linux) try IPv6 forever and hang.
  // https://en.wikipedia.org/wiki/Unique_local_address (RFC 4193)
  // https://man7.org/linux/man-pages/man5/gai.conf.5.html

  // simply "dead::1" is globally-routable, don't use it
  json.insert("deviceIpv6Address", "fd58:baa6:dead::1");

  json.insert("serverPublicKey", wgConfig.value(amnezia::configKey::serverPubKey));
  json.insert("serverPskKey", wgConfig.value(amnezia::configKey::pskKey));
  json.insert("serverIpv4AddrIn", wgConfig.value(amnezia::configKey::hostName));
  //  json.insert("serverIpv6AddrIn", QJsonValue(hop.m_server.ipv6AddrIn()));
  json.insert("deviceMTU", wgConfig.value(amnezia::configKey::mtu));

  json.insert("serverPort", wgConfig.value(amnezia::configKey::port).toInt());
  json.insert("serverIpv4Gateway", wgConfig.value(amnezia::configKey::hostName));
  //  json.insert("serverIpv6Gateway", QJsonValue(hop.m_server.ipv6Gateway()));

  if (wgConfig.contains(amnezia::configKey::persistentKeepAlive)) {
    json.insert("persistentKeepalive",
                wgConfig.value(amnezia::configKey::persistentKeepAlive).toString());
  }

  json.insert("primaryDnsServer", rawConfig.value(amnezia::configKey::dns1));

  // We don't use secondary DNS if primary DNS is AmneziaDNS
  if (!rawConfig.value(amnezia::configKey::dns1).toString().
    contains(amnezia::protocols::dns::amneziaDnsIp)) {
    json.insert("secondaryDnsServer", rawConfig.value(amnezia::configKey::dns2));
  }

  QJsonArray jsAllowedIPAddesses;

  QJsonArray plainAllowedIP = wgConfig.value(amnezia::configKey::allowedIps).toArray();
  QJsonArray defaultAllowedIP = { "0.0.0.0/0", "::/0" };

  if (plainAllowedIP != defaultAllowedIP && !plainAllowedIP.isEmpty()) {
    // Use AllowedIP list from WG config because of higher priority
    for (auto v : plainAllowedIP) {
      QString ipRange = v.toString();
      if (ipRange.split('/').size() > 1){
          QJsonObject range;
          range.insert("address", ipRange.split('/')[0]);
          range.insert("range", atoi(ipRange.split('/')[1].toLocal8Bit()));
          range.insert("isIpv6", false);
          jsAllowedIPAddesses.append(range);
      } else {
          QJsonObject range;
          range.insert("address",ipRange);
          range.insert("range", 32);
          range.insert("isIpv6", false);
          jsAllowedIPAddesses.append(range);
      }
    }
  } else {

    // Use APP split tunnel
      if (splitTunnelType == 0 || splitTunnelType == 2) {
          QJsonObject range_ipv4;
          range_ipv4.insert("address", "0.0.0.0");
          range_ipv4.insert("range", 0);
          range_ipv4.insert("isIpv6", false);
          jsAllowedIPAddesses.append(range_ipv4);

          QJsonObject range_ipv6;
          range_ipv6.insert("address", "::");
          range_ipv6.insert("range", 0);
          range_ipv6.insert("isIpv6", true);
          jsAllowedIPAddesses.append(range_ipv6);
      }

      if (splitTunnelType == 1) {
          for (auto v : splitTunnelSites) {
              QString ipRange = v.toString();
              if (ipRange.split('/').size() > 1){
                  QJsonObject range;
                  range.insert("address", ipRange.split('/')[0]);
                  range.insert("range", atoi(ipRange.split('/')[1].toLocal8Bit()));
                  range.insert("isIpv6", false);
                  jsAllowedIPAddesses.append(range);
              } else {
                  QJsonObject range;
                  range.insert("address",ipRange);
                  range.insert("range", 32);
                  range.insert("isIpv6", false);
                  jsAllowedIPAddesses.append(range);
              }
          }
      }
  }

  json.insert("allowedIPAddressRanges", jsAllowedIPAddesses);

  QJsonArray jsExcludedAddresses;
  jsExcludedAddresses.append(wgConfig.value(amnezia::configKey::hostName));
  if (splitTunnelType == 2) {
    for (auto v : splitTunnelSites) {
          QString ipRange = v.toString();
          jsExcludedAddresses.append(ipRange);
      }
  }

  json.insert("excludedAddresses", jsExcludedAddresses);

  json.insert("vpnDisabledApps", splitTunnelApps);

  json.insert("allowedDnsServers", allowedDns);

  json.insert(amnezia::configKey::killSwitchOption, rawConfig.value(amnezia::configKey::killSwitchOption));

  const QStringList awgProtocolKeys = amnezia::configKey::awgProtocolKeys();

  for (const QString &key : awgProtocolKeys) {
    const QJsonValue value = wgConfig.value(key);
    if (value.isString() && !value.toString().isEmpty()) {
      json.insert(key, value);
    }
  }

  write(json);
}

void LocalSocketController::deactivate() {
  ++m_healthGeneration;
  m_connectedGeneration = 0;
  m_healthActive = false;
  m_activePeerPublicKey.clear();
  m_expectedHealth = {};
  m_statusRequestPending = false;
  m_pendingStatusId.clear();
  logger.debug() << "Deactivating";

  if (m_daemonState != eReady) {
    logger.debug() << "No disconnect, controller is not ready";
    emit disconnected();
    return;
  }

  QJsonObject json;
  json.insert("type", "deactivate");
  write(json);
  emit disconnected();
}

void LocalSocketController::flushManagedRequests() {
  for (auto it = m_managedStops.cbegin(); it != m_managedStops.cend(); ++it)
    write(QJsonObject{{"type", "managedDeactivate"}, {"stopRequestId", it.key()}, {"healthContextId", it.value()}});
  for (const auto& request : m_managedInspections)
    write(QJsonObject{{"type", "managedInspect"}, {"inspectRequestId", request}});
}
void LocalSocketController::managedDeactivate(const QString& request, const QString& context) {
  // Do not synthesize disconnected and do not discard transport/context here.
  if (request.size() != 64 || context.isEmpty() || m_managedStops.contains(request)) return;
  m_managedStops.insert(request, context);
  if (m_daemonState != eReady) return; // unknown, caller's bounded timer settles
  QJsonObject json{{"type", "managedDeactivate"}, {"stopRequestId", request}, {"healthContextId", context}};
  write(json);
}
void LocalSocketController::inspectOwnBackend(const QString& request) {
  if (request.size() != 64 || m_managedInspections.contains(request)) return;
  m_managedInspections.insert(request);
  if (m_daemonState != eReady) return;
  write(QJsonObject{{"type", "managedInspect"}, {"inspectRequestId", request}});
}

void LocalSocketController::checkStatus() {
  logger.debug() << "Check status";

  if (m_daemonState == eReady || m_daemonState == eInitializing) {
    Q_ASSERT(m_socket);
    if (m_statusRequestPending) return;
    m_statusRequestPending = true;
    m_pendingStatusGeneration = m_healthGeneration;
    ++m_statusRequestSerial;
    m_pendingStatusId = QUuid::createUuid().toString(QUuid::WithoutBraces);

    QJsonObject json;
    json.insert("type", "status");
    json.insert("statusRequestId", m_pendingStatusId);
    write(json);
  }
}

void LocalSocketController::getBackendLogs(
    std::function<void(const QString&)>&& a_callback) {
  logger.debug() << "Backend logs";

  if (m_logCallback) {
    m_logCallback("");
    m_logCallback = nullptr;
  }

  if (m_daemonState != eReady) {
    std::function<void(const QString&)> callback = a_callback;
    callback("");
    return;
  }

  m_logCallback = std::move(a_callback);

  QJsonObject json;
  json.insert("type", "logs");
  write(json);
}

void LocalSocketController::cleanupBackendLogs() {
  logger.debug() << "Cleanup logs";

  if (m_logCallback) {
    m_logCallback("");
    m_logCallback = nullptr;
  }

  if (m_daemonState != eReady) {
    return;
  }

  QJsonObject json;
  json.insert("type", "cleanlogs");
  write(json);
}

void LocalSocketController::readData() {
  logger.debug() << "Reading";

  Q_ASSERT(m_socket);
  Q_ASSERT(m_daemonState == eInitializing || m_daemonState == eReady);
  QByteArray input = m_socket->readAll();
  m_buffer.append(input);

  while (true) {
    int pos = m_buffer.indexOf("\n");
    if (pos == -1) {
      break;
    }

    QByteArray line = m_buffer.left(pos);
    m_buffer.remove(0, pos + 1);

    QByteArray command(line);
    command = command.trimmed();

    if (command.isEmpty()) {
      continue;
    }

    const QPointer<LocalSocketController> owner(this);
    const quint64 generation = m_healthGeneration;
    const quint64 requestSerial = m_statusRequestSerial;
    parseCommand(command);
    // Direct signal receivers can delete or replace the controller while parsing.
    if (!owner || owner->m_healthGeneration != generation ||
        owner->m_statusRequestSerial != requestSerial) return;
  }
}

void LocalSocketController::parseCommand(const QByteArray& command) {
  QJsonDocument json = QJsonDocument::fromJson(command);
  if (!json.isObject()) {
    logger.error() << "Invalid JSON - object expected";
    return;
  }

  QJsonObject obj = json.object();
  QJsonValue typeValue = obj.value("type");
  if (!typeValue.isString()) {
    logger.error() << "Invalid JSON - no type";
    return;
  }
  QString type = typeValue.toString();

  logger.debug() << "Parse command:" << type;

  if (type == "managedStopped") {
    const QString request = obj.value("stopRequestId").toString();
    const QString context = obj.value("healthContextId").toString();
    if (obj.value("owner").toString() != "MayakVpnAwgLifecycleV1" ||
        !obj.value("stopped").isBool() || !m_managedStops.contains(request) ||
        m_managedStops.value(request) != context) return;
    m_managedStops.remove(request);
    const bool stopped = obj.value("stopped").toBool();
    if (stopped && m_expectedHealth.id == context) {
      ++m_healthGeneration;
      m_healthActive = false;
      m_expectedHealth = {};
      m_statusRequestPending = false;
      m_pendingStatusId.clear();
    }
    emit managedStopped(request, context, stopped);
    return;
  }
  if (type == "managedInspection") {
    const QString request = obj.value("inspectRequestId").toString();
    if (obj.value("owner").toString() != "MayakVpnAwgLifecycleV1" || !m_managedInspections.remove(request)) return;
    const QString state = obj.value("state").toString();
    const QString identity = obj.value("controlIdentity").toString();
    if ((state != "active" && state != "off" && state != "unknown") || (state == "active" && identity.isEmpty())) {
      emit managedInspected(request, QStringLiteral("unknown"), QString()); return;
    }
    emit managedInspected(request, state, identity);
    return;
  }

  if (type == "status") {
    // A duplicate/old/unsolicited response must not consume a newer pending request.
    if (!m_statusRequestPending || m_pendingStatusId.isEmpty() ||
        obj.value("statusRequestId").toString() != m_pendingStatusId) return;
    const quint64 requestGeneration = m_pendingStatusGeneration;
    m_statusRequestPending = false;
    m_pendingStatusId.clear();
    if (requestGeneration != m_healthGeneration) return;
    if (m_daemonState != eReady && m_daemonState != eInitializing) return;
    if (!obj.value("connected").isBool()) return;

    QJsonObject healthJson = obj;
    healthJson.insert("valid", obj.value("healthValid").toBool());
    const AwgTunnelHealth health = AwgTunnelHealth::fromJson(healthJson);
    const bool current = m_healthActive && m_expectedHealth.matches(health);
    const QPointer<LocalSocketController> owner(this);
    const quint64 requestSerial = m_statusRequestSerial;
    // Every outgoing signal invokes foreign code synchronously. Never resume an
    // older dispatch after deletion, stop/restart, or a newer status request.
    const auto canContinue = [owner, requestGeneration, requestSerial, &health] {
      return owner && owner->m_healthGeneration == requestGeneration &&
          owner->m_statusRequestSerial == requestSerial && owner->m_daemonState == eReady &&
          owner->m_healthActive && owner->m_expectedHealth.matches(health);
    };
    // Initialization uses exactly the same identity gate as normal polling.
    if (m_daemonState == eInitializing) {
      m_daemonState = eReady;
      flushManagedRequests();
      const bool connected = current && health.hasConfirmedHandshake();
      emit initialized(true, connected, connected
          ? QDateTime::fromMSecsSinceEpoch(health.latestHandshakeEpochMs) : QDateTime());
      if (!current || !canContinue()) return;
      emit awgTunnelHealthUpdated(health);
      if (!canContinue()) return;
      if (connected) m_connectedGeneration = requestGeneration;
      return;
    }
    if (current) {
      emit awgTunnelHealthUpdated(health);
      if (!canContinue()) return;
      if (health.hasConfirmedHandshake() && m_connectedGeneration != requestGeneration) {
        m_connectedGeneration = requestGeneration;
        emit connected(m_activePeerPublicKey,
                       QDateTime::fromMSecsSinceEpoch(health.latestHandshakeEpochMs));
        if (!canContinue()) return;
      }
    }

    QJsonValue serverIpv4Gateway = obj.value("serverIpv4Gateway");
    if (!serverIpv4Gateway.isString()) {
      logger.error() << "Unexpected serverIpv4Gateway value";
      return;
    }

    QJsonValue deviceIpv4Address = obj.value("deviceIpv4Address");
    if (!deviceIpv4Address.isString()) {
      logger.error() << "Unexpected deviceIpv4Address value";
      return;
    }

    QJsonValue txBytes = obj.value("txBytes");
    if (!txBytes.isDouble()) {
      logger.error() << "Unexpected txBytes value";
      return;
    }

    QJsonValue rxBytes = obj.value("rxBytes");
    if (!rxBytes.isDouble()) {
      logger.error() << "Unexpected rxBytes value";
      return;
    }

    emit statusUpdated(serverIpv4Gateway.toString(),
                       deviceIpv4Address.toString(), txBytes.toDouble(),
                       rxBytes.toDouble());

    return;
  }

  if (type == "disconnected") {
    if (!m_managedStops.isEmpty()) return; // legacy event is never a managed ACK
    disconnectInternal();
    return;
  }

  if (type == "connected") {
    QJsonValue pubkey = obj.value("pubkey");
    if (!pubkey.isString()) {
      logger.error() << "Unexpected pubkey value";
      return;
    }

    if (!m_healthActive || m_activePeerPublicKey.isEmpty() ||
        pubkey.toString().compare(m_activePeerPublicKey, Qt::CaseInsensitive) != 0) {
      return;
    }

    logger.debug() << "Handshake completed with:"
                   << pubkey.toString();

    checkStatus();

    emit statusUpdated("", m_deviceIpv4, 0, 0);

    return;
  }

  if (type == "backendFailure") {
    if (!obj.contains("errorCode")) {
      // report a generic error if we dont know what it is.
      logger.error() << "generic backend failure error";
      // REPORTERROR(ErrorHandler::ControllerError, "controller");
      return;
    }
    auto errorCode = static_cast<uint8_t>(obj["errorCode"].toInt());
    if (errorCode >= (uint8_t)DaemonError::DAEMON_ERROR_MAX) {
      // Also report a generic error if the code is invalid.
      logger.error() << "invalid backend failure error code";
      // REPORTERROR(ErrorHandler::ControllerError, "controller");
      return;
    }
    switch (static_cast<DaemonError>(errorCode)) {
      case DaemonError::ERROR_NONE:
        [[fallthrough]];
      case DaemonError::ERROR_FATAL:
        logger.error() << "generic backend failure error (fatal or error none)";
        // REPORTERROR(ErrorHandler::ControllerError, "controller");
        break;
      case DaemonError::ERROR_SPLIT_TUNNEL_INIT_FAILURE:
        [[fallthrough]];
      case DaemonError::ERROR_SPLIT_TUNNEL_START_FAILURE:
        [[fallthrough]];
      case DaemonError::ERROR_SPLIT_TUNNEL_EXCLUDE_FAILURE:
        logger.error() << "split tunnel backend failure error";
        //REPORTERROR(ErrorHandler::SplitTunnelError, "controller");
        break;
      case DaemonError::DAEMON_ERROR_MAX:
        // We should not get here.
        Q_ASSERT(false);
        break;
    }
  }

  if (type == "logs") {
    // We don't care if we are not waiting for logs.
    if (!m_logCallback) {
      return;
    }

    QJsonValue logs = obj.value("logs");
    m_logCallback(logs.isString() ? logs.toString().replace("|", "\n")
                                  : QString());
    m_logCallback = nullptr;
    return;
  }

  logger.warning() << "Invalid command received:" << command;
}

void LocalSocketController::write(const QJsonObject& json) {
  Q_ASSERT(m_socket);
  m_socket->write(QJsonDocument(json).toJson(QJsonDocument::Compact));
  m_socket->write("\n");
  m_socket->flush();
}
