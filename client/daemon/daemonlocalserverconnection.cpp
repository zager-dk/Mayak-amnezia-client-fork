/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "daemonlocalserverconnection.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLocalSocket>

#include "daemon.h"
#include "leakdetector.h"
#include "logger.h"

#if defined(MZ_WINDOWS)
#  include "platforms/windows/daemon/mayakforeignvpnstop.h"
#endif

namespace {
Logger logger("DaemonLocalServerConnection");
}

DaemonLocalServerConnection::DaemonLocalServerConnection(QObject* parent,
                                                         QLocalSocket* socket)
    : QObject(parent) {
  MZ_COUNT_CTOR(DaemonLocalServerConnection);

  logger.debug() << "Connection created";

  Q_ASSERT(socket);
  m_socket = socket;

  connect(m_socket, &QLocalSocket::readyRead, this,
          &DaemonLocalServerConnection::readData);

  Daemon* daemon = Daemon::instance();
  connect(daemon, &Daemon::connected, this,
          &DaemonLocalServerConnection::connected);
  connect(daemon, &Daemon::disconnected, this,
          &DaemonLocalServerConnection::disconnected);
  connect(daemon, &Daemon::backendFailure, this,
          &DaemonLocalServerConnection::backendFailure);
}

DaemonLocalServerConnection::~DaemonLocalServerConnection() {
  MZ_COUNT_DTOR(DaemonLocalServerConnection);

  logger.debug() << "Connection released";
}

void DaemonLocalServerConnection::readData() {
  logger.debug() << "Read Data";

  Q_ASSERT(m_socket);

  while (true) {
    int pos = m_buffer.indexOf("\n");
    if (pos == -1) {
      QByteArray input = m_socket->readAll();
      if (input.isEmpty()) {
        break;
      }
      m_buffer.append(input);
      continue;
    }

    QByteArray line = m_buffer.left(pos);
    m_buffer.remove(0, pos + 1);

    QByteArray command(line);
    command = command.trimmed();

    if (command.isEmpty()) {
      continue;
    }

    parseCommand(command);
  }
}

void DaemonLocalServerConnection::parseCommand(const QByteArray& data) {
  QJsonDocument json = QJsonDocument::fromJson(data);
  if (!json.isObject()) {
    logger.error() << "Invalid input";
    return;
  }

  QJsonObject obj = json.object();
  QJsonValue typeValue = obj.value("type");
  if (!typeValue.isString()) {
    logger.warning() << "No type command. Ignoring request.";
    return;
  }
  QString type = typeValue.toString();

  logger.debug() << "Command received:" << type;

  // It is expected that sometimes the client will request backend logs
  // before the first authentication. In these cases we just return empty
  // logs.
  if (type == "logs") {
    QJsonObject obj;
    obj.insert("type", "logs");
    obj.insert("logs", "");
    write(obj);
    return;
  }

  if (type == "activate") {
    InterfaceConfig config;
    if (!Daemon::parseConfig(obj, config)) {
      logger.error() << "Invalid configuration";
      emit disconnected();
      return;
    }

    if (!Daemon::instance()->activateWithHealthContext(config, obj.value("healthContextId").toString())) {
      logger.error() << "Failed to activate the interface";
      emit disconnected();
    }
    return;
  }

  if (type == "managedDeactivate") {
    const QString request = obj.value("stopRequestId").toString();
    const QString context = obj.value("healthContextId").toString();
    if (request.size() != 64 || context.isEmpty()) return;
    const bool stopped = Daemon::instance()->managedDeactivate(context);
    write(QJsonObject{{"type", "managedStopped"}, {"owner", "MayakVpnAwgLifecycleV1"},
        {"stopRequestId", request}, {"healthContextId", context}, {"stopped", stopped}});
    return;
  }
  if (type == "managedInspect") {
    const QString request = obj.value("inspectRequestId").toString();
    if (request.size() != 64) return;
    auto result = Daemon::instance()->managedInspection();
    result.insert("type", "managedInspection");
    result.insert("owner", "MayakVpnAwgLifecycleV1");
    result.insert("inspectRequestId", request);
    write(result);
    return;
  }

#if defined(MZ_WINDOWS)
  // Mayak: the user pressed "turn off Browsec" in the app. Only fixed, known cores are ended.
  if (type == "mayakStopForeignVpn") {
    const QString request = obj.value("requestId").toString();
    if (request.size() != 64) return;
    const int stopped = MayakForeignVpnStop::stopKnownCores();
    write(QJsonObject{{"type", "mayakForeignVpnStopped"}, {"owner", "MayakVpnAwgLifecycleV1"},
        {"requestId", request}, {"stopped", stopped}});
    return;
  }
  // Mayak: prepare app exclusions before a connect (may take seconds: AmneziaVPN's copy of the split tunnel
  // driver is released for Mayak when it holds the device and runs no VPN).
  if (type == "mayakPrepareSplitTunnel") {
    const QString request = obj.value("requestId").toString();
    if (request.size() != 64) return;
    const QString result = Daemon::instance()->mayakPrepareSplitTunnel();
    write(QJsonObject{{"type", "mayakSplitTunnelPrepared"}, {"owner", "MayakVpnAwgLifecycleV1"},
        {"requestId", request}, {"result", result}});
    return;
  }
  // Mayak: the app found its own Xray tunnel left by an ended app process. Ends only tun2socks
  // started from this installation's tun2socks.exe.
  if (type == "mayakStopXrayLeftover") {
    const QString request = obj.value("requestId").toString();
    if (request.size() != 64) return;
    const int stopped = MayakForeignVpnStop::stopOwnTun2Socks();
    write(QJsonObject{{"type", "mayakXrayLeftoverStopped"}, {"owner", "MayakVpnAwgLifecycleV1"},
        {"requestId", request}, {"stopped", stopped}});
    return;
  }
#endif

  if (type == "deactivate") {
    Daemon::instance()->deactivate(true);
    return;
  }

  if (type == "status") {
    QJsonObject status = Daemon::instance()->getStatus();
    status.insert("type", "status");
    status.insert("statusRequestId", obj.value("statusRequestId"));
    write(status);
    return;
  }

  if (type == "logs") {
    QJsonObject obj;
    obj.insert("type", "logs");
    obj.insert("logs", Daemon::instance()->logs().replace("\n", "|"));
    write(obj);
    return;
  }

  if (type == "cleanlogs") {
    Daemon::instance()->cleanLogs();
    return;
  }

  logger.warning() << "Invalid command:" << type;
}

void DaemonLocalServerConnection::connected(const QString& pubkey) {
  QJsonObject obj;
  obj.insert("type", "connected");
  obj.insert("pubkey", QJsonValue(pubkey));
  write(obj);
}

void DaemonLocalServerConnection::disconnected() {
  QJsonObject obj;
  obj.insert("type", "disconnected");
  write(obj);
}

void DaemonLocalServerConnection::backendFailure(DaemonError err) {
  QJsonObject obj;
  obj.insert("type", "backendFailure");
  obj.insert("errorCode", static_cast<int>(err));
  write(obj);
}

void DaemonLocalServerConnection::write(const QJsonObject& obj) {
  m_socket->write(QJsonDocument(obj).toJson(QJsonDocument::Compact));
  m_socket->write("\n");
}
