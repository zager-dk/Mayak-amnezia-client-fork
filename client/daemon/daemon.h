/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef DAEMON_H
#define DAEMON_H

#include <QDateTime>
#include <QTimer>
#ifdef Q_OS_WINDOWS
#include <optional>
#endif

#include "daemon/daemonerrors.h"
#include "daemonerrors.h"
#include "dnsutils.h"
#include "interfaceconfig.h"
#include "iputils.h"
#include "wireguardutils.h"

class Daemon : public QObject {
  Q_OBJECT

 public:
  enum Op {
    Up,
    Down,
    Switch,
  };

  explicit Daemon(QObject* parent);
  ~Daemon();

  static Daemon* instance();

  static bool parseConfig(const QJsonObject& obj, InterfaceConfig& config);

  virtual bool activate(const InterfaceConfig& config);
  // Only commit the supplied context after actual backend activation succeeds.
  bool activateWithHealthContext(const InterfaceConfig& config, const QString& contextId);
  QString activeHealthContextId() const { return m_healthContextId; }
  virtual bool deactivate(bool emitSignals = true);
  bool managedDeactivate(const QString& controlIdentity);
  QJsonObject managedInspection();
  virtual QJsonObject getStatus();
  // Mayak: make app exclusions usable before a connect ("ok" or a reason). Only Windows needs it.
  virtual QString mayakPrepareSplitTunnel() { return QStringLiteral("ok"); }

  // Callback before any Activating measure is done
  virtual void prepareActivation(const InterfaceConfig& config, int inetAdapterIndex = 0) {
      Q_UNUSED(config)  };
  virtual void activateSplitTunnel(const InterfaceConfig& config, int vpnAdapterIndex = 0) {
      Q_UNUSED(config)  };

  QString logs();
  void cleanLogs();

 signals:
  void connected(const QString& pubkey);
  /**
   * Can be fired if a call to activate() was unsucessfull
   * and connected systems should rollback
   */
  void activationFailure();
  void disconnected();
  void backendFailure(DaemonError reason = DaemonError::ERROR_FATAL);

 private:
  bool maybeUpdateResolvers(const InterfaceConfig& config);
#ifdef Q_OS_WINDOWS
  bool cleanupWindowsManagedActivation();
#endif
  bool addExclusionRoute(const IPAddress& address);
  bool delExclusionRoute(const IPAddress& address);

 protected:
  virtual bool run(Op op, const InterfaceConfig& config) {
    Q_UNUSED(op);
    Q_UNUSED(config);
    return true;
  }
  virtual bool supportServerSwitching(const InterfaceConfig& config) const;
  virtual bool switchServer(const InterfaceConfig& config);
  virtual WireguardUtils* wgutils() const = 0;
  virtual bool supportIPUtils() const { return false; }
  virtual IPUtils* iputils() { return nullptr; }
  virtual DnsUtils* dnsutils() { return nullptr; }

  static bool parseStringList(const QJsonObject& obj, const QString& name,
                              QStringList& list);

  void checkHandshake();

  class ConnectionState {
   public:
    ConnectionState(){};
    ConnectionState(const InterfaceConfig& config) { m_config = config; }
    QDateTime m_date;
    InterfaceConfig m_config;
  };
  QMap<InterfaceConfig::HopType, ConnectionState> m_connections;
  QHash<IPAddress, int> m_excludedAddrSet;
  QTimer m_handshakeTimer;
#ifdef Q_OS_WINDOWS
  bool m_windowsManagedActivation = false;
  std::optional<InterfaceConfig> m_windowsCleanupConfig;
  bool m_windowsInterfaceAttempted = false;
  bool m_windowsDnsAttempted = false;
  bool m_windowsUpAttempted = false;
  QString m_windowsLastStoppedIdentity;
#endif
  QString m_healthContextId;
  QString m_controlIdentity;
  bool m_teardownUncertain = false;
  quint64 m_healthGeneration = 0;
  InterfaceConfig::HopType m_healthHopType = InterfaceConfig::SingleHop;
};

#endif  // DAEMON_H
