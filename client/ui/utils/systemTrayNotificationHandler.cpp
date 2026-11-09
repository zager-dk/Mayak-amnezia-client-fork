/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <QDebug>
#include "systemTrayNotificationHandler.h"


#ifdef Q_OS_MAC
#  include "platforms/macos/macosstatusicon.h"
#endif

#include <QApplication>
#include <QDesktopServices>
#include <QIcon>
#include <QSettings>
#include <QStyleHints>
#include <QWindow>

#include "version.h"

SystemTrayNotificationHandler::SystemTrayNotificationHandler(QObject* parent) :
    NotificationHandler(parent)
#ifndef Q_OS_MAC
    , m_systemTrayIcon(parent)
#endif
{
    m_trayActionShow =  m_menu.addAction(QIcon(":/images/tray/application.png"), tr("Show") + " " + APPLICATION_NAME, this, [this](){
        emit raiseRequested();
    });
    m_menu.addSeparator();
    m_trayActionConnect = m_menu.addAction(tr("Connect"), this, [this](){ emit connectRequested(); });
    m_trayActionDisconnect = m_menu.addAction(tr("Disconnect"), this, [this](){ emit disconnectRequested(); });

    m_menu.addSeparator();

    m_trayActionVisitWebSite = m_menu.addAction(QIcon(":/images/tray/link.png"), tr("Visit Website"), [&](){
        QDesktopServices::openUrl(QUrl(websiteUrl));
    });

    // Quit action: disconnect VPN first on macOS NE, else quit directly
    m_trayActionQuit = m_menu.addAction(QIcon(":/images/tray/cancel.png"),
                                       tr("Quit") + " " + APPLICATION_NAME,
                                       this,
                                       [&](){ qApp->quit(); });

#ifdef Q_OS_MAC
    // QSystemTrayIcon::setContextMenu crashes on macOS 14+: its menu-tracking
    // observer reads -[NSEvent clickCount] off a non-mouse event. Own the
    // NSStatusItem and attach the native NSMenu instead.
    m_statusIcon = new MacOSStatusIcon(this);
    m_statusIcon->setMenu(&m_menu);
#else
    m_systemTrayIcon.show();
    connect(&m_systemTrayIcon, &QSystemTrayIcon::activated, this,
            &SystemTrayNotificationHandler::onTrayActivated);
    m_systemTrayIcon.setContextMenu(&m_menu);
    // Re-pick the light/dark tray variant when the system theme changes.
    connect(QGuiApplication::styleHints(), &QStyleHints::colorSchemeChanged, this,
            [this](Qt::ColorScheme) { setMayakTrayIcon(m_trayIconState); });
#endif
    setTrayState(Vpn::ConnectionState::Disconnected);
}

bool SystemTrayNotificationHandler::taskbarUsesLightTheme()
{
#ifdef Q_OS_WIN
    // The taskbar follows the "system" (not app) theme; read-only registry lookup.
    const QSettings personalize(QStringLiteral("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize"),
                                QSettings::NativeFormat);
    return personalize.value(QStringLiteral("SystemUsesLightTheme"), 0).toInt() == 1;
#else
    return false;
#endif
}

void SystemTrayNotificationHandler::setMayakTrayIcon(const QString &state)
{
    m_trayIconState = state;
#ifdef Q_OS_MAC
    // macOS status item: template image (dark silhouette, system tints it).
    setTrayIcon(QStringLiteral(":/images/tray/mayak/%1-light-32.png").arg(state));
#else
    const QString theme = taskbarUsesLightTheme() ? QStringLiteral("light") : QStringLiteral("dark");
    QIcon icon;
    for (const int size : {16, 20, 24, 32, 40, 48})
        icon.addFile(QStringLiteral(":/images/tray/mayak/%1-%2-%3.png").arg(state, theme).arg(size), QSize(size, size));
    m_systemTrayIcon.setIcon(icon);
#endif
}

SystemTrayNotificationHandler::~SystemTrayNotificationHandler() {
#ifdef Q_OS_MAC
    delete m_statusIcon;  // before m_menu: the status item references its NSMenu
    m_statusIcon = nullptr;
#endif
}

void SystemTrayNotificationHandler::setConnectionState(Vpn::ConnectionState state)
{
    setTrayState(state);
    NotificationHandler::setConnectionState(state);
}

void SystemTrayNotificationHandler::onTranslationsUpdated()
{
    m_trayActionShow->setText(tr("Show") + " " + APPLICATION_NAME);
    m_trayActionConnect->setText(tr("Connect"));
    m_trayActionDisconnect->setText(tr("Disconnect"));
    m_trayActionVisitWebSite->setText(tr("Visit Website"));
    m_trayActionQuit->setText(tr("Quit")+ " " + APPLICATION_NAME);
}

void SystemTrayNotificationHandler::updateWebsiteUrl(const QString &newWebsiteUrl) {
    qDebug() << "Updated website URL:" << newWebsiteUrl;
    websiteUrl = newWebsiteUrl;
}

void SystemTrayNotificationHandler::setTrayIcon(const QString &iconPath)
{
#ifdef Q_OS_MAC
    m_statusIcon->setIcon(iconPath);
#else
    QIcon trayIconMask(QPixmap(iconPath).scaled(128,128));
    trayIconMask.setIsMask(true);
    m_systemTrayIcon.setIcon(trayIconMask);
#endif
}

void SystemTrayNotificationHandler::onTrayActivated(QSystemTrayIcon::ActivationReason reason)
{
    if(reason == QSystemTrayIcon::DoubleClick || reason == QSystemTrayIcon::Trigger) {
        emit raiseRequested();
    }
}

void SystemTrayNotificationHandler::setTrayState(Vpn::ConnectionState state)
{
    // Mayak: "on" only for a confirmed tunnel; every transition shows "connecting".
    switch (state) {
    case Vpn::ConnectionState::Disconnected:
        setMayakTrayIcon(QStringLiteral("off"));
        m_trayActionConnect->setEnabled(true);
        m_trayActionDisconnect->setEnabled(false);
        break;
    case Vpn::ConnectionState::Preparing:
    case Vpn::ConnectionState::Connecting:
    case Vpn::ConnectionState::Disconnecting:
    case Vpn::ConnectionState::Reconnecting:
        setMayakTrayIcon(QStringLiteral("connecting"));
        m_trayActionConnect->setEnabled(false);
        m_trayActionDisconnect->setEnabled(true);
        break;
    case Vpn::ConnectionState::Connected:
        setMayakTrayIcon(QStringLiteral("on"));
        m_trayActionConnect->setEnabled(false);
        m_trayActionDisconnect->setEnabled(true);
        break;
    case Vpn::ConnectionState::Error:
        setMayakTrayIcon(QStringLiteral("error"));
        m_trayActionConnect->setEnabled(true);
        m_trayActionDisconnect->setEnabled(false);
        break;
    case Vpn::ConnectionState::Unknown:
    default:
        m_trayActionConnect->setEnabled(false);
        m_trayActionDisconnect->setEnabled(true);
        setMayakTrayIcon(QStringLiteral("off"));
    }

    //#ifdef Q_OS_MAC
    //    // Get theme from current user (note, this app can be launched as root application and in this case this theme can be different from theme of real current user )
    //    bool darkTaskBar = MacOSFunctions::instance().isMenuBarUseDarkTheme();
    //    darkTaskBar = forceUseBrightIcons ? true : darkTaskBar;
    //    resourcesPath = ":/images_mac/tray_icon/%1";
    //    useIconName = useIconName.replace(".png", darkTaskBar ? "@2x.png" : " dark@2x.png");
    //#endif
}


void SystemTrayNotificationHandler::notify(NotificationHandler::Message type,
                                           const QString& title,
                                           const QString& message,
                                           int timerMsec) {
  Q_UNUSED(type);

#ifdef Q_OS_MAC
  Q_UNUSED(timerMsec);
  m_statusIcon->showMessage(title, message);
#else
  m_systemTrayIcon.showMessage(title, message, m_systemTrayIcon.icon(), timerMsec);
#endif
}

void SystemTrayNotificationHandler::showHideWindow() {
//  QmlEngineHolder* engine = QmlEngineHolder::instance();
//  if (engine->window()->isVisible()) {
//    engine->hideWindow();
//#ifdef MVPN_MACOS
//    MacOSUtils::hideDockIcon();
//#endif
//  } else {
//    engine->showWindow();
//#ifdef MVPN_MACOS
//    MacOSUtils::showDockIcon();
//#endif
//  }
}

