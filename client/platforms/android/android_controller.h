#include <QHash>
#include <QSet>
#ifndef ANDROID_CONTROLLER_H
#define ANDROID_CONTROLLER_H

#include <QJniObject>
#include <QPixmap>
#include <QStringList>
#include <functional>

#include "core/protocols/vpnProtocol.h"
#include "core/utils/awgTunnelHealth.h"

using namespace amnezia;

class AndroidController : public QObject
{
    Q_OBJECT

public:
    enum class ManagedPermissionResult { Ready = 0, Denied = 1, Unavailable = 2 };
    using ManagedPermissionDone = std::function<void(const QString &, ManagedPermissionResult)>;
    enum UpdateInstallResult { UpdateInstallFailed = 0, UpdateInstallInstallerOpened = 1, UpdateInstallSettingsOpened = 2 };
    explicit AndroidController();
    static AndroidController *instance();

    bool initialize();

    // keep synchronized with org.amnezia.vpn.protocol.ProtocolState
    enum class ConnectionState
    {
        DISCONNECTED,
        CONNECTED,
        CONNECTING,
        DISCONNECTING,
        RECONNECTING,
        UNKNOWN
    };

    ErrorCode start(const QJsonObject &vpnConfig);
    void stop();
    void cancelManaged(const QString& ticket);
    void managedStop(const QString& request, const QString& context, const QString& ticket);
    void managedInspect(const QString& request);
    void managedRecover(const QString& request, const QString& context, const QString& ticket);
    // Adopt the running managed backend (cold start). `expected` becomes the accepted health
    // context and `ticket` the managed ticket only after the service confirms the match.
    void managedAdopt(const QString& request, const AwgHealthContext& expected, const QString& ticket);
    void prepareManagedPermissions(const QString &requestId, ManagedPermissionDone done);
    void cancelManagedPermissionPreparation(const QString &requestId);
    AwgHealthContext expectedAwgHealthContext() const { return m_expectedHealth; }
    // Consumes a pending tile/notification connect request (survives an early emit at startup).
    bool takeConnectRequest() { const bool pending = m_connectRequestPending; m_connectRequestPending = false; return pending; }
    // Called on the owning Qt thread, including JNI deliveries queued from Java.
    void receiveAwgTunnelHealth(const AwgTunnelHealth& health);
    void resetLastServer(int serverIndex);
    void saveFile(const QString &fileName, const QString &data);
    bool saveFile(const QString &fileName, const QByteArray &data, const QString &mime, bool *cancelled = nullptr);
    void shareFile(const QString &path, const QString &mime);
    QString openFile(const QString &filter);
    int getFd(const QString &fileName);
    void closeFd();
    QString getFileName(const QString &uri);
    bool isCameraPresent();
    bool isOnTv();
    bool isEdgeToEdgeEnabled();
    int getStatusBarHeight();
    int getNavigationBarHeight();
    void startQrReaderActivity();
    void setSaveLogs(bool enabled);
    void setScreenshotsEnabled(bool enabled);
    void setNavigationBarColor(unsigned int color);
    void minimizeApp();
    QJsonArray getAppList();
    QPixmap getAppIcon(const QString &package, QSize *size, const QSize &requestedSize);
    bool isNotificationPermissionGranted();
    void requestNotificationPermission();
    bool requestAuthentication();
    int installUpdateApk(const QString &path);
    void sendTouch(float x, float y);
    bool isPlay();
    QJsonObject getSubscriptionPlans();
    QJsonObject purchaseSubscription(const QString &offerToken);
    QJsonObject upgradeSubscription(const QString &offerToken, const QString &oldPurchaseToken);
    QJsonObject acknowledgePurchase(const QString &purchaseToken);
    QJsonObject queryPurchases();

    static bool initLogging();
    static void messageHandler(QtMsgType type, const QMessageLogContext &context, const QString &message);

    static QStringList logFiles(int stream);
    static QString deviceInfo();
    static void clearLogStream(int stream);

signals:
    void connectionStateChanged(Vpn::ConnectionState state);
    void status(ConnectionState state);
    void serviceDisconnected();
    void serviceError();
    void vpnPermissionRejected();
    void notificationStateChanged();
    void vpnStateChanged(ConnectionState state);
    void statisticsUpdated(quint64 rxBytes, quint64 txBytes);
    void awgTunnelHealthUpdated(const AwgTunnelHealth& health);
    void managedStopped(const QString& request, const QString& context, bool stopped);
    void managedInspected(const QString& request, const QString& state, const QString& identity);
    void managedDenied(const QString& ticket, const QString& context);
    void managedRecovered(const QString& request, const QString& context, bool recovered);
    void managedAdopted(const QString& request, const QString& context, bool adopted);
    // The managed session was stopped outside the owner (notification/tile "Disconnect", revoke).
    void managedUserStopped(const QString& context);
    // The service watchdog gave up repairing the current exit (soft replacements did not help):
    // the owner should reconnect, preferring another exit.
    void managedFailoverRequested(const QString& context);
    // Underlying network of the current managed backend: true = new validated default, false = lost.
    void managedNetworkChanged(const QString& context, bool available);
    // The Activity became visible again: was the backend replaced by the service watchdog
    // while the UI was hidden, and is the underlying network available now.
    void managedResumed(const QString& context, bool backendReplaced, bool networkAvailable);
    // Quick-settings tile / notification asked to connect (the app was opened for it).
    void connectRequested();
    void fileOpened(QString uri);
    void fileSaved(bool success, bool cancelled);
    void configImported(QString config);
    void importConfigFromOutside(QString config);
    void initConnectionState(Vpn::ConnectionState state);
    void authenticationResult(bool result);
    void imeInsetsChanged(int heightDp);
    void systemBarsInsetsChanged(int navBarHeightDp, int statusBarHeightDp);
    void activityPaused();
    void activityResumed();

private:
    bool isWaitingStatus = true;
    bool m_connectRequestPending = false;
    ConnectionState m_vpnState = ConnectionState::UNKNOWN;
    AwgHealthContext m_expectedHealth;
    QString m_managedTicket;
    QHash<QString, QString> m_managedStops;
    QSet<QString> m_managedInspections;
    QHash<QString, QString> m_managedRecovers;
    struct PendingAdopt { AwgHealthContext expected; QString ticket; };
    QHash<QString, PendingAdopt> m_managedAdopts;
    QHash<QString, ManagedPermissionDone> m_permissionPreflightCallbacks;

    static jclass log;
    static jmethodID logDebug;
    static jmethodID logInfo;
    static jmethodID logWarning;
    static jmethodID logError;
    static jmethodID logFatal;

    static jclass findLogClass();

    void qtAndroidControllerInitialized();

    static Vpn::ConnectionState convertState(ConnectionState state);
    static QString textConnectionState(ConnectionState state);

    // JNI functions called by Android
    static void onStatus(JNIEnv *env, jobject thiz, jint stateCode);
    static void onServiceDisconnected(JNIEnv *env, jobject thiz);
    static void onServiceError(JNIEnv *env, jobject thiz);
    static void onVpnPermissionRejected(JNIEnv *env, jobject thiz);
    static void onNotificationStateChanged(JNIEnv *env, jobject thiz);
    static void onVpnStateChanged(JNIEnv *env, jobject thiz, jint stateCode);
    static void onStatisticsUpdate(JNIEnv *env, jobject thiz, jlong rxBytes, jlong txBytes);
    static void onAwgTunnelHealth(JNIEnv *env, jobject thiz, jstring snapshotJson);
    static void onManagedLifecycle(JNIEnv *env, jobject thiz, jstring resultJson);
    static void onManagedPermissionPreflightResult(JNIEnv *env, jobject thiz, jstring requestId, jint result);
    static void onConfigImported(JNIEnv *env, jobject thiz, jstring data);
    static void onFileOpened(JNIEnv *env, jobject thiz, jstring uri);
    static void onFileSaved(JNIEnv *env, jobject thiz, jboolean success, jboolean cancelled);
    static void onAuthResult(JNIEnv *env, jobject thiz, jboolean result);
    static bool decodeQrCode(JNIEnv *env, jobject thiz, jstring data);
    static void onImeInsetsChanged(JNIEnv *env, jobject thiz, jint heightDp);
    static void onSystemBarsInsetsChanged(JNIEnv *env, jobject thiz, jint navBarHeightDp, jint statusBarHeightDp);
    static void onActivityPaused(JNIEnv *env, jobject thiz);
    static void onActivityResumed(JNIEnv *env, jobject thiz);

    template <typename Ret, typename ...Args>
    static auto callActivityMethod(const char *methodName, const char *signature, Args &&...args);
    template <typename ...Args>
    static void callActivityMethod(const char *methodName, const char *signature, Args &&...args);
};

#endif // ANDROID_CONTROLLER_H
