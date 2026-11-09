#include <QJniEnvironment>
#include <QJsonDocument>
#include <QQmlFile>
#include <QEventLoop>
#include <QImage>
#include <QUuid>
#include <QThread>
#include <QCoreApplication>
#include <QDeadlineTimer>
#include <QHostAddress>

#include <android/bitmap.h>

#include "android_controller.h"
#include "android_utils.h"
#include "ui/controllers/importUiController.h"

namespace
{
    AndroidController *s_instance = nullptr;

    constexpr auto QT_ANDROID_CONTROLLER_CLASS = "org/amnezia/vpn/qt/QtAndroidController";
    constexpr auto ANDROID_LOG_CLASS = "org/amnezia/vpn/util/Log";
    constexpr auto TAG = "AmneziaQt";
} // namespace

AndroidController::AndroidController() : QObject()
{
    connect(this, &AndroidController::status, this,
            [this](AndroidController::ConnectionState state) {
                m_vpnState = state;
                qDebug() << "Android event: status =" << textConnectionState(state);
                if (isWaitingStatus) {
                    qDebug() << "Initialization by service status";
                    isWaitingStatus = false;
                    emit initConnectionState(convertState(state));
                }
            },
            Qt::QueuedConnection);

    connect(
        this, &AndroidController::serviceDisconnected, this,
        [this]() {
            qDebug() << "Android event: service disconnected";
            isWaitingStatus = true;
            m_expectedHealth = {};
            emit connectionStateChanged(Vpn::ConnectionState::Disconnected);
        },
        Qt::QueuedConnection);

    connect(
        this, &AndroidController::serviceError, this,
        [this]() {
            qDebug() << "Android event: service error";
            // todo: add error message
            m_expectedHealth = {};
            emit connectionStateChanged(Vpn::ConnectionState::Error);
        },
        Qt::QueuedConnection);

    connect(
        this, &AndroidController::vpnPermissionRejected, this,
        [this]() {
            qWarning() << "Android event: VPN permission rejected";
            m_expectedHealth = {};
            emit connectionStateChanged(Vpn::ConnectionState::Disconnected);
        },
        Qt::QueuedConnection);

    connect(
        this, &AndroidController::vpnStateChanged, this,
        [this](AndroidController::ConnectionState state) {
            m_vpnState = state;
            if (state == ConnectionState::DISCONNECTED || state == ConnectionState::DISCONNECTING ||
                state == ConnectionState::RECONNECTING || state == ConnectionState::UNKNOWN) m_expectedHealth = {};
            qDebug() << "Android event: VPN state changed:" << textConnectionState(state);
            emit connectionStateChanged(convertState(state));
        },
        Qt::QueuedConnection);

    connect(
        this, &AndroidController::configImported, this,
        [this](const QString& config) {
            qDebug() << "Android event: config import";
            emit importConfigFromOutside(config);
        },
        Qt::QueuedConnection);
}

AndroidController *AndroidController::instance()
{
    if (!s_instance) {
        s_instance = new AndroidController();
    }

    return s_instance;
}

bool AndroidController::initialize()
{
    qDebug() << "Initialize AndroidController";

    const JNINativeMethod methods[] = {
        {"onStatus", "(I)V", reinterpret_cast<void *>(onStatus)},
        {"onServiceDisconnected", "()V", reinterpret_cast<void *>(onServiceDisconnected)},
        {"onServiceError", "()V", reinterpret_cast<void *>(onServiceError)},
        {"onVpnPermissionRejected", "()V", reinterpret_cast<void *>(onVpnPermissionRejected)},
        {"onNotificationStateChanged", "()V", reinterpret_cast<void *>(onNotificationStateChanged)},
        {"onVpnStateChanged", "(I)V", reinterpret_cast<void *>(onVpnStateChanged)},
        {"onStatisticsUpdate", "(JJ)V", reinterpret_cast<void *>(onStatisticsUpdate)},
        {"onAwgTunnelHealth", "(Ljava/lang/String;)V", reinterpret_cast<void *>(onAwgTunnelHealth)},
        {"onManagedLifecycle", "(Ljava/lang/String;)V", reinterpret_cast<void *>(onManagedLifecycle)},
        {"onManagedPermissionPreflightResult", "(Ljava/lang/String;I)V", reinterpret_cast<void *>(onManagedPermissionPreflightResult)},
        {"onFileOpened", "(Ljava/lang/String;)V", reinterpret_cast<void *>(onFileOpened)},
        {"onFileSaved", "(ZZ)V", reinterpret_cast<void *>(onFileSaved)},
        {"onConfigImported", "(Ljava/lang/String;)V", reinterpret_cast<void *>(onConfigImported)},
        {"onAuthResult", "(Z)V", reinterpret_cast<void *>(onAuthResult)},
        {"decodeQrCode", "(Ljava/lang/String;)Z", reinterpret_cast<bool *>(decodeQrCode)},
        {"onImeInsetsChanged", "(I)V", reinterpret_cast<void *>(onImeInsetsChanged)},
        {"onSystemBarsInsetsChanged", "(II)V", reinterpret_cast<void *>(onSystemBarsInsetsChanged)},
        {"onActivityPaused", "()V", reinterpret_cast<void *>(onActivityPaused)},
        {"onActivityResumed", "()V", reinterpret_cast<void *>(onActivityResumed)}
    };

    QJniEnvironment env;
    bool registered = env.registerNativeMethods(QT_ANDROID_CONTROLLER_CLASS, methods,
                                                sizeof(methods) / sizeof(JNINativeMethod));
    if (!registered) {
        qCritical() << "Failed native method registration";
        return false;
    }
    qtAndroidControllerInitialized();
    return true;
}

// static
template <typename Ret, typename ...Args>
auto AndroidController::callActivityMethod(const char *methodName, const char *signature, Args &&...args)
{
    qDebug() << "Call activity method:" << methodName;
    QJniObject activity = AndroidUtils::getActivity();
    Q_ASSERT(activity.isValid());
    return activity.callMethod<Ret>(methodName, signature, std::forward<Args>(args)...);
}

// static
template <typename ...Args>
void AndroidController::callActivityMethod(const char *methodName, const char *signature, Args &&...args)
{
    callActivityMethod<void>(methodName, signature, std::forward<Args>(args)...);
}

ErrorCode AndroidController::start(const QJsonObject &vpnConfig)
{
    isWaitingStatus = false;
    QJsonObject configured = vpnConfig;
    const QString protocol = configured.value("protocol").toString();
    const QJsonObject peer = configured.value(protocol + "_config_data").toObject();
    QString host = peer.value("hostName").toString();
    QHostAddress numericHost;
    if (numericHost.setAddress(host)) host = numericHost.toString();
    m_expectedHealth = {QUuid::createUuid().toString(QUuid::WithoutBraces),
        QString::fromLatin1(QByteArray::fromBase64(peer.value("server_pub_key").toString().toLatin1()).toHex()),
        AwgHealthContext::endpointForHost(host, peer.value("port").toInt())};
    configured.insert("healthContextId", m_expectedHealth.id);
    m_managedTicket = configured.value("managedTicket").toString();
    auto config = QJsonDocument(configured).toJson();
    callActivityMethod("start", "(Ljava/lang/String;)V",
                       QJniObject::fromString(config).object<jstring>());

    return ErrorCode::NoError;
}

void AndroidController::stop()
{
    m_expectedHealth = {};
    callActivityMethod("stop", "()V");
}

int AndroidController::installUpdateApk(const QString &path)
{
    auto pending = QNativeInterface::QAndroidApplication::runOnAndroidMainThread([path]() -> QVariant {
        return static_cast<int>(callActivityMethod<jint>("installUpdateApk", "(Ljava/lang/String;)I",
                        QJniObject::fromString(path).object<jstring>()));
    }, QDeadlineTimer(5000));
    pending.waitForFinished();
    return pending.isCanceled() || pending.resultCount() == 0 ? UpdateInstallFailed : pending.result().toInt();
}

void AndroidController::resetLastServer(int serverIndex)
{
    callActivityMethod("resetLastServer", "(I)V", serverIndex);
}

void AndroidController::saveFile(const QString &fileName, const QString &data)
{
    callActivityMethod("saveFile", "(Ljava/lang/String;Ljava/lang/String;)V",
                       QJniObject::fromString(fileName).object<jstring>(),
                       QJniObject::fromString(data).object<jstring>());
}

bool AndroidController::saveFile(const QString &fileName, const QByteArray &data, const QString &mime, bool *cancelled)
{
    QJniEnvironment env;
    const jsize size = static_cast<jsize>(data.size());
    jbyteArray bytes = env->NewByteArray(size);
    if (!bytes) {
        env.checkAndClearExceptions();
        qCritical() << "AndroidController::saveFile: cannot allocate byte array of size" << size;
        return false;
    }
    env->SetByteArrayRegion(bytes, 0, size, reinterpret_cast<const jbyte *>(data.constData()));

    QEventLoop wait;
    bool saved = false;
    bool saveCancelled = false;
    connect(this, &AndroidController::fileSaved, this,
            [&saved, &saveCancelled, &wait](bool success, bool isCancelled) {
                saved = success;
                saveCancelled = isCancelled;
                wait.quit();
            },
            static_cast<Qt::ConnectionType>(Qt::QueuedConnection | Qt::SingleShotConnection));
    callActivityMethod("saveFileBytes", "(Ljava/lang/String;[BLjava/lang/String;)V",
                       QJniObject::fromString(fileName).object<jstring>(), bytes,
                       QJniObject::fromString(mime).object<jstring>());
    env->DeleteLocalRef(bytes);
    wait.exec();
    if (cancelled) {
        *cancelled = saveCancelled;
    }
    return saved;
}

void AndroidController::shareFile(const QString &path, const QString &mime)
{
    callActivityMethod("shareFile", "(Ljava/lang/String;Ljava/lang/String;)V",
                       QJniObject::fromString(path).object<jstring>(),
                       QJniObject::fromString(mime).object<jstring>());
}

QString AndroidController::openFile(const QString &filter)
{
    QEventLoop wait;
    QString fileName;
    connect(this, &AndroidController::fileOpened, this,
            [&fileName, &wait](const QString &uri) {
                fileName = uri;
                wait.quit();
            },
            static_cast<Qt::ConnectionType>(Qt::QueuedConnection | Qt::SingleShotConnection));
    callActivityMethod("openFile", "(Ljava/lang/String;)V",
                       QJniObject::fromString(filter).object<jstring>());
    wait.exec();
    return fileName;
}

int AndroidController::getFd(const QString &fileName)
{
    return callActivityMethod<jint>("getFd", "(Ljava/lang/String;)I",
                                    QJniObject::fromString(fileName).object<jstring>());
}

void AndroidController::closeFd()
{
    callActivityMethod("closeFd", "()V");
}

QString AndroidController::getFileName(const QString &uri)
{
    auto fileName = callActivityMethod<jstring, jstring>("getFileName", "(Ljava/lang/String;)Ljava/lang/String;",
                                                         QJniObject::fromString(uri).object<jstring>());
    QJniEnvironment env;
    return AndroidUtils::convertJString(env.jniEnv(), fileName.object<jstring>());
}

bool AndroidController::isCameraPresent()
{
    return callActivityMethod<jboolean>("isCameraPresent", "()Z");
}

bool AndroidController::isOnTv()
{
    return callActivityMethod<jboolean>("isOnTv", "()Z");
}

bool AndroidController::isEdgeToEdgeEnabled()
{
    return callActivityMethod<jboolean>("isEdgeToEdgeEnabled", "()Z");
}

int AndroidController::getStatusBarHeight()
{
    return callActivityMethod<jint>("getStatusBarHeight", "()I");
}

int AndroidController::getNavigationBarHeight()
{
    return callActivityMethod<jint>("getNavigationBarHeight", "()I");
}

void AndroidController::startQrReaderActivity()
{
    callActivityMethod("startQrCodeReader", "()V");
}

void AndroidController::setSaveLogs(bool enabled)
{
    callActivityMethod("setSaveLogs", "(Z)V", enabled);
}

void AndroidController::setScreenshotsEnabled(bool enabled)
{
    callActivityMethod("setScreenshotsEnabled", "(Z)V", enabled);
}

void AndroidController::setNavigationBarColor(unsigned int color)
{
    callActivityMethod("setNavigationBarColor", "(I)V", color);
}

void AndroidController::minimizeApp()
{
    callActivityMethod("minimizeApp", "()V");
}

QJsonArray AndroidController::getAppList()
{
    QJniObject appList = callActivityMethod<jstring>("getAppList", "()Ljava/lang/String;");
    QJsonArray jsonAppList = QJsonDocument::fromJson(appList.toString().toUtf8()).array();
    return jsonAppList;
}

QPixmap AndroidController::getAppIcon(const QString &package, QSize *size, const QSize &requestedSize)
{
    QJniObject bitmap = callActivityMethod<jobject>("getAppIcon", "(Ljava/lang/String;II)Landroid/graphics/Bitmap;",
                                                    QJniObject::fromString(package).object<jstring>(),
                                                    requestedSize.width(), requestedSize.height());

    QJniEnvironment env;
    AndroidBitmapInfo info;
    if (AndroidBitmap_getInfo(env.jniEnv(), bitmap.object(), &info) != ANDROID_BITMAP_RESULT_SUCCESS) return {};

    void *pixels;
    if (AndroidBitmap_lockPixels(env.jniEnv(), bitmap.object(), &pixels) != ANDROID_BITMAP_RESULT_SUCCESS) return {};

    int width = info.width;
    int height = info.height;

    size->setWidth(width);
    size->setHeight(height);

    QImage image(width, height, QImage::Format_RGBA8888);
    if (info.stride == uint32_t(image.bytesPerLine())) {
        memcpy((void *) image.constBits(), pixels, info.stride * height);
    } else {
        auto *bmpPtr = static_cast<uchar *>(pixels);
        for (int i = 0; i < height; i++, bmpPtr += info.stride)
            memcpy((void *) image.constScanLine(i), bmpPtr, width);
    }

    if (AndroidBitmap_unlockPixels(env.jniEnv(), bitmap.object()) != ANDROID_BITMAP_RESULT_SUCCESS) return {};

    return QPixmap::fromImage(image);
}

bool AndroidController::isNotificationPermissionGranted()
{
    return callActivityMethod<jboolean>("isNotificationPermissionGranted", "()Z");
}

void AndroidController::requestNotificationPermission()
{
    callActivityMethod("requestNotificationPermission", "()V");
}

bool AndroidController::requestAuthentication()
{
    QEventLoop wait;
    bool result;
    connect(this, &AndroidController::authenticationResult, this,
            [&result, &wait](const bool &authResult){
                qDebug() << "Android authentication result:" << authResult;
                result = authResult;
                wait.quit();
            },
            static_cast<Qt::ConnectionType>(Qt::QueuedConnection | Qt::SingleShotConnection));
    callActivityMethod("requestAuthentication", "()V");
    wait.exec();
    return result;
}

void AndroidController::sendTouch(float x, float y)
{
    callActivityMethod("sendTouch", "(FF)V", x, y);
}


bool AndroidController::isPlay()
{
    return callActivityMethod<jboolean>("isPlay", "()Z");
}

QJsonObject AndroidController::getSubscriptionPlans()
{
    QJniObject subscriptionPlans = callActivityMethod<jstring>("getSubscriptionPlans", "()Ljava/lang/String;");
    QJsonObject json = QJsonDocument::fromJson(subscriptionPlans.toString().toUtf8()).object();
    return json;
}

QJsonObject AndroidController::purchaseSubscription(const QString &offerToken)
{
    QJniObject result = callActivityMethod<jstring, jstring>("purchaseSubscription", "(Ljava/lang/String;)Ljava/lang/String;",
                                                    QJniObject::fromString(offerToken).object<jstring>());
    QJsonObject json = QJsonDocument::fromJson(result.toString().toUtf8()).object();
    return json;
}

QJsonObject AndroidController::upgradeSubscription(const QString &offerToken, const QString &oldPurchaseToken)
{
    QJniObject result = callActivityMethod<jstring, jstring, jstring>("upgradeSubscription",
                                                                      "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                                                                      QJniObject::fromString(offerToken).object<jstring>(),
                                                                      QJniObject::fromString(oldPurchaseToken).object<jstring>());
    QJsonObject json = QJsonDocument::fromJson(result.toString().toUtf8()).object();
    return json;
}

QJsonObject AndroidController::acknowledgePurchase(const QString &purchaseToken)
{
    QJniObject result = callActivityMethod<jstring, jstring>("acknowledgePurchase", "(Ljava/lang/String;)Ljava/lang/String;",
                                                             QJniObject::fromString(purchaseToken).object<jstring>());
    QJsonObject json = QJsonDocument::fromJson(result.toString().toUtf8()).object();
    return json;
}

QJsonObject AndroidController::queryPurchases()
{
    QJniObject result = callActivityMethod<jstring>("queryPurchases", "()Ljava/lang/String;");
    QJsonObject json = QJsonDocument::fromJson(result.toString().toUtf8()).object();
    return json;
}

// Moving log processing to the Android side
jclass AndroidController::log;
jmethodID AndroidController::logDebug;
jmethodID AndroidController::logInfo;
jmethodID AndroidController::logWarning;
jmethodID AndroidController::logError;
jmethodID AndroidController::logFatal;

// static
bool AndroidController::initLogging()
{
    QJniEnvironment env;

    log = env.findClass(ANDROID_LOG_CLASS);
    if (log == nullptr) {
        qCritical() << "Android log class" << ANDROID_LOG_CLASS << "not found";
        return false;
    }

    auto logMethodSignature = "(Ljava/lang/String;Ljava/lang/String;)V";

    logDebug = env.findStaticMethod(log, "d", logMethodSignature);
    if (logDebug == nullptr) {
        qCritical() << "Android debug log method not found";
        return false;
    }

    logInfo = env.findStaticMethod(log, "i", logMethodSignature);
    if (logInfo == nullptr) {
        qCritical() << "Android info log method not found";
        return false;
    }

    logWarning = env.findStaticMethod(log, "w", logMethodSignature);
    if (logWarning == nullptr) {
        qCritical() << "Android warning log method not found";
        return false;
    }

    logError = env.findStaticMethod(log, "e", logMethodSignature);
    if (logError == nullptr) {
        qCritical() << "Android error log method not found";
        return false;
    }

    logFatal = env.findStaticMethod(log, "f", logMethodSignature);
    if (logFatal == nullptr) {
        qCritical() << "Android fatal log method not found";
        return false;
    }

    qInstallMessageHandler(messageHandler);
    return true;
}

// static
void AndroidController::messageHandler(QtMsgType type, const QMessageLogContext &context, const QString &message)
{
    jmethodID logMethod = logDebug;
    switch (type) {
        case QtDebugMsg:
            logMethod = logDebug;
            break;
        case QtInfoMsg:
            logMethod = logInfo;
            break;
        case QtWarningMsg:
            logMethod = logWarning;
            break;
        case QtCriticalMsg:
            logMethod = logError;
            break;
        case QtFatalMsg:
            logMethod = logFatal;
            break;
    }
    QString formattedMessage = qFormatLogMessage(type, context, message);
    QJniObject::callStaticMethod<void>(log, logMethod,
                                       QJniObject::fromString(TAG).object<jstring>(),
                                       QJniObject::fromString(formattedMessage).object<jstring>());
}

// static
jclass AndroidController::findLogClass()
{
    if (log != nullptr) {
        return log;
    }
    return QJniEnvironment().findClass(ANDROID_LOG_CLASS);
}

// static
QStringList AndroidController::logFiles(int stream)
{
    const jclass logClass = findLogClass();
    if (logClass == nullptr) {
        return {};
    }
    const QString files =
        QJniObject::callStaticObjectMethod(logClass, "getLogFiles", "(I)Ljava/lang/String;", static_cast<jint>(stream))
            .toString();
    return files.split('\n', Qt::SkipEmptyParts);
}

// static
QString AndroidController::deviceInfo()
{
    const jclass logClass = findLogClass();
    if (logClass == nullptr) {
        return {};
    }
    return QJniObject::callStaticObjectMethod(logClass, "getDeviceInfo", "()Ljava/lang/String;").toString();
}

// static
void AndroidController::clearLogStream(int stream)
{
    const jclass logClass = findLogClass();
    if (logClass == nullptr) {
        return;
    }
    QJniObject::callStaticMethod<void>(logClass, "clearStream", "(I)V", static_cast<jint>(stream));
}

void AndroidController::qtAndroidControllerInitialized()
{
    callActivityMethod("qtAndroidControllerInitialized", "()V");
}

// static
Vpn::ConnectionState AndroidController::convertState(AndroidController::ConnectionState state)
{
    switch (state) {
        case AndroidController::ConnectionState::CONNECTED: return Vpn::ConnectionState::Connected;
        case AndroidController::ConnectionState::CONNECTING: return Vpn::ConnectionState::Connecting;
        case AndroidController::ConnectionState::DISCONNECTED: return Vpn::ConnectionState::Disconnected;
        case AndroidController::ConnectionState::DISCONNECTING: return Vpn::ConnectionState::Disconnecting;
        case AndroidController::ConnectionState::RECONNECTING: return Vpn::ConnectionState::Reconnecting;
        case AndroidController::ConnectionState::UNKNOWN: return Vpn::ConnectionState::Unknown;
    }
}

// static
QString AndroidController::textConnectionState(AndroidController::ConnectionState state)
{
    switch (state) {
        case AndroidController::ConnectionState::CONNECTED: return "CONNECTED";
        case AndroidController::ConnectionState::CONNECTING: return "CONNECTING";
        case AndroidController::ConnectionState::DISCONNECTED: return "DISCONNECTED";
        case AndroidController::ConnectionState::DISCONNECTING: return "DISCONNECTING";
        case AndroidController::ConnectionState::RECONNECTING: return "RECONNECTING";
        case AndroidController::ConnectionState::UNKNOWN: return "UNKNOWN";
    }
}

// JNI functions called by Android
// static
void AndroidController::onStatus(JNIEnv *env, jobject thiz, jint stateCode)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    auto state = ConnectionState(stateCode);
    AndroidController *controller = AndroidController::instance();
    emit controller->status(state);
}

// static
void AndroidController::onServiceDisconnected(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->serviceDisconnected();
}

// static
void AndroidController::onServiceError(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->serviceError();
}

// static
void AndroidController::onVpnPermissionRejected(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->vpnPermissionRejected();
}

// static
void AndroidController::onNotificationStateChanged(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->notificationStateChanged();
}

// static
void AndroidController::onVpnStateChanged(JNIEnv *env, jobject thiz, jint stateCode)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    auto state = ConnectionState(stateCode);
    AndroidController *controller = AndroidController::instance();
    emit controller->vpnStateChanged(state);
}

// static
void AndroidController::onStatisticsUpdate(JNIEnv *env, jobject thiz, jlong rxBytes, jlong txBytes)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->statisticsUpdated((quint64) rxBytes, (quint64) txBytes);
}

// static
void AndroidController::onAwgTunnelHealth(JNIEnv *env, jobject thiz, jstring snapshotJson)
{
    Q_UNUSED(thiz);
    AndroidController *controller = AndroidController::instance();
    const QString payload = AndroidUtils::convertJString(env, snapshotJson);
    const QJsonDocument document = QJsonDocument::fromJson(payload.toUtf8());
    if (!document.isObject()) return;
    const AwgTunnelHealth health = AwgTunnelHealth::fromJson(document.object());
    // Never read the expected activation/state on the Java callback thread.
    QMetaObject::invokeMethod(controller, [controller, health] {
        controller->receiveAwgTunnelHealth(health);
    }, Qt::QueuedConnection);
}

void AndroidController::receiveAwgTunnelHealth(const AwgTunnelHealth& health)
{
    Q_ASSERT(QThread::currentThread() == thread());
    if (m_vpnState != ConnectionState::CONNECTED && m_vpnState != ConnectionState::CONNECTING) return;
    if (!m_expectedHealth.matches(health)) return;
    emit awgTunnelHealthUpdated(health);
}

// static
void AndroidController::onFileOpened(JNIEnv *env, jobject thiz, jstring uri)
{
    Q_UNUSED(thiz);

    emit AndroidController::instance()->fileOpened(AndroidUtils::convertJString(env, uri));
}

// static
void AndroidController::onFileSaved(JNIEnv *env, jobject thiz, jboolean success, jboolean cancelled)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->fileSaved(success, cancelled);
}

// static
void AndroidController::onConfigImported(JNIEnv *env, jobject thiz, jstring data)
{
    Q_UNUSED(thiz);

    emit AndroidController::instance()->configImported(AndroidUtils::convertJString(env, data));
}

// static
void AndroidController::onAuthResult(JNIEnv *env, jobject thiz, jboolean result)
{
    Q_UNUSED(thiz);

    emit AndroidController::instance()->authenticationResult(result);
}

// static
bool AndroidController::decodeQrCode(JNIEnv *env, jobject thiz, jstring data)
{
    Q_UNUSED(thiz);

    return ImportUiController::decodeQrCode(AndroidUtils::convertJString(env, data));
}
// static
void AndroidController::onImeInsetsChanged(JNIEnv *env, jobject thiz, jint heightDp)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    qDebug() << "Android IME insets changed: height =" << heightDp << "dp";
    emit AndroidController::instance()->imeInsetsChanged(heightDp);
}

// static
void AndroidController::onSystemBarsInsetsChanged(JNIEnv *env, jobject thiz, jint navBarHeightDp, jint statusBarHeightDp)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    qDebug() << "Android system bars insets changed: nav bar =" << navBarHeightDp << "dp, status bar =" << statusBarHeightDp << "dp";
    emit AndroidController::instance()->systemBarsInsetsChanged(navBarHeightDp, statusBarHeightDp);
}

// static
void AndroidController::onActivityPaused(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->activityPaused();
}

// static
void AndroidController::onActivityResumed(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->activityResumed();
}



void AndroidController::prepareManagedPermissions(const QString &requestId, ManagedPermissionDone done) {
    Q_ASSERT(QThread::currentThread() == thread());
    if (requestId.isEmpty() || !done || m_permissionPreflightCallbacks.contains(requestId)) {
        if (done) done(requestId, ManagedPermissionResult::Unavailable);
        return;
    }
    QJniObject activity = AndroidUtils::getActivity();
    if (!activity.isValid()) { done(requestId, ManagedPermissionResult::Unavailable); return; }
    m_permissionPreflightCallbacks.insert(requestId, std::move(done));
    activity.callMethod<void>("prepareManagedPermissionPreflight", "(Ljava/lang/String;)V",
                              QJniObject::fromString(requestId).object<jstring>());
    if (QJniEnvironment().checkAndClearExceptions()) {
        const auto callback = m_permissionPreflightCallbacks.take(requestId);
        if (callback) callback(requestId, ManagedPermissionResult::Unavailable);
    }
}

void AndroidController::cancelManagedPermissionPreparation(const QString &requestId) {
    Q_ASSERT(QThread::currentThread() == thread());
    m_permissionPreflightCallbacks.remove(requestId);
    QJniObject activity = AndroidUtils::getActivity();
    if (!activity.isValid()) return;
    activity.callMethod<void>("cancelManagedPermissionPreflight", "(Ljava/lang/String;)V",
                              QJniObject::fromString(requestId).object<jstring>());
    QJniEnvironment().checkAndClearExceptions();
}

void AndroidController::onManagedPermissionPreflightResult(JNIEnv *env, jobject, jstring jRequestId, jint result) {
    const QString requestId = AndroidUtils::convertJString(env, jRequestId);
    ManagedPermissionResult status = ManagedPermissionResult::Unavailable;
    if (result == static_cast<jint>(ManagedPermissionResult::Ready)) status = ManagedPermissionResult::Ready;
    else if (result == static_cast<jint>(ManagedPermissionResult::Denied)) status = ManagedPermissionResult::Denied;
    auto *controller = instance();
    QMetaObject::invokeMethod(controller, [controller, requestId, status] {
        const auto callback = controller->m_permissionPreflightCallbacks.take(requestId);
        if (callback) callback(requestId, status);
    }, Qt::QueuedConnection);
}

void AndroidController::cancelManaged(const QString& ticket) {
    Q_ASSERT(QThread::currentThread() == thread());
    callActivityMethod("cancelManaged", "(Ljava/lang/String;)V", QJniObject::fromString(ticket).object<jstring>());
}
void AndroidController::managedStop(const QString& request, const QString& context, const QString& ticket) {
    Q_ASSERT(QThread::currentThread() == thread());
    m_managedStops.insert(request, context);
    qInfo() << "MayakManagedStop dispatch=invoked";
    callActivityMethod("managedStop", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        QJniObject::fromString(request).object<jstring>(), QJniObject::fromString(context).object<jstring>(),
        QJniObject::fromString(ticket).object<jstring>());
}
void AndroidController::managedInspect(const QString& request) {
    Q_ASSERT(QThread::currentThread() == thread());
    m_managedInspections.insert(request);
    callActivityMethod("managedInspect", "(Ljava/lang/String;)V", QJniObject::fromString(request).object<jstring>());
}
void AndroidController::onManagedLifecycle(JNIEnv*, jobject, jstring resultJson) {
    const QJsonDocument document = QJsonDocument::fromJson(QJniObject(resultJson).toString().toUtf8());
    if (!document.isObject()) { qInfo() << "MayakManagedStopAck accepted=false reason=shape"; return; }
    const QJsonObject obj = document.object();
    auto* controller = instance();
    QMetaObject::invokeMethod(controller, [controller, obj] {
        if (obj.value("owner").toString() != "MayakVpnAwgLifecycleV1") {
            if (obj.value("type").toString() == "managedStopped")
                qInfo() << "MayakManagedStopAck accepted=false reason=owner";
            return;
        }
        const QString type = obj.value("type").toString();
        if (type == "managedStopped") {
            const QString request = obj.value("stopRequestId").toString();
            const QString context = obj.value("healthContextId").toString();
            const bool stoppedShape = obj.value("stopped").isBool();
            const bool requestMatch = controller->m_managedStops.contains(request);
            const bool contextMatch = requestMatch && controller->m_managedStops.value(request) == context;
            if (!stoppedShape || !requestMatch || !contextMatch) {
                qInfo() << "MayakManagedStopAck accepted=false stopped_shape=" << stoppedShape
                        << "request_match=" << requestMatch << "context_match=" << contextMatch;
                return;
            }
            controller->m_managedStops.remove(request);
            const bool stopped = obj.value("stopped").toBool();
            if (stopped && controller->m_expectedHealth.id == context) controller->m_expectedHealth = {};
            qInfo() << "MayakManagedStopAck accepted=true stopped=" << stopped;
            emit controller->managedStopped(request, context, stopped);
        } else if (type == "managedInspection") {
            const QString request = obj.value("inspectRequestId").toString();
            if (!controller->m_managedInspections.remove(request)) return;
            emit controller->managedInspected(request, obj.value("state").toString(), obj.value("controlIdentity").toString());
        } else if (type == "managedDenied") {
            const QString ticket = obj.value("ticket").toString();
            const QString context = obj.value("healthContextId").toString();
            if (ticket != controller->m_managedTicket || context != controller->m_expectedHealth.id) return;
            controller->m_expectedHealth = {};
            emit controller->managedDenied(ticket, context);
        }
    }, Qt::QueuedConnection);
}
