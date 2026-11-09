#include "mayakDeviceIdentity.h"

#include <QCryptographicHash>
#include <QSysInfo>

#ifdef Q_OS_ANDROID
#include <QCoreApplication>
#include <QJniObject>
#endif

namespace mayak::device {

QString hashDeviceId(const QString &rawId)
{
    const QString id = rawId.trimmed();
    // Известный общий ANDROID_ID старых прошивок Android 2.2: он одинаков на многих устройствах.
    if (id.isEmpty() || id.compare(QStringLiteral("9774d56d682e549c"), Qt::CaseInsensitive) == 0) return {};
    return QString::fromLatin1(QCryptographicHash::hash(QByteArrayLiteral("mayak-device-v1:") + id.toUtf8(),
                                                        QCryptographicHash::Sha256).toHex());
}

QString stableDeviceHash()
{
#ifdef Q_OS_ANDROID
    // ANDROID_ID (Android 8+) один для ключа подписи приложения и пользователя и переживает переустановку.
    const QJniObject context = QNativeInterface::QAndroidApplication::context();
    if (!context.isValid()) return {};
    const QJniObject resolver = context.callObjectMethod("getContentResolver", "()Landroid/content/ContentResolver;");
    if (!resolver.isValid()) return {};
    const QJniObject name = QJniObject::fromString(QStringLiteral("android_id"));
    const QJniObject id = QJniObject::callStaticObjectMethod("android/provider/Settings$Secure", "getString",
        "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;", resolver.object(), name.object<jstring>());
    return hashDeviceId(id.isValid() ? id.toString() : QString());
#else
    // Windows: MachineGuid; Linux: /etc/machine-id; macOS: IOPlatformUUID. Плюс имя пользователя системы: у разных
    // пользователей одного компьютера свои установки Маяка, и они не должны отбирать друг у друга устройство.
    const QString machine = QString::fromLatin1(QSysInfo::machineUniqueId());
    if (machine.isEmpty()) return {};
#ifdef Q_OS_WIN
    const QString user = qEnvironmentVariable("USERNAME");
#else
    const QString user = qEnvironmentVariable("USER");
#endif
    return hashDeviceId(user.isEmpty() ? machine : machine + QLatin1Char(':') + user.toLower());
#endif
}

QString osDescription()
{
    return (QSysInfo::productType() + QLatin1Char(' ') + QSysInfo::productVersion()).trimmed().left(64);
}

} // namespace mayak::device
