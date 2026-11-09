#include "secureQSettings.h"

#include <QDebug>
#include "cryptoUtils.h"
#include <QDataStream>
#include <QDebug>
#include <QEventLoop>
#include <QIODevice>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QSharedPointer>
#include <QTimer>

using namespace QKeychain;

namespace {
#ifdef Q_OS_WIN
    // The pinned Windows QtKeychain backend uses job.key as the global
    // Credential Manager target and ignores the service name. Keep these
    // stable Mayak-only names; never probe the legacy Amnezia targets.
    const QString settingsKeyTag = QStringLiteral("MayakVPN-Client/settingsKeyTag");
    const QString settingsIvTag = QStringLiteral("MayakVPN-Client/settingsIvTag");
#else
    // Preserve existing credentials on Android, macOS and Linux.
    const QString settingsKeyTag = QStringLiteral("settingsKeyTag");
    const QString settingsIvTag = QStringLiteral("settingsIvTag");
#endif
#ifndef CLIENT_KEYCHAIN_NAME_STR
#define CLIENT_KEYCHAIN_NAME_STR "AmneziaVPN-Keychain"
#endif
    constexpr const char *keyChainName = CLIENT_KEYCHAIN_NAME_STR;
}

SecureQSettings::SecureQSettings(const QString &organization, const QString &application, QObject *parent, bool enableEncryption)
    : QObject { parent }, m_settings(organization, application, parent), encryptedKeys({ "Servers/serversList", "Conf/favoriteLocations", "Conf/proxyUrls/agw_state", "Mayak/sessionToken", "Mayak/pendingAttempts", "Mayak/managedServers" }), m_encryptionEnabled(enableEncryption)
{
    bool encrypted = m_settings.value("Conf/encrypted").toBool();

    // convert settings to encrypted for if updated to >= 2.1.0
    if (encryptionRequired() && !encrypted) {
        for (const QString &key : m_settings.allKeys()) {
            // This new ledger has no legacy plaintext migration: a plaintext value
            // is untrusted cleanup authority and must remain detectable as corrupt.
            if (key == QStringLiteral("Mayak/pendingAttempts")) {
                continue;
            }
            if (encryptedKeys.contains(key)) {
                const QVariant &val = value(key);
                setValue(key, val);
            }
        }
        m_settings.setValue("Conf/encrypted", true);
    }

    const QString sessionKey = QStringLiteral("Mayak/sessionToken");
    const QVariant storedSession = m_settings.value(sessionKey);
    if (storedSession.isValid()) {
        if (!encryptionRequired()) {
            m_settings.remove(sessionKey);
            m_settings.sync();
        } else if (storedSession.userType() != QMetaType::QByteArray || !storedSession.toByteArray().startsWith(magicString)) {
            // Migrate the token written by earlier Mayak builds before it was added to the encrypted key set.
            if (!setEncryptedValueAndSync(sessionKey, storedSession)) {
                qCritical() << "SecureQSettings: failed to migrate Mayak session token to encrypted storage";
                m_settings.remove(sessionKey);
                m_settings.sync();
            }
        }
    }
}

QVariant SecureQSettings::value(const QString &key, const QVariant &defaultValue) const
{
    QMutexLocker locker(&m_mutex);

    if (m_cache.contains(key)) {
        return m_cache.value(key);
    }

    if (!m_settings.contains(key))
        return defaultValue;

    QVariant retVal;

    // check if value is not encrypted, v. < 2.0.x
    retVal = m_settings.value(key);
    if (retVal.isValid()) {
        if (retVal.userType() == QMetaType::QByteArray && retVal.toByteArray().mid(0, magicString.size()) == magicString) {

            if (getEncKey().isEmpty() || getEncIv().isEmpty()) {
                qCritical() << "SecureQSettings::setValue Decryption requested, but key is empty";
                return {};
            }

            QByteArray encryptedValue = retVal.toByteArray().mid(magicString.size());

            QByteArray decryptedValue = decryptText(encryptedValue);
            QDataStream ds(&decryptedValue, QIODevice::ReadOnly);

            ds >> retVal;

            if (!retVal.isValid()) {
                qWarning() << "SecureQSettings::value settings decryption failed";
                retVal = QVariant();
            }
        }
    } else {
        qWarning() << "SecureQSettings::value invalid QVariant value";
        retVal = QVariant();
    }

    m_cache.insert(key, retVal);
    return retVal;
}

void SecureQSettings::setValue(const QString &key, const QVariant &value)
{
    storeValue(key, value, false);
}

bool SecureQSettings::setEncryptedValueAndSync(const QString &key, const QVariant &value)
{
    if (!encryptedKeys.contains(key) || !encryptedStorageAvailable()) {
        return false;
    }
    return storeValue(key, value, true);
}

bool SecureQSettings::storeValue(const QString &key, const QVariant &value, bool sync)
{
    QMutexLocker locker(&m_mutex);

    if (encryptionRequired() && encryptedKeys.contains(key)) {
        if (!getEncKey().isEmpty() && !getEncIv().isEmpty()) {
            QByteArray decryptedValue;
            {
                QDataStream ds(&decryptedValue, QIODevice::WriteOnly);
                ds << value;
            }

            QByteArray encryptedValue = encryptText(decryptedValue);
            if (encryptedValue.isEmpty() && !decryptedValue.isEmpty()) {
                return false;
            }
            m_settings.setValue(key, magicString + encryptedValue);
        } else {
            qCritical() << "SecureQSettings::setValue Encryption required, but key is empty";
            return false;
        }

    } else {
        m_settings.setValue(key, value);
    }

    if (sync) {
        m_settings.sync();
        if (m_settings.status() != QSettings::NoError) {
            return false;
        }
    }
    m_cache.insert(key, value);
    return true;
}

void SecureQSettings::remove(const QString &key)
{
    QMutexLocker locker(&m_mutex);
    m_settings.remove(key);
    m_cache.remove(key);
}

bool SecureQSettings::removeAndSync(const QString &key)
{
    QMutexLocker locker(&m_mutex);

    m_settings.remove(key);
    m_settings.sync();
    if (m_settings.status() != QSettings::NoError) {
        return false;
    }
    m_cache.remove(key);
    return true;
}

bool SecureQSettings::encryptedStorageAvailable() const
{
    return encryptionRequired() && !getEncKey().isEmpty() && !getEncIv().isEmpty();
}

bool SecureQSettings::isEncryptedValueStored(const QString &key) const
{
    QMutexLocker locker(&m_mutex);
    const QVariant stored = m_settings.value(key);
    return stored.userType() == QMetaType::QByteArray && stored.toByteArray().startsWith(magicString);
}

SecureQSettings::StoredValueClass SecureQSettings::storedValueClass(const QString &key) const
{
    QMutexLocker locker(&m_mutex);
    if (!m_settings.contains(key)) {
        return StoredValueClass::Missing;
    }
    const QVariant stored = m_settings.value(key);
    if (stored.userType() == QMetaType::QByteArray && stored.toByteArray().startsWith(magicString)) {
        return StoredValueClass::Encrypted;
    }
    return StoredValueClass::UnencryptedOrInvalid;
}

QByteArray SecureQSettings::backupAppConfig() const
{
    QMutexLocker locker(&m_mutex);

    QJsonObject cfg;

    const auto needToBackup = [this](const QString &key) {
        if (isExcludedFromBackup(key)) {
            return false;
        }
        for (const auto &item : m_fieldsToBackup) {
            if (key.startsWith(item)) {
                return true;
            }
        }
        return false;
    };

    for (const QString &key : m_settings.allKeys()) {

        if (!needToBackup(key))
        {
            continue;
        }

        cfg.insert(key, QJsonValue::fromVariant(value(key)));
    }

    return QJsonDocument(cfg).toJson();
}

bool SecureQSettings::restoreAppConfig(const QByteArray &json)
{
    QMutexLocker locker(&m_mutex);

    QJsonObject cfg = QJsonDocument::fromJson(json).object();
    if (cfg.isEmpty())
        return false;

    for (const QString &key : cfg.keys()) {
        if (isExcludedFromBackup(key)) {
            continue;
        }

        setValue(key, cfg.value(key).toVariant());
    }

    return true;
}

bool SecureQSettings::isExcludedFromBackup(const QString &key) const
{
    for (const auto &item : m_fieldsExcludedFromBackup) {
        if (key.startsWith(item)) {
            return true;
        }
    }
    return false;
}

void SecureQSettings::clearSettings()
{
    QMutexLocker locker(&m_mutex);
    m_settings.clear();
    m_cache.clear();
}

QByteArray SecureQSettings::encryptText(const QByteArray &value) const
{
    QByteArray result = CryptoUtils::encryptAes256Cbc(value, getEncKey(), getEncIv());
    if (result.isEmpty() && !value.isEmpty()) {
        qCritical() << "error when encrypting the settings value";
    }
    return result;
}

QByteArray SecureQSettings::decryptText(const QByteArray &ba) const
{
    QByteArray result = CryptoUtils::decryptAes256Cbc(ba, getEncKey(), getEncIv());
    if (result.isEmpty() && !ba.isEmpty()) {
        qCritical() << "error when decrypting the settings value";
    }
    return result;
}

bool SecureQSettings::encryptionRequired() const
{
    if (!m_encryptionEnabled) {
        return false;
    }
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    // QtKeyChain failing on Linux
    return false;
#endif
    return true;
}

QByteArray SecureQSettings::getEncKey() const
{

    if (!m_key.isEmpty()) {
        return m_key;
    }
    // load keys from system key storage
    m_key = getSecTag(settingsKeyTag);

    if (m_key.isEmpty()) {
        // Create new key
        QByteArray key = CryptoUtils::generateRandomBytes(32);
        if (key.isEmpty()) {
            qCritical() << "SecureQSettings::getEncKey Unable to generate new enc key";
        }

        setSecTag(settingsKeyTag, key);

        // check
        m_key = getSecTag(settingsKeyTag);
        if (key != m_key) {
            qCritical() << "SecureQSettings::getEncKey Unable to store key in keychain" << key.size() << m_key.size();
            return {};
        }
    }

    return m_key;
}

QByteArray SecureQSettings::getEncIv() const
{
    if (!m_iv.isEmpty()) {
        return m_iv;
    }
    // load keys from system key storage
    m_iv = getSecTag(settingsIvTag);

    if (m_iv.isEmpty()) {
        // Create new IV
        QByteArray iv = CryptoUtils::generateRandomBytes(32);
        if (iv.isEmpty()) {
            qCritical() << "SecureQSettings::getEncIv Unable to generate new enc IV";
        }
        setSecTag(settingsIvTag, iv);

        // check
        m_iv = getSecTag(settingsIvTag);
        if (iv != m_iv) {
            qCritical() << "SecureQSettings::getEncIv Unable to store IV in keychain" << iv.size() << m_iv.size();
            return {};
        }
    }

    return m_iv;
}

QByteArray SecureQSettings::getSecTag(const QString &tag)
{
    auto job = QSharedPointer<ReadPasswordJob>(new ReadPasswordJob(keyChainName), &QObject::deleteLater);
    job->setAutoDelete(false);
    job->setKey(tag);
    QEventLoop loop;
    job->connect(job.data(), &ReadPasswordJob::finished, job.data(), [&loop]() { loop.quit(); });
    job->start();
    loop.exec();

    if (job->error()) {
        qCritical() << "SecureQSettings::getSecTag Error:" << job->errorString();
    }

    return job->binaryData();
}

void SecureQSettings::setSecTag(const QString &tag, const QByteArray &data)
{
    auto job = QSharedPointer<WritePasswordJob>(new WritePasswordJob(keyChainName), &QObject::deleteLater);
    job->setAutoDelete(false);
    job->setKey(tag);
    job->setBinaryData(data);
    QEventLoop loop;
    QTimer::singleShot(1000, &loop, SLOT(quit()));
    job->connect(job.data(), &WritePasswordJob::finished, job.data(), [&loop]() { loop.quit(); });
    job->start();
    loop.exec();

    if (job->error()) {
        qCritical() << "SecureQSettings::setSecTag Error:" << job->errorString();
    }
}
