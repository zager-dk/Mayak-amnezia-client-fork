#ifndef UPDATECONTROLLER_H
#define UPDATECONTROLLER_H

#include <QDateTime>
#include <QNetworkRequest>
#include <QObject>
#include <QQmlEngine>
#include <QStringList>
#include <QUrl>
#include <QVector>
#include <functional>

#include "core/repositories/secureAppSettingsRepository.h"

class QCryptographicHash;
class QNetworkAccessManager;
class QNetworkReply;
class QSaveFile;
class QTimer;
class VpnConnection;

namespace UpdateState
{
    Q_NAMESPACE
    enum class State {
        Idle = 0,
        Downloading,
        ReadyToInstall,
        DownloadError
    };
    Q_ENUM_NS(State)

    inline void declareQmlUpdateStateEnum()
    {
        qmlRegisterUncreatableMetaObject(UpdateState::staticMetaObject, "UpdateState", 1, 0, "UpdateState",
                                         "Error: only enums");
    }
}

struct SignedUpdateManifest {
    QString product;
    QString channel;
    QString platform;
    QString version;
    quint64 versionCode = 0;
    QUrl url;
    quint64 size = 0;
    QByteArray sha256;
    QDateTime publishedAt;
    QDateTime expiresAt;
    QString releaseNotes;
};

// Explicit dependencies make the real controller testable with loopback
// transport, a generated fixture key and a non-executing installer callback.
struct UpdateControllerDependencies {
    QNetworkAccessManager *networkAccessManager = nullptr;
    QByteArray signingPublicKeyPem;
    QUrl manifestUrl;
    QString platform;
    QString installedVersion;
    quint64 installedVersionCode = 0;
    QString cacheDirectory;
    std::function<bool()> tunnelDisconnected;
    std::function<bool(const QString &)> installerLauncher;
    std::function<QDateTime()> nowUtc;
    bool automaticChecksEnabled = true;
    bool checkOnConstruction = true;
};

class UpdateController : public QObject
{
    Q_OBJECT
public:
    explicit UpdateController(SecureAppSettingsRepository *appSettingsRepository, QObject *parent = nullptr);
    UpdateController(SecureAppSettingsRepository *appSettingsRepository, VpnConnection *vpnConnection, QObject *parent);
    UpdateController(SecureAppSettingsRepository *appSettingsRepository, UpdateControllerDependencies dependencies,
                     QObject *parent = nullptr);

    QString getVersion() const;
    QString getReleaseDate() const;
    QString getDescription() const;
    QStringList getTags() const;
    QStringList getNewFeatures() const;
    QStringList getImprovements() const;
    QStringList getBugFixes() const;
    UpdateState::State getUpdateState() const;
    bool isStoreUpdate() const;
    bool isUpdateCheckRunning() const;
    bool isUpdateSupported() const;
    int getDownloadProgress() const;
    QString getStatusMessage() const;
    void setTunnelDisconnectedProvider(std::function<bool()> provider) { m_dependencies.tunnelDisconnected = std::move(provider); }

    static bool verifySignedManifest(const QByteArray &envelope, const QByteArray &publicKeyPem,
                                     const QString &expectedPlatform, const QString &installedVersion,
                                     quint64 installedVersionCode, const QUrl &manifestUrl, const QDateTime &nowUtc,
                                     SignedUpdateManifest *manifest, QString *error = nullptr);
    static bool isAllowedPackageUrl(const QUrl &url, const QUrl &manifestUrl, QString *error = nullptr);

public slots:
    void checkForUpdates();
    void checkForUpdatesAutomatically();
    void startUpdate();
    void cancelUpdate();
    void installUpdate();

signals:
    void updateFound();
    void updateNotFound();
    void updateCheckFailed();
    void updateStateChanged();
    void updateCheckRunningChanged();
    void downloadProgressChanged();
    void statusMessageChanged();

private:
    enum class RequestKind { None, Manifest, Package };

    UpdateController(SecureAppSettingsRepository *appSettingsRepository, VpnConnection *vpnConnection,
                     UpdateControllerDependencies dependencies, QObject *parent);
    static UpdateControllerDependencies productionDependencies();
    static QByteArray productionUpdateSigningPublicKey();
    static QString productionPlatform();
    static bool compareVersions(const QString &left, const QString &right, int *comparison = nullptr);

    void setUpdateState(UpdateState::State state);
    void setUpdateCheckRunning(bool running);
    void setDownloadProgress(int percent);
    void setStatusMessage(const QString &message);
    void requestSignedManifest();
    void performUpdateCheck();
    void finishManifestRequest();
    void beginPackageDownload();
    void consumePackageData();
    void finishPackageDownload();
    void failActiveRequest(const QString &message, bool isCheck);
    void finishActiveReply();
    bool writePackageChunk(const QByteArray &chunk);
    bool verifyDownloadedFile(QString *error = nullptr) const;
    QDateTime currentTimeUtc() const;
    bool isTunnelDisconnected() const;
    bool launchInstaller(const QString &path);
    QString packageCacheDirectory() const;
    QNetworkRequest requestForUrl(const QUrl &url) const;
    void openStorePage() const;
    void downloadInstaller();
    QString composeDownloadUrl() const;

    SecureAppSettingsRepository *m_appSettingsRepository = nullptr;
    VpnConnection *m_vpnConnection = nullptr;
    QNetworkAccessManager *m_networkAccessManager = nullptr;
    QNetworkReply *m_activeReply = nullptr;
    QSaveFile *m_downloadFile = nullptr;
    QCryptographicHash *m_downloadHash = nullptr;
    QTimer *m_periodicCheckTimer = nullptr;
    UpdateControllerDependencies m_dependencies;
    SignedUpdateManifest m_signedUpdate;
    RequestKind m_requestKind = RequestKind::None;
    QByteArray m_manifestBuffer;
    QString m_verifiedArtifactPath;
    quint64 m_downloadedBytes = 0;
    int m_downloadProgress = 0;
    QString m_statusMessage;
    bool m_updateCheckRunning = false;
    bool m_updateSupported = false;
    bool m_signedFeedEnabled = false;

    QString m_version;
    QString m_releaseDate;
    QString m_description;
    QStringList m_tags;
    QStringList m_newFeatures;
    QStringList m_improvements;
    QStringList m_bugFixes;
    QString m_downloadBaseUrl;
    QString m_releasePageUrl;
    UpdateState::State m_updateState = UpdateState::State::Idle;

#if defined(Q_OS_WIN)
    int runWindowsInstaller(const QString &installerPath);
#elif defined(Q_OS_MACOS) && !defined(MACOS_NE)
    int runMacInstaller(const QString &installerPath);
#elif defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    int runLinuxInstaller(const QString &installerPath);
#endif
};

#endif // UPDATECONTROLLER_H
