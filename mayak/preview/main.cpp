#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QJSEngine>
#include <QtQml/qqml.h>
#include <QTimer>
#include <QTranslator>

class MockInviteController final : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool busy READ busy NOTIFY stateChanged)
    Q_PROPERTY(bool hasSession READ hasSession NOTIFY stateChanged)
    Q_PROPERTY(QString message READ message NOTIFY stateChanged)
public:
    bool busy() const { return m_busy; }
    bool hasSession() const { return m_hasSession; }
    QString message() const { return m_message; }
    Q_INVOKABLE void acceptInvite(const QString &code)
    {
        if (code.trimmed().isEmpty()) { m_message = QStringLiteral("Введите код приглашения."); emit stateChanged(); return; }
        m_busy = true; m_message = QStringLiteral("Проверяем приглашение…"); emit stateChanged();
        QTimer::singleShot(700, this, [this]() {
            m_busy = false; m_hasSession = true;
            m_message = QStringLiteral("Демо: сеть прервалась после входа. Сеанс сохранён."); emit stateChanged();
        });
    }
    Q_INVOKABLE void retrySetup()
    {
        m_busy = true; m_message = QStringLiteral("Демо: повторяем получение подписки…"); emit stateChanged();
        QTimer::singleShot(700, this, [this]() {
            m_busy = false; m_hasSession = false;
            m_message = QStringLiteral("Демо завершено: повтор настройки успешен."); emit stateChanged(); emit setupFinished();
        });
    }
signals:
    void stateChanged();
    void setupFinished();
private:
    bool m_busy = false;
    bool m_hasSession = false;
    QString m_message;
};

class MockPageController final : public QObject
{
    Q_OBJECT
    Q_PROPERTY(int safeAreaTopMargin READ safeAreaTopMargin CONSTANT)
    Q_PROPERTY(int safeAreaBottomMargin READ safeAreaBottomMargin CONSTANT)
    Q_PROPERTY(bool homeShown READ homeShown NOTIFY stateChanged)
public:
    bool homeShown() const { return m_homeShown; }
    int safeAreaTopMargin() const { return 0; }
    int safeAreaBottomMargin() const { return 0; }
    Q_INVOKABLE void closePage() {}
    Q_INVOKABLE void showNotificationMessage(const QString &) {}
    Q_INVOKABLE void goToPageHome() { m_homeShown = true; emit stateChanged(); }
signals:
    void stateChanged();
private:
    bool m_homeShown = false;
};

class MockUpdateController final : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString version READ version CONSTANT)
    Q_PROPERTY(QString releaseInfoText READ releaseInfoText CONSTANT)
    Q_PROPERTY(QString description READ description CONSTANT)
    Q_PROPERTY(QStringList tags READ tags CONSTANT)
    Q_PROPERTY(QStringList newFeatures READ newFeatures CONSTANT)
    Q_PROPERTY(QStringList improvements READ improvements CONSTANT)
    Q_PROPERTY(QStringList bugFixes READ bugFixes CONSTANT)
    Q_PROPERTY(int updateState READ updateState NOTIFY updateStateChanged)
    Q_PROPERTY(bool isStoreUpdate READ isStoreUpdate CONSTANT)
    Q_PROPERTY(bool isCheckRunning READ isCheckRunning NOTIFY isCheckRunningChanged)
    Q_PROPERTY(int downloadProgress READ downloadProgress NOTIFY downloadProgressChanged)
    Q_PROPERTY(QString statusMessage READ statusMessage NOTIFY statusMessageChanged)
    Q_PROPERTY(bool isUpdateSupported READ isUpdateSupported CONSTANT)
public:
    enum State { Idle, Downloading, ReadyToInstall, DownloadError };
    QString version() const { return QStringLiteral("5.1.0.5"); }
    QString releaseInfoText() const { return QStringLiteral("28 окт. · 5.1.0.5"); }
    QString description() const { return QStringLiteral("Mock release notes. No network, VPN, or real credentials are used."); }
    QStringList tags() const { return {QStringLiteral("Официальное обновление")}; }
    QStringList newFeatures() const { return {QStringLiteral("Подписанная проверка версии"), QStringLiteral("Загрузка с контролем целостности")}; }
    QStringList improvements() const { return {}; }
    QStringList bugFixes() const { return {}; }
    int updateState() const { return m_state; }
    bool isStoreUpdate() const { return false; }
    bool isCheckRunning() const { return false; }
    int downloadProgress() const { return m_progress; }
    QString statusMessage() const { return m_status; }
    bool isUpdateSupported() const { return true; }
    void enableDownloadErrorPreview()
    {
        m_state = DownloadError;
        m_status = QStringLiteral("Не удалось загрузить обновление. Проверьте подключение и нажмите «Повторить».");
    }
    Q_INVOKABLE void checkForUpdates() { setStatus(QStringLiteral("Предпросмотр: доступна версия 5.1.0.5.")); }
    Q_INVOKABLE void update() {
        m_state = Downloading; m_progress = 12; setStatus(QStringLiteral("Предпросмотр загрузки. Сеть не используется."));
        emit downloadProgressChanged(); emit updateStateChanged();
        QTimer::singleShot(400, this, [this]() { m_progress = 68; emit downloadProgressChanged(); });
        QTimer::singleShot(900, this, [this]() {
            m_state = ReadyToInstall; m_progress = 100;
            setStatus(QStringLiteral("Файл проверен. Установка в этом preview не запускается."));
            emit downloadProgressChanged(); emit updateStateChanged();
        });
    }
    Q_INVOKABLE void retry() { update(); }
    Q_INVOKABLE void cancel() { m_state = Idle; m_progress = 0; setStatus(QStringLiteral("Загрузка отменена.")); emit updateStateChanged(); emit downloadProgressChanged(); }
    Q_INVOKABLE void install() { setStatus(QStringLiteral("Предпросмотр: системная установка не запускается.")); }
signals:
    void updateFound();
    void updateNotFound();
    void updateCheckFailed();
    void updateStateChanged();
    void isCheckRunningChanged();
    void downloadProgressChanged();
    void statusMessageChanged();
private:
    void setStatus(const QString &value) { m_status = value; emit statusMessageChanged(); }
    int m_state = Idle;
    int m_progress = 0;
    QString m_status = QStringLiteral("Предпросмотр: доступна версия 5.1.0.5.");
};

class MockUpdateState final : public QObject
{
    Q_OBJECT
    Q_PROPERTY(int Idle MEMBER idle CONSTANT)
    Q_PROPERTY(int Downloading MEMBER downloading CONSTANT)
    Q_PROPERTY(int ReadyToInstall MEMBER readyToInstall CONSTANT)
    Q_PROPERTY(int DownloadError MEMBER downloadError CONSTANT)
public:
    int idle = MockUpdateController::Idle;
    int downloading = MockUpdateController::Downloading;
    int readyToInstall = MockUpdateController::ReadyToInstall;
    int downloadError = MockUpdateController::DownloadError;
};

static QObject *createMockUpdateState(QQmlEngine *, QJSEngine *)
{
    return new MockUpdateState;
}

class MockLanguageController final : public QObject
{
    Q_OBJECT
public:
    Q_INVOKABLE int getLineHeightAppend() const { return 0; }
};

int main(int argc, char *argv[])
{
    qputenv("QT_QUICK_CONTROLS_STYLE", "Basic");
    QGuiApplication app(argc, argv);
    QQmlApplicationEngine engine;
    MockInviteController mockInvite;
    MockPageController mockPage;
    MockLanguageController mockLanguage;
    MockUpdateController mockUpdate;
    const QString mode = app.arguments().contains(QStringLiteral("--updates"))
        ? QStringLiteral("updates") : QStringLiteral("invite");
    const bool phone = app.arguments().contains(QStringLiteral("--phone"));
    QTranslator russianTranslator;
    if (russianTranslator.load(QStringLiteral(":/translations/amneziavpn_ru_RU.qm"))) {
        app.installTranslator(&russianTranslator);
    }
    if (app.arguments().contains(QStringLiteral("--download-error"))) {
        mockUpdate.enableDownloadErrorPreview();
    }
    qmlRegisterModule("PageEnum", 1, 0);
    qmlRegisterSingletonType<MockUpdateState>("UpdateState", 1, 0, "UpdateState", createMockUpdateState);
    engine.addImportPath(QStringLiteral(MAYAK_QML_MODULES_DIR));
    engine.rootContext()->setContextProperty(QStringLiteral("PreviewMode"), mode);
    engine.rootContext()->setContextProperty(QStringLiteral("MayakInviteController"), &mockInvite);
    engine.rootContext()->setContextProperty(QStringLiteral("PageController"), &mockPage);
    engine.rootContext()->setContextProperty(QStringLiteral("LanguageUiController"), &mockLanguage);
    engine.rootContext()->setContextProperty(QStringLiteral("UpdateController"), &mockUpdate);
    engine.rootContext()->setContextProperty(QStringLiteral("PreviewPhoneSize"), phone);
    engine.load(QUrl::fromLocalFile(QStringLiteral(MAYAK_PREVIEW_MAIN_QML)));
    if (engine.rootObjects().isEmpty()) return 1;
    return app.exec();
}

#include "main.moc"
