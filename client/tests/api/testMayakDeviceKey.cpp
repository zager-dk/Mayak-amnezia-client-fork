// Изолированный тест ключа устройства: запрос /api/app/device-key, откат на старый сервер, выбор замены при лимите,
// привязка Telegram и замена ключа подписки на месте. Сеть подменена, VPN и сетевые настройки не затрагиваются.
#include <QEventLoop>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QRegularExpression>
#include <QSignalSpy>
#include <QTest>
#include <QTimer>
#include <QUuid>
#include <cstring>

#include "core/controllers/serversController.h"
#include "core/models/api/apiV2ServerConfig.h"
#include "core/repositories/secureAppSettingsRepository.h"
#include "core/repositories/secureServersRepository.h"
#include "core/utils/mayakDeviceIdentity.h"
#include "core/utils/serverConfigUtils.h"
#include "ui/controllers/mayakInviteUiController.h"
#include "secureQSettings.h"

using namespace amnezia;

namespace
{
#ifndef AMNEZIA_TEST_KEYCHAIN_NAME_STR
#error "Device key tests must use isolated credential names"
#endif
    const QString testKeychainService = QStringLiteral(AMNEZIA_TEST_KEYCHAIN_NAME_STR);

    class TestSecureQSettings final : public SecureQSettings
    {
    public:
        using SecureQSettings::SecureQSettings;
        ~TestSecureQSettings() override { clearSettings(); }
    };

    bool waitForKeychainJob(QKeychain::Job &job)
    {
        job.setAutoDelete(false);
        QEventLoop loop;
        QTimer timer;
        timer.setSingleShot(true);
        bool finished = false;
        QObject::connect(&job, &QKeychain::Job::finished, &loop, [&]() { finished = true; loop.quit(); });
        QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
        timer.start(5000);
        job.start();
        loop.exec();
        return finished;
    }

    // Только два имени тестовой сборки (см. test_common), production-имена не трогаются.
    bool removeTestCredentials()
    {
        if (!testKeychainService.startsWith(QStringLiteral("Mayak-Client-Tests-"))) return false;
        for (const auto &tag : {QStringLiteral("settingsKeyTag"), QStringLiteral("settingsIvTag")}) {
            const QString key = testKeychainService + QLatin1Char('/') + tag + QLatin1Char('-')
                                + QString::number(QCoreApplication::applicationPid());
            QKeychain::DeletePasswordJob remove(testKeychainService);
            remove.setKey(key);
            if (!waitForKeychainJob(remove)
                || (remove.error() != QKeychain::NoError && remove.error() != QKeychain::EntryNotFound)) return false;
        }
        return true;
    }

    struct MockHttpResponse { int status; QByteArray body; };

    class MockNetworkReply final : public QNetworkReply
    {
    public:
        MockNetworkReply(const QNetworkRequest &request, QNetworkAccessManager::Operation operation,
                         MockHttpResponse response, QObject *parent)
            : QNetworkReply(parent), m_body(std::move(response.body))
        {
            setRequest(request);
            setUrl(request.url());
            setOperation(operation);
            setAttribute(QNetworkRequest::HttpStatusCodeAttribute, response.status);
            if (response.status >= 400) setError(QNetworkReply::ProtocolInvalidOperationError, QStringLiteral("http error"));
            setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
            open(QIODevice::ReadOnly | QIODevice::Unbuffered);
            QTimer::singleShot(0, this, [this]() { setFinished(true); emit readyRead(); emit finished(); });
        }
        void abort() override {}
        qint64 bytesAvailable() const override { return m_body.size() - m_offset + QNetworkReply::bytesAvailable(); }
    protected:
        qint64 readData(char *data, qint64 maxSize) override
        {
            const qint64 remaining = m_body.size() - m_offset;
            if (remaining <= 0) return -1;
            const qint64 amount = qMin(remaining, maxSize);
            std::memcpy(data, m_body.constData() + m_offset, static_cast<size_t>(amount));
            m_offset += amount;
            return amount;
        }
    private:
        QByteArray m_body;
        qint64 m_offset = 0;
    };

    class MockNetworkAccessManager final : public QNetworkAccessManager
    {
    public:
        struct Call { Operation operation; QUrl url; QByteArray body; QNetworkRequest request; };
        void enqueue(int status, const QByteArray &body) { m_responses.append({status, body}); }
        QList<Call> calls;
    protected:
        QNetworkReply *createRequest(Operation operation, const QNetworkRequest &request, QIODevice *outgoingData) override
        {
            QByteArray outgoing;
            if (outgoingData != nullptr) outgoing = outgoingData->readAll();
            calls.append({operation, request.url(), outgoing, request});
            const MockHttpResponse response = m_responses.isEmpty() ? MockHttpResponse{503, "{}"} : m_responses.takeFirst();
            return new MockNetworkReply(request, operation, response, this);
        }
    private:
        QList<MockHttpResponse> m_responses;
    };

    QByteArray json(const QJsonObject &o) { return QJsonDocument(o).toJson(QJsonDocument::Compact); }

    QByteArray authResponse(const QString &token)
    {
        return json({{"status", "ok"}, {"token", token},
                     {"account", QJsonObject{{"email", "member@example.org"}, {"hasPassword", true}}}});
    }

    QJsonObject bodyOf(const MockNetworkAccessManager::Call &call) { return QJsonDocument::fromJson(call.body).object(); }

    const QUrl apiRoot(QStringLiteral("https://mock.mayak/api/"));
}

class TestMayakDeviceKey : public QObject
{
    Q_OBJECT

    std::unique_ptr<TestSecureQSettings> m_secure;
    std::unique_ptr<SecureAppSettingsRepository> m_settings;

    void freshSettings()
    {
        m_settings.reset();
        m_secure.reset();
        const QString org = QStringLiteral("MayakDeviceKeyTest-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        m_secure = std::make_unique<TestSecureQSettings>(org, QStringLiteral("amnezia-client"), nullptr, true);
        m_settings = std::make_unique<SecureAppSettingsRepository>(m_secure.get());
    }

    // Вход по почте и паролю; ответ на запрос ключа — status/body.
    void login(MayakInviteUiController &controller, MockNetworkAccessManager &network, int keyStatus, const QByteArray &keyBody)
    {
        network.enqueue(200, authResponse(QStringLiteral("session-1")));
        network.enqueue(keyStatus, keyBody);
        controller.login(QStringLiteral("member@example.org"), QStringLiteral("correct horse battery"));
        QTRY_VERIFY_WITH_TIMEOUT(network.calls.size() >= 2 && !controller.busy(), 5000);
    }

private slots:
    void initTestCase() { QVERIFY(removeTestCredentials()); }
    void init() { freshSettings(); }
    void cleanupTestCase()
    {
        m_settings.reset();
        m_secure.reset();
        QVERIFY(removeTestCredentials());
    }

    void deviceHashIsStableAndPrivate()
    {
        const QString a = mayak::device::hashDeviceId(QStringLiteral("abc123"));
        QCOMPARE(a.size(), 64);
        QVERIFY(QRegularExpression(QStringLiteral("^[0-9a-f]{64}$")).match(a).hasMatch());
        QCOMPARE(mayak::device::hashDeviceId(QStringLiteral(" abc123 ")), a);
        QVERIFY(mayak::device::hashDeviceId(QStringLiteral("abc124")) != a);
        QVERIFY(!a.contains(QStringLiteral("abc123")));
        QVERIFY(mayak::device::hashDeviceId(QString()).isEmpty());
        QVERIFY(mayak::device::hashDeviceId(QStringLiteral("9774d56d682e549c")).isEmpty());
        const QString local = mayak::device::stableDeviceHash();
        QVERIFY(local.isEmpty() || local.size() == 64);
        QCOMPARE(mayak::device::stableDeviceHash(), local);
        QVERIFY(!mayak::device::osDescription().isEmpty());
    }

    void requestsKeyForThisInstallation()
    {
        MockNetworkAccessManager network;
        MayakInviteUiController controller(m_settings.get(), nullptr, nullptr, nullptr, &network, apiRoot);
        login(controller, network, 503, "{}");
        QCOMPARE(network.calls.size(), 2);
        const auto &call = network.calls.at(1);
        QCOMPARE(call.operation, QNetworkAccessManager::PostOperation);
        QCOMPARE(call.url.path(), QStringLiteral("/api/app/device-key"));
        QCOMPARE(call.request.rawHeader("Authorization"), QByteArray("Bearer session-1"));
        const QJsonObject body = bodyOf(call);
        QCOMPARE(body.value("installationId").toString(), m_settings->getInstallationUuid(false));
        QVERIFY(!body.value("installationId").toString().isEmpty());
        QVERIFY(!body.value("os").toString().isEmpty());
        QVERIFY(!body.value("appVersion").toString().isEmpty());
        QVERIFY(!body.contains("replaceDeviceId"));
        if (body.contains("deviceHash")) QCOMPARE(body.value("deviceHash").toString().size(), 64);
        QVERIFY(controller.message().contains(QStringLiteral("проверьте соединение")));
        QVERIFY(controller.limitDevices().isEmpty());
    }

    void oldServerFallsBackToAccountKey()
    {
        MockNetworkAccessManager network;
        MayakInviteUiController controller(m_settings.get(), nullptr, nullptr, nullptr, &network, apiRoot);
        network.enqueue(200, authResponse(QStringLiteral("session-1")));
        network.enqueue(404, QByteArray());   // старый сервер: метода нет
        network.enqueue(503, "{}");           // прежний /api/app-key
        controller.login(QStringLiteral("member@example.org"), QStringLiteral("correct horse battery"));
        QTRY_VERIFY_WITH_TIMEOUT(network.calls.size() == 3 && !controller.busy(), 5000);
        QCOMPARE(network.calls.at(2).operation, QNetworkAccessManager::GetOperation);
        QCOMPARE(network.calls.at(2).url.path(), QStringLiteral("/api/app-key"));
    }

    void notFoundWithReasonDoesNotFallBack()
    {
        MockNetworkAccessManager network;
        MayakInviteUiController controller(m_settings.get(), nullptr, nullptr, nullptr, &network, apiRoot);
        login(controller, network, 404, json({{"error", "Устройство для замены не найдено"}}));
        QCOMPARE(network.calls.size(), 2);
        QCOMPARE(controller.message(), QStringLiteral("Устройство для замены не найдено"));
    }

    void deviceLimitOffersReplacement()
    {
        MockNetworkAccessManager network;
        MayakInviteUiController controller(m_settings.get(), nullptr, nullptr, nullptr, &network, apiRoot);
        const QJsonArray devices{
            QJsonObject{{"id", "11111111-1111-1111-1111-111111111111"}, {"name", "Android"}, {"kind", "Android"}, {"os", "android 14"}, {"lastSeen", "2026-11-01T10:00:00Z"}},
            QJsonObject{{"id", "22222222-2222-2222-2222-222222222222"}, {"name", "Компьютер"}, {"kind", "Windows"}, {"os", "windows 11"}, {"lastSeen", "2026-10-20T10:00:00Z"}},
        };
        login(controller, network, 409, json({{"error", "limit"}, {"code", "DEVICE_LIMIT"}, {"maxDevices", 2}, {"devices", devices}}));
        QCOMPARE(controller.limitDevices().size(), 2);
        QCOMPARE(controller.maxDevices(), 2);
        QVERIFY(controller.message().contains(QStringLiteral("Выберите, какое заменить")));

        controller.replaceDevice(QStringLiteral("33333333-3333-3333-3333-333333333333")); // не из списка
        QTest::qWait(50);
        QCOMPARE(network.calls.size(), 2);

        network.enqueue(503, "{}");
        controller.replaceDevice(QStringLiteral("22222222-2222-2222-2222-222222222222"));
        QTRY_VERIFY_WITH_TIMEOUT(network.calls.size() == 3 && !controller.busy(), 5000);
        QCOMPARE(network.calls.at(2).url.path(), QStringLiteral("/api/app/device-key"));
        QCOMPARE(bodyOf(network.calls.at(2)).value("replaceDeviceId").toString(), QStringLiteral("22222222-2222-2222-2222-222222222222"));
    }

    void serverReasonIsShown()
    {
        MockNetworkAccessManager network;
        MayakInviteUiController controller(m_settings.get(), nullptr, nullptr, nullptr, &network, apiRoot);
        login(controller, network, 403, json({{"error", "Устройство отключено. Обратитесь к администратору."}}));
        QCOMPARE(controller.message(), QStringLiteral("Устройство отключено. Обратитесь к администратору."));
        QVERIFY(controller.hasSession());
    }

    void expiredSessionIsCleared()
    {
        MockNetworkAccessManager network;
        MayakInviteUiController controller(m_settings.get(), nullptr, nullptr, nullptr, &network, apiRoot);
        login(controller, network, 401, "{}");
        QVERIFY(!controller.hasSession());
    }

    void telegramLinkOpensOnlyTheBot()
    {
        MockNetworkAccessManager network;
        MayakInviteUiController controller(m_settings.get(), nullptr, nullptr, nullptr, &network, apiRoot);
        login(controller, network, 503, "{}");
        QSignalSpy opened(&controller, &MayakInviteUiController::openExternalUrl);

        network.enqueue(200, json({{"requestId", "abcdefgh12"}, {"botUrl", "https://evil.example/start"}}));
        controller.linkTelegram();
        QTRY_VERIFY_WITH_TIMEOUT(network.calls.size() == 3 && !controller.busy(), 5000);
        QCOMPARE(network.calls.at(2).url.path(), QStringLiteral("/api/auth/telegram/link"));
        QCOMPARE(network.calls.at(2).request.rawHeader("Authorization"), QByteArray("Bearer session-1"));
        QCOMPARE(opened.count(), 0);
        QVERIFY(!controller.telegramLinkPending());

        network.enqueue(200, json({{"requestId", "abcdefgh12"}, {"botUrl", "https://t.me:8443/mayak_bot?start=abcdefgh12"}}));
        controller.linkTelegram();
        QTRY_VERIFY_WITH_TIMEOUT(network.calls.size() == 4 && !controller.busy(), 5000);
        QCOMPARE(opened.count(), 0); // t.me, но с портом — не открываем
        network.enqueue(200, json({{"requestId", "abcdefgh12"}, {"botUrl", "https://t.me/mayak/../evil?start=abcdefgh12"}}));
        controller.linkTelegram();
        QTRY_VERIFY_WITH_TIMEOUT(network.calls.size() == 5 && !controller.busy(), 5000);
        QCOMPARE(opened.count(), 0); // путь не похож на имя бота

        controller.confirmTelegramLink(); // подтверждать нечего — запроса нет
        QTest::qWait(50);
        QCOMPARE(network.calls.size(), 5);

        network.enqueue(200, json({{"requestId", "abcdefgh12"}, {"botUrl", "https://t.me/mayak_bot?start=abcdefgh12"}}));
        network.enqueue(202, json({{"status", "pending"}}));
        network.enqueue(200, json({{"status", "confirm"}, {"telegram", "relative_tg"}, {"telegramId", "900002"}}));
        controller.linkTelegram();
        QTRY_COMPARE_WITH_TIMEOUT(opened.count(), 1, 5000);
        QCOMPARE(opened.at(0).at(0).toString(), QStringLiteral("https://t.me/mayak_bot?start=abcdefgh12"));
        QVERIFY(controller.telegramLinkPending());
        QTRY_COMPARE_WITH_TIMEOUT(controller.telegramConfirmName(), QStringLiteral("@relative_tg"), 15000);
        QVERIFY(!controller.telegramLinked()); // нажатие в боте само по себе ничего не привязывает
        QCOMPARE(network.calls.at(6).url.path(), QStringLiteral("/api/auth/telegram/abcdefgh12"));
        QVERIFY(!network.calls.at(6).request.hasRawHeader("Authorization"));
        const int callsBeforeConfirm = network.calls.size();
        QTest::qWait(5500);
        QCOMPARE(network.calls.size(), callsBeforeConfirm); // опрос остановлен до решения человека

        network.enqueue(200, json({{"status", "linked"}, {"telegram", "relative_tg"}, {"telegramLinked", true}}));
        controller.confirmTelegramLink();
        QTRY_VERIFY_WITH_TIMEOUT(controller.telegramLinked(), 5000);
        const auto &confirm = network.calls.last();
        QCOMPARE(confirm.operation, QNetworkAccessManager::PostOperation);
        QCOMPARE(confirm.url.path(), QStringLiteral("/api/auth/telegram/link/abcdefgh12/confirm"));
        QCOMPARE(confirm.request.rawHeader("Authorization"), QByteArray("Bearer session-1"));
        QCOMPARE(bodyOf(confirm).value("telegramId").toString(), QStringLiteral("900002"));
        QCOMPARE(controller.telegramName(), QStringLiteral("relative_tg"));
        QVERIFY(!controller.telegramLinkPending());
        QVERIFY(controller.telegramConfirmName().isEmpty());
    }

    void telegramLinkedWithoutUsername()
    {
        MockNetworkAccessManager network;
        MayakInviteUiController controller(m_settings.get(), nullptr, nullptr, nullptr, &network, apiRoot);
        network.enqueue(200, json({{"status", "ok"}, {"token", "session-1"},
                                   {"account", QJsonObject{{"email", "member@example.org"}, {"hasPassword", true}, {"telegram", QJsonValue()}, {"telegramLinked", true}}}}));
        network.enqueue(503, "{}");
        controller.login(QStringLiteral("member@example.org"), QStringLiteral("correct horse battery"));
        QTRY_VERIFY_WITH_TIMEOUT(network.calls.size() >= 2 && !controller.busy(), 5000);
        QVERIFY(controller.telegramLinked());
        QVERIFY(controller.telegramName().isEmpty());
    }

    void deviceServerMappingIsOnePerServer()
    {
        QVERIFY(!m_settings->hasMayakDeviceServers());
        m_settings->setMayakServerForDevice(QStringLiteral("device-a"), QStringLiteral("server-1"));
        m_settings->setMayakServerForDevice(QStringLiteral("device-b"), QStringLiteral("server-2"));
        QCOMPARE(m_settings->mayakServerForDevice(QStringLiteral("device-a")), QStringLiteral("server-1"));
        QCOMPARE(m_settings->mayakServerForDevice(QStringLiteral("device-b")), QStringLiteral("server-2"));
        // Подписка server-1 перешла к другому устройству — у device-a записи больше нет.
        m_settings->setMayakServerForDevice(QStringLiteral("device-c"), QStringLiteral("server-1"));
        QVERIFY(m_settings->mayakServerForDevice(QStringLiteral("device-a")).isEmpty());
        QCOMPARE(m_settings->mayakServerForDevice(QStringLiteral("device-c")), QStringLiteral("server-1"));
        QVERIFY(m_settings->mayakServerForDevice(QString()).isEmpty());
        QVERIFY(m_settings->hasMayakDeviceServers());
    }

    void apiKeyIsReplacedInPlace()
    {
        SecureServersRepository repository(m_secure.get());
        ServersController servers(&repository, m_settings.get());
        ApiV2ServerConfig config;
        config.configVersion = serverConfigUtils::ConfigSource::AmneziaGateway;
        config.name = QStringLiteral("Маяк VPN");
        config.apiConfig.serviceType = QStringLiteral("amnezia-premium");
        config.apiConfig.serviceProtocol = QStringLiteral("awg");
        config.apiConfig.userCountryCode = QStringLiteral("ru");
        config.authData.apiKey = QStringLiteral("account-key");
        const QJsonObject jsonConfig = config.toJson();
        const QString id = repository.addServer(QString(), jsonConfig, serverConfigUtils::configTypeFromJson(jsonConfig));
        QVERIFY(!id.isEmpty());
        QVERIFY(!servers.setApiV2AuthKey(id, QString()));
        QVERIFY(servers.setApiV2AuthKey(id, QStringLiteral("md1.device-token")));
        QCOMPARE(repository.serversCount(), 1);
        QCOMPARE(servers.apiV2Config(id)->authData.apiKey, QStringLiteral("md1.device-token"));
        QCOMPARE(servers.apiV2Config(id)->name, QStringLiteral("Маяк VPN"));
        QVERIFY(!servers.setApiV2AuthKey(QStringLiteral("missing"), QStringLiteral("md1.x")));
    }
};

QTEST_MAIN(TestMayakDeviceKey)
#include "testMayakDeviceKey.moc"
