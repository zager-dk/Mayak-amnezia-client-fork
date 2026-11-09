#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QEventLoop>
#include <QNetworkReply>
#include <QPromise>
#include <QSignalSpy>
#include <QProcessEnvironment>
#include <QTest>
#include <QTemporaryDir>
#include <QThreadPool>
#include <QTimer>
#include <QUuid>
#include <cstring>
#include <utility>

#include "utils/testCoreController.h"
#include "core/controllers/api/subscriptionController.h"
#include "core/controllers/serversController.h"
#include "core/models/api/apiV2ServerConfig.h"
#include "core/repositories/secureServersRepository.h"
#include "core/utils/constants/apiKeys.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/serverConfigUtils.h"
#include "ui/controllers/importUiController.h"
#include "ui/controllers/mayakInviteUiController.h"

#include "amneziaApplication.h"
#include "secureQSettings.h"
#include "vpnConnection.h"

using namespace amnezia;

namespace
{
#ifndef AMNEZIA_TEST_KEYCHAIN_NAME_STR
#error "Gateway tests must use isolated credential names"
#endif
    const QString testKeychainService = QStringLiteral(AMNEZIA_TEST_KEYCHAIN_NAME_STR);
    bool standaloneAuthMode = false;
    bool standaloneAuthAssertionsCompleted = false;
    bool standaloneMayakKeyMode = false;
    bool standaloneMayakKeyAssertionsCompleted = false;
    QStringList capturedAuthDiagnostics;
    void captureAuthDiagnostic(QtMsgType, const QMessageLogContext &, const QString &message)
    {
        capturedAuthDiagnostics.append(message);
    }
    QString testCredentialKey(const QString &tag)
    {
        return testKeychainService + QLatin1Char('/') + tag + QLatin1Char('-')
                + QString::number(QCoreApplication::applicationPid());
    }

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

    // Never enumerate credentials or delete a production name. These are the
    // same two build-specific names generated for test_common by CMake.
    bool removeTestCredentials()
    {
        if (!testKeychainService.startsWith(QStringLiteral("Mayak-Client-Tests-"))) return false;
        for (const auto &tag : {QStringLiteral("settingsKeyTag"), QStringLiteral("settingsIvTag")}) {
            const QString key = testCredentialKey(tag);
            QKeychain::DeletePasswordJob remove(testKeychainService);
            remove.setKey(key);
            if (!waitForKeychainJob(remove)
                || (remove.error() != QKeychain::NoError && remove.error() != QKeychain::EntryNotFound)) return false;
            QKeychain::ReadPasswordJob read(testKeychainService);
            read.setKey(key);
            if (!waitForKeychainJob(read) || read.error() != QKeychain::EntryNotFound) return false;
        }
        return true;
    }

    struct MockHttpResponse {
        int status;
        QByteArray body;
        QUrl redirect;
        QNetworkReply::NetworkError networkError = QNetworkReply::NoError;
    };

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
            if (response.networkError != QNetworkReply::NoError) {
                setError(response.networkError, QStringLiteral("mock network failure"));
            }
            if (!response.redirect.isEmpty()) {
                setAttribute(QNetworkRequest::RedirectionTargetAttribute, response.redirect);
                setRawHeader("Location", response.redirect.toEncoded());
            }
            setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
            open(QIODevice::ReadOnly | QIODevice::Unbuffered);
            QTimer::singleShot(0, this, [this]() {
                setFinished(true);
                emit readyRead();
                emit finished();
            });
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
        void enqueue(int status, const QByteArray &body) { m_responses.append({status, body, {}, QNetworkReply::NoError}); }
        void enqueueRedirect(const QUrl &url) { m_responses.append({302, {}, url, QNetworkReply::NoError}); }
        void enqueueNetworkError(QNetworkReply::NetworkError error) { m_responses.append({0, {}, {}, error}); }
        QList<Call> calls;
    protected:
        QNetworkReply *createRequest(Operation operation, const QNetworkRequest &request, QIODevice *outgoingData) override
        {
            QByteArray outgoing;
            if (outgoingData != nullptr) outgoing = outgoingData->readAll();
            calls.append({operation, request.url(), outgoing, request});
            Q_ASSERT(!m_responses.isEmpty());
            return new MockNetworkReply(request, operation, m_responses.takeFirst(), this);
        }
    private:
        QList<MockHttpResponse> m_responses;
    };

    class MockMayakProvisioner final : public MayakSubscriptionProvisioner
    {
    public:
        using MayakSubscriptionProvisioner::MayakSubscriptionProvisioner;
        struct Pending { QString serverId; IsCurrent isCurrent; Completion completion; };
        QList<Pending> pending;
        void provision(const QString &serverId, IsCurrent isCurrent, Completion completion) override
        { pending.append({serverId, std::move(isCurrent), std::move(completion)}); }
        void completeNext(ErrorCode error) { auto item = pending.takeFirst(); item.completion(error); }
    };

    QString mockMayakSubscriptionKey(const QString &apiKey = QStringLiteral("mock-mayak-api-key"))
    {
        ApiV2ServerConfig config;
        config.configVersion = serverConfigUtils::ConfigSource::AmneziaGateway;
        config.name = QStringLiteral("Mayak VPN");
        config.apiConfig.serviceType = QStringLiteral("amnezia-premium");
        config.apiConfig.serviceProtocol = QStringLiteral("awg");
        config.apiConfig.userCountryCode = QStringLiteral("ru");
        config.apiConfig.vpnKey = QStringLiteral("vpn://mock");
        config.authData.apiKey = apiKey;
        return QStringLiteral("vpn://") + QString::fromUtf8(QJsonDocument(config.toJson()).toJson(QJsonDocument::Compact)
                    .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
    }

    QByteArray authResponse(const QString &token, bool hasPassword = true)
    {
        const QJsonObject account{{QStringLiteral("email"), hasPassword ? QJsonValue(QStringLiteral("member@example.org")) : QJsonValue(QJsonValue::Null)},
                                  {QStringLiteral("hasPassword"), hasPassword}};
        return QJsonDocument(QJsonObject{{QStringLiteral("status"), QStringLiteral("ok")},
                                         {QStringLiteral("token"), token},
                                         {QStringLiteral("account"), account}}).toJson(QJsonDocument::Compact);
    }

    QByteArray appKeyResponse(const QString &apiKey = QStringLiteral("mock-mayak-api-key"))
    {
        return QJsonDocument(QJsonObject{{QStringLiteral("key"), mockMayakSubscriptionKey(apiKey)}}).toJson(QJsonDocument::Compact);
    }
    constexpr const char *privateKeyPlaceholder = "$WIREGUARD_CLIENT_PRIVATE_KEY";

    QJsonObject awgContainer(const QString &clientPrivKeyValue)
    {
        QJsonObject lastConfig;
        lastConfig[configKey::hostName] = QStringLiteral("10.0.0.1");
        lastConfig[configKey::clientPrivKey] = clientPrivKeyValue;
        lastConfig[configKey::persistentKeepAlive] = QStringLiteral("25-35");

        QJsonObject awgConfig;
        awgConfig[configKey::lastConfig] = QString(QJsonDocument(lastConfig).toJson(QJsonDocument::Compact));
        awgConfig[configKey::port] = QStringLiteral("35333");

        QJsonObject container;
        container[configKey::container] = QStringLiteral("amnezia-awg");
        container[QString(configKey::awg)] = awgConfig;
        return container;
    }

    QJsonObject gatewayAwg2Allocation(const QString &privateKey, const QString &publicKey,
                                      const QString &host = QStringLiteral("81.29.149.103"), int port = 51820,
                                      const QString &containerName = QStringLiteral("amnezia-awg2"),
                                      const QString &rootHost = {})
    {
        const QString nativeConfig = QStringLiteral(
                "[Interface]\nAddress = 10.8.1.2/32\nDNS = 1.1.1.1, 1.0.0.1\n"
                "PrivateKey = $WIREGUARD_CLIENT_PRIVATE_KEY\nJc = 4\nJmin = 40\nJmax = 70\n"
                "S1 = 15\nS2 = 20\nS3 = 4\nS4 = 8\nH1 = 100000-100100\nH2 = 200000-200100\n"
                "H3 = 300000-300100\nH4 = 400000-400100\n\n[Peer]\n"
                "PublicKey = REVIEW_SERVER_PUBLIC_KEY\nPresharedKey = REVIEW_PSK\n"
                "AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %1:%2\nPersistentKeepalive = 25\n")
                .arg(host).arg(port);
        QJsonObject lastConfig{{configKey::clientPrivKey, privateKey}, {configKey::hostName, host},
                               {configKey::port, port}, {configKey::config, nativeConfig},
                               {configKey::clientIp, QStringLiteral("10.8.1.2")},
                               {configKey::clientPubKey, publicKey}, {QStringLiteral("clientId"), publicKey},
                               {configKey::serverPubKey, QStringLiteral("REVIEW_SERVER_PUBLIC_KEY")},
                               {configKey::pskKey, QStringLiteral("REVIEW_PSK")},
                               {configKey::allowedIps, QJsonArray{QStringLiteral("0.0.0.0/0"), QStringLiteral("::/0")}},
                               {configKey::persistentKeepAlive, QStringLiteral("25")},
                               {configKey::mtu, QStringLiteral("1280")}};
        QJsonObject awg{{configKey::lastConfig, QString::fromUtf8(QJsonDocument(lastConfig).toJson(QJsonDocument::Compact))},
                        {configKey::port, QString::number(port)},
                        {QStringLiteral("transport_proto"), QStringLiteral("udp")},
                        {configKey::protocolVersion, QStringLiteral("2")},
                        {configKey::subnetAddress, QStringLiteral("10.8.1.0")},
                        {configKey::subnetCidr, QStringLiteral("24")},
                        {configKey::junkPacketCount, QStringLiteral("4")},
                        {configKey::junkPacketMinSize, QStringLiteral("40")},
                        {configKey::junkPacketMaxSize, QStringLiteral("70")},
                        {configKey::initPacketJunkSize, QStringLiteral("15")},
                        {configKey::responsePacketJunkSize, QStringLiteral("20")},
                        {configKey::cookieReplyPacketJunkSize, QStringLiteral("4")},
                        {configKey::transportPacketJunkSize, QStringLiteral("8")},
                        {configKey::initPacketMagicHeader, QStringLiteral("100000-100100")},
                        {configKey::responsePacketMagicHeader, QStringLiteral("200000-200100")},
                        {configKey::underloadPacketMagicHeader, QStringLiteral("300000-300100")},
                        {configKey::transportPacketMagicHeader, QStringLiteral("400000-400100")}};
        QJsonObject container{{configKey::container, containerName},
                              {QString(configKey::awg), awg}};
        QJsonObject apiConfig{{apiDefs::key::serviceType, QStringLiteral("amnezia-premium")},
                              {apiDefs::key::serviceProtocol, QString(configKey::awg)}};
        QJsonObject authData{{apiDefs::key::apiKey, QStringLiteral("factory-api-identity")}};
        QJsonObject config{{configKey::configVersion, 2}, {configKey::formatVersion, serverConfigUtils::currentConfigFormatVersion},
                           {configKey::name, QStringLiteral("Mayak AWG2")},
                           {configKey::hostName, rootHost.isEmpty() ? host : rootHost}, {configKey::defaultContainer, containerName},
                           {configKey::containers, QJsonArray{container}},
                           {apiDefs::key::apiConfig, apiConfig}, {QStringLiteral("auth_data"), authData}};
        return config;
    }

    QJsonObject gatewayServerConfig(int configVersion = serverConfigUtils::ConfigSource::AmneziaGateway,
                                    int formatVersion = serverConfigUtils::currentConfigFormatVersion)
    {
        QJsonObject config;
        config[configKey::name] = QStringLiteral("Amnezia Premium");
        config[configKey::description] = QStringLiteral("Premium service");
        config[configKey::hostName] = QStringLiteral("gateway.example.org");
        config[configKey::configVersion] = configVersion;
        config[configKey::formatVersion] = formatVersion;
        config[configKey::defaultContainer] = QStringLiteral("amnezia-awg");
        config[configKey::containers] = QJsonArray { awgContainer(QString::fromLatin1(privateKeyPlaceholder)) };
        return config;
    }

    QJsonObject updatedGatewayServerConfig()
    {
        QJsonObject config = gatewayServerConfig();
        config[configKey::name] = QStringLiteral("Amnezia Premium Updated");
        config[configKey::hostName] = QStringLiteral("gateway-updated.example.org");
        return config;
    }

    // Mirrors how the gateway ships a config in the `config` field of its v1/config response.
    QByteArray gatewayResponse(const QJsonObject &serverConfig, bool withServiceInfo = true)
    {
        const QByteArray payload = qCompress(QJsonDocument(serverConfig).toJson(QJsonDocument::Compact));

        QJsonObject response;
        response[apiDefs::key::config] =
                QStringLiteral("vpn://") + QString::fromUtf8(payload.toBase64(QByteArray::Base64UrlEncoding
                                                                              | QByteArray::OmitTrailingEquals));
        if (withServiceInfo) {
            QJsonObject serviceInfo;
            serviceInfo[apiDefs::key::isAdVisible] = true;
            serviceInfo[apiDefs::key::adHeader] = QStringLiteral("Promo header");
            response[apiDefs::key::serviceInfo] = serviceInfo;
        }
        return QJsonDocument(response).toJson(QJsonDocument::Compact);
    }

    // Populated from GitHub Secrets in CI; empty locally and on fork PRs.
    QString envValue(const char *name)
    {
        return QProcessEnvironment::systemEnvironment().value(QString::fromLatin1(name)).trimmed();
    }

    SubscriptionController::ProtocolData awgProtocolData()
    {
        SubscriptionController::ProtocolData data;
        data.wireGuardClientPrivKey = QStringLiteral("cHJpdmF0ZS1rZXktZm9yLXRlc3Q=");
        data.wireGuardClientPubKey = QStringLiteral("cHVibGljLWtleS1mb3ItdGVzdA==");
        return data;
    }
} // namespace

class TestGatewayServiceImport : public QObject
{
    Q_OBJECT

private:
    TestCoreController *m_coreController = nullptr;
    SecureQSettings *m_settings = nullptr;
    QString m_liveGatewayEndpoint;
    const QString m_offlineGatewayEndpoint = QStringLiteral("https://127.0.0.1:1/");

    QJsonObject storedServer() const
    {
        if (m_coreController->m_serversRepository->serversCount() == 0) {
            return QJsonObject {};
        }
        const QString serverId = m_coreController->m_serversRepository->serverIdAt(0);
        const auto config = m_coreController->m_serversRepository->apiV2Config(serverId);
        return config ? config->toJson() : QJsonObject {};
    }

    static ApiV2ServerConfig storedSubscription()
    {
        ApiV2ServerConfig seed = ApiV2ServerConfig::fromJson(gatewayServerConfig());
        seed.apiConfig.serviceType = QStringLiteral("amnezia-premium");
        seed.apiConfig.serviceProtocol = QString(configKey::awg);
        seed.apiConfig.userCountryCode = QStringLiteral("NL");
        seed.apiConfig.vpnKey = QStringLiteral("vpn://stored-key");
        seed.authData.apiKey = QStringLiteral("stored-api-key");
        seed.crc = 42;
        return seed;
    }

    QString addStoredServer(const ApiV2ServerConfig &config)
    {
        const QJsonObject json = config.toJson();
        return m_coreController->m_serversRepository->addServer(QString(), json, serverConfigUtils::configTypeFromJson(json));
    }

    ErrorCode applyUpdate(const QString &serverId, const QByteArray &response)
    {
        return m_coreController->m_subscriptionController->applyUpdatedServiceConfigForTest(serverId, configKey::awg,
                                                                                             awgProtocolData(), response);
    }

private slots:
    void initTestCase()
    {
        if (standaloneAuthMode || standaloneMayakKeyMode) return;
        const QString testOrg = "AmneziaVPN-Test-" + QUuid::createUuid().toString();
        m_settings = new SecureQSettings(testOrg, "amnezia-client", nullptr, false);
        SecureAppSettingsRepository initialSettings(m_settings);
        m_liveGatewayEndpoint = initialSettings.getGatewayEndpoint();
        // Import/update signals can fetch news in the background. Rust gateway
        // networking bypasses our Qt mock, so point it at loopback before Core.
        initialSettings.setGatewayEndpoint(m_offlineGatewayEndpoint);
        auto vpnConnection = QSharedPointer<VpnConnection>::create(nullptr, nullptr);
        m_coreController = new TestCoreController(vpnConnection, m_settings, nullptr, this);
    }

    void cleanupTestCase()
    {
        if (standaloneAuthMode || standaloneMayakKeyMode) {
            QVERIFY2(removeTestCredentials(), "Failed to remove the isolated auth-test credential names");
            return;
        }
        m_settings->clearSettings();
        QTRY_VERIFY_WITH_TIMEOUT(QThreadPool::globalInstance()->activeThreadCount() == 0, 60000);
        delete m_coreController;
        delete m_settings;
        QVERIFY2(removeTestCredentials(), "Failed to remove and verify only the two isolated test credentials");
    }

    void init()
    {
        if (standaloneAuthMode || standaloneMayakKeyMode) {
            if (standaloneAuthMode && QByteArray(QTest::currentTestFunction()) != QByteArrayLiteral("standaloneAuthControllerAssertions"))
                QSKIP("Only the isolated auth controller assertion is selected in this mode");
            if (standaloneMayakKeyMode && QByteArray(QTest::currentTestFunction()) != QByteArrayLiteral("standaloneMayakKeyBootstrapAssertions"))
                QSKIP("Only the isolated Mayak key bootstrap assertion is selected in this mode");
            return;
        }
        m_settings->clearSettings();
        m_coreController->m_appSettingsRepository->setGatewayEndpoint(m_offlineGatewayEndpoint);
        QCOMPARE(m_coreController->m_appSettingsRepository->getGatewayEndpoint(), m_offlineGatewayEndpoint);
        m_coreController->m_serversRepository->clearServers();
        m_coreController->m_serversModel->updateModel(QVector<ServerDescription>(), QString {});
    }

    void standaloneAuthControllerAssertions()
    {
        const QString org = QStringLiteral("MayakAuthStandalone-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        TestSecureQSettings secureSettings(org, QStringLiteral("amnezia-client"), nullptr, true);
        SecureAppSettingsRepository appSettings(&secureSettings);
        MockNetworkAccessManager network;
        network.enqueue(200, authResponse(QStringLiteral("register-session")));
        network.enqueue(503, QByteArrayLiteral("{}")); // app-key down after bearer persistence
        network.enqueue(401, QByteArrayLiteral("{\"error\":\"invalid credentials\"}"));
        network.enqueue(200, authResponse(QStringLiteral("login-session")));
        network.enqueue(503, QByteArrayLiteral("{}"));
        network.enqueue(200, authResponse(QStringLiteral("bound-session")));
        network.enqueue(503, QByteArrayLiteral("{}"));
        MayakInviteUiController controller(&appSettings, nullptr, nullptr, nullptr, &network,
                                           QUrl(QStringLiteral("https://mock.mayak/api/")));

        controller.registerAccount(QStringLiteral("https://mayaklight.ru/my/?invite=abc_DEF-012"),
                                   QStringLiteral("member@example.org"), QStringLiteral("correct horse battery"));
        QTRY_VERIFY_WITH_TIMEOUT(!controller.busy(), 5000);
        QCOMPARE(network.calls.size(), 2);
        QCOMPARE(network.calls.at(0).url.path(), QStringLiteral("/api/auth/register"));
        QCOMPARE(QJsonDocument::fromJson(network.calls.at(0).body).object().value(QStringLiteral("invite")).toString(),
                 QStringLiteral("abc_DEF-012"));
        QCOMPARE(network.calls.at(1).url.path(), QStringLiteral("/api/app-key"));
        QCOMPARE(appSettings.mayakSessionToken(), QStringLiteral("register-session"));
        QVERIFY(controller.accountMetadataKnown());
        QVERIFY(controller.accountHasPassword());
        QCOMPARE(controller.accountEmail(), QStringLiteral("member@example.org"));

        controller.login(QStringLiteral("member@example.org"), QStringLiteral("incorrect password"));
        QTRY_VERIFY_WITH_TIMEOUT(!controller.busy(), 5000);
        QCOMPARE(appSettings.mayakSessionToken(), QStringLiteral("register-session"));
        QCOMPARE(network.calls.at(2).url.path(), QStringLiteral("/api/auth/login"));

        MockNetworkAccessManager diagnosticNetwork;
        diagnosticNetwork.enqueue(503, QByteArrayLiteral("payload-secret-marker"));
        MayakInviteUiController diagnosticController(&appSettings, nullptr, nullptr, nullptr, &diagnosticNetwork,
                                                      QUrl(QStringLiteral("https://mock.mayak/api/")));
        capturedAuthDiagnostics.clear();
        struct MessageHandlerGuard {
            QtMessageHandler previous;
            ~MessageHandlerGuard() { qInstallMessageHandler(previous); }
        } messageHandlerGuard{qInstallMessageHandler(captureAuthDiagnostic)};
        diagnosticController.login(QStringLiteral("email-secret-marker@example.org"), QStringLiteral("password-secret-marker"));
        QTRY_VERIFY_WITH_TIMEOUT(!diagnosticController.busy(), 5000);
        QCOMPARE(capturedAuthDiagnostics.size(), 1);
        const QString diagnostic = capturedAuthDiagnostics.constFirst();
        QVERIFY(diagnostic.contains(QStringLiteral("MayakAuthFailure network_error=0 http_status=503 response_bytes=21")));
        QVERIFY(diagnostic.contains(QStringLiteral("tls_supported=")));
        QVERIFY(diagnostic.contains(QStringLiteral("tls_runtime=")));
        QVERIFY(!diagnostic.contains(QStringLiteral("payload-secret-marker")));
        QVERIFY(!diagnostic.contains(QStringLiteral("email-secret-marker")));
        QVERIFY(!diagnostic.contains(QStringLiteral("password-secret-marker")));

        controller.login(QStringLiteral("member@example.org"), QStringLiteral("correct horse battery"));
        QTRY_VERIFY_WITH_TIMEOUT(!controller.busy(), 5000);
        QCOMPARE(appSettings.mayakSessionToken(), QStringLiteral("login-session"));
        QVERIFY(controller.accountMetadataKnown());
        QVERIFY(controller.accountHasPassword());
        QCOMPARE(controller.accountEmail(), QStringLiteral("member@example.org"));
        QCOMPARE(network.calls.at(3).url.path(), QStringLiteral("/api/auth/login"));
        QCOMPARE(network.calls.at(4).url.path(), QStringLiteral("/api/app-key"));

        controller.bindCredentials(QStringLiteral("member@example.org"), QStringLiteral("correct horse battery"));
        QTRY_VERIFY_WITH_TIMEOUT(!controller.busy(), 5000);
        QCOMPARE(network.calls.at(5).url.path(), QStringLiteral("/api/auth/credentials"));
        QCOMPARE(network.calls.at(5).request.rawHeader("Authorization"), QByteArrayLiteral("Bearer login-session"));
        QCOMPARE(appSettings.mayakSessionToken(), QStringLiteral("bound-session"));
        QVERIFY(controller.accountMetadataKnown());
        QVERIFY(controller.accountHasPassword());
        QCOMPARE(controller.accountEmail(), QStringLiteral("member@example.org"));

        const QString metadataOrg = QStringLiteral("MayakAuthMetadataStandalone-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        TestSecureQSettings metadataSecureSettings(metadataOrg, QStringLiteral("amnezia-client"), nullptr, true);
        SecureAppSettingsRepository metadataSettings(&metadataSecureSettings);
        QVERIFY(metadataSettings.setMayakSessionToken(QStringLiteral("saved-session")));
        MockNetworkAccessManager metadataNetwork;
        metadataNetwork.enqueue(200, QJsonDocument(QJsonObject{
            {QStringLiteral("account"), QJsonObject{
                {QStringLiteral("email"), QStringLiteral("saved@example.org")},
                {QStringLiteral("hasPassword"), true}
            }}
        }).toJson(QJsonDocument::Compact));
        MayakInviteUiController metadataController(&metadataSettings, nullptr, nullptr, nullptr, &metadataNetwork,
                                                   QUrl(QStringLiteral("https://mock.mayak/api/")));
        metadataController.refreshAccount();
        QVERIFY(metadataController.busy());
        QVERIFY(!metadataController.accountMetadataKnown());
        QTRY_VERIFY_WITH_TIMEOUT(!metadataController.busy(), 5000);
        QCOMPARE(metadataNetwork.calls.size(), 1);
        QCOMPARE(metadataNetwork.calls.at(0).operation, QNetworkAccessManager::GetOperation);
        QCOMPARE(metadataNetwork.calls.at(0).url.path(), QStringLiteral("/api/me"));
        QCOMPARE(metadataNetwork.calls.at(0).request.rawHeader("Authorization"), QByteArrayLiteral("Bearer saved-session"));
        QVERIFY(metadataController.accountMetadataKnown());
        QVERIFY(metadataController.accountHasPassword());
        QCOMPARE(metadataController.accountEmail(), QStringLiteral("saved@example.org"));

        const QString expiryOrg = QStringLiteral("MayakAuthExpiryStandalone-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        TestSecureQSettings expirySecureSettings(expiryOrg, QStringLiteral("amnezia-client"), nullptr, true);
        SecureAppSettingsRepository expirySettings(&expirySecureSettings);
        QVERIFY(expirySettings.setMayakSessionToken(QStringLiteral("expired-session")));
        MockNetworkAccessManager expiryNetwork;
        expiryNetwork.enqueue(401, QByteArrayLiteral("{\"error\":\"expired\"}"));
        expiryNetwork.enqueue(200, authResponse(QStringLiteral("fresh-login-session")));
        expiryNetwork.enqueue(503, QByteArrayLiteral("{}"));
        MayakInviteUiController expiredSession(&expirySettings, nullptr, nullptr, nullptr, &expiryNetwork,
                                               QUrl(QStringLiteral("https://mock.mayak/api/")));
        expiredSession.retrySetup();
        QTRY_VERIFY_WITH_TIMEOUT(!expiredSession.busy(), 5000);
        QCOMPARE(expiryNetwork.calls.size(), 1);
        QCOMPARE(expiryNetwork.calls.at(0).operation, QNetworkAccessManager::GetOperation);
        QCOMPARE(expiryNetwork.calls.at(0).url.path(), QStringLiteral("/api/app-key"));
        QVERIFY(expirySettings.mayakSessionToken().isEmpty());
        QVERIFY(!expiredSession.accountMetadataKnown());
        QVERIFY(!expiredSession.requiresFreshInvite());
        QVERIFY(expiredSession.message().contains(QStringLiteral("Войдите по адресу почты"), Qt::CaseInsensitive));
        expiredSession.login(QStringLiteral("member@example.org"), QStringLiteral("correct horse battery"));
        QTRY_VERIFY_WITH_TIMEOUT(!expiredSession.busy(), 5000);
        QCOMPARE(expiryNetwork.calls.at(1).url.path(), QStringLiteral("/api/auth/login"));
        QCOMPARE(expiryNetwork.calls.at(2).url.path(), QStringLiteral("/api/app-key"));
        QCOMPARE(expirySettings.mayakSessionToken(), QStringLiteral("fresh-login-session"));

        const QString staleOrg = QStringLiteral("MayakAuthStaleProvisionStandalone-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        TestSecureQSettings staleSecureSettings(staleOrg, QStringLiteral("amnezia-client"), nullptr, true);
        SecureAppSettingsRepository staleAppSettings(&staleSecureSettings);
        SecureServersRepository staleServersRepository(&staleSecureSettings);
        ServersController staleServersController(&staleServersRepository, &staleAppSettings);
        SubscriptionController staleSubscriptionController(&staleServersRepository, &staleAppSettings);
        ImportController staleImportCore(&staleServersRepository, &staleAppSettings);
        ImportUiController staleImporter(&staleImportCore);
        QVERIFY(staleImporter.extractConfigFromData(mockMayakSubscriptionKey(QStringLiteral("session-a-key"))));
        staleImporter.importConfig();
        QCOMPARE(staleServersRepository.serversCount(), 1);
        const QString serverA = staleServersController.getServerId(0);
        staleServersController.setDefaultServer(serverA);
        const QJsonObject serverABefore = staleServersRepository.serverJsonById(serverA).value();

        using GatewayResult = SubscriptionController::GatewayConfigResult;
        QList<QSharedPointer<QPromise<GatewayResult>>> pendingGatewayResults;
        GatewayMayakProvisioner realProvisioner(&staleSubscriptionController, &staleServersController, nullptr,
                [&pendingGatewayResults](const QString &) {
            auto promise = QSharedPointer<QPromise<GatewayResult>>::create();
            promise->start();
            QFuture<GatewayResult> future = promise->future();
            pendingGatewayResults.append(promise);
            return future;
        });
        MockNetworkAccessManager staleNetwork;
        staleNetwork.enqueue(200, authResponse(QStringLiteral("session-a")));
        staleNetwork.enqueue(200, appKeyResponse(QStringLiteral("session-a-key")));
        staleNetwork.enqueue(204, QByteArray());
        staleNetwork.enqueue(200, authResponse(QStringLiteral("session-b")));
        staleNetwork.enqueue(200, appKeyResponse(QStringLiteral("session-b-key")));
        MayakInviteUiController staleController(&staleAppSettings, &staleImporter, &staleServersController,
                                                &realProvisioner, &staleNetwork,
                                                QUrl(QStringLiteral("https://mock.mayak/api/")));
        staleController.login(QStringLiteral("a@example.org"), QStringLiteral("correct horse battery"));
        QTRY_COMPARE_WITH_TIMEOUT(pendingGatewayResults.size(), 1, 5000);
        QCOMPARE(pendingGatewayResults.size(), 1); // generation A has started its real apply-capable provisioner
        staleController.logout();
        staleController.login(QStringLiteral("b@example.org"), QStringLiteral("correct horse battery"));
        QTRY_COMPARE_WITH_TIMEOUT(pendingGatewayResults.size(), 2, 5000);
        QCOMPARE(staleServersRepository.serversCount(), 2);
        const QString serverB = staleServersController.getServerId(1);
        QVERIFY(serverB != serverA);

        GatewayResult currentResult;
        currentResult.error = ErrorCode::NoError;
        currentResult.serverId = serverB;
        currentResult.serviceProtocol = QStringLiteral("awg");
        currentResult.protocolData = SubscriptionController::generateProtocolData(currentResult.serviceProtocol);
        currentResult.responseBody = gatewayResponse(updatedGatewayServerConfig());
        pendingGatewayResults.at(1)->addResult(currentResult);
        pendingGatewayResults.at(1)->finish();
        QTRY_VERIFY_WITH_TIMEOUT(!staleController.busy(), 5000);
        QCOMPARE(staleServersRepository.defaultServerId(), serverB);

        GatewayResult staleResult;
        staleResult.error = ErrorCode::NoError;
        staleResult.serverId = serverA;
        staleResult.serviceProtocol = QStringLiteral("awg");
        staleResult.protocolData = SubscriptionController::generateProtocolData(staleResult.serviceProtocol);
        QJsonObject staleConfig = updatedGatewayServerConfig();
        staleConfig[configKey::hostName] = QStringLiteral("stale-session-a.example.org");
        staleResult.responseBody = gatewayResponse(staleConfig);
        pendingGatewayResults.at(0)->addResult(staleResult);
        pendingGatewayResults.at(0)->finish();
        QTest::qWait(100);
        QCOMPARE(staleServersRepository.defaultServerId(), serverB);
        QCOMPARE(staleServersRepository.serverJsonById(serverA).value(), serverABefore);
        QCOMPARE(staleServersRepository.serverJsonById(serverB).value().value(configKey::hostName).toString(),
                 QStringLiteral("gateway-updated.example.org"));

        const int callsBeforeRejectedInvite = network.calls.size();
        controller.registerAccount(QStringLiteral("https://evil.invalid/my/?invite=token"),
                                   QStringLiteral("member@example.org"), QStringLiteral("correct horse battery"));
        QCOMPARE(network.calls.size(), callsBeforeRejectedInvite);
        QVERIFY(controller.message().contains(QStringLiteral("действительную ссылку"), Qt::CaseInsensitive));

        const QString cancelOrg = QStringLiteral("MayakAuthCancelStandalone-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        TestSecureQSettings cancelSecureSettings(cancelOrg, QStringLiteral("amnezia-client"), nullptr, true);
        SecureAppSettingsRepository cancelSettings(&cancelSecureSettings);
        MockNetworkAccessManager delayedNetwork;
        delayedNetwork.enqueue(200, authResponse(QStringLiteral("late-session")));
        MayakInviteUiController cancelled(&cancelSettings, nullptr, nullptr, nullptr, &delayedNetwork,
                                          QUrl(QStringLiteral("https://mock.mayak/api/")));
        cancelled.login(QStringLiteral("member@example.org"), QStringLiteral("correct horse battery"));
        cancelled.cancelPendingRequests();
        QTest::qWait(50); // Mock abort deliberately leaves its scheduled finished event in flight.
        QVERIFY(!cancelled.busy());
        QVERIFY(cancelSettings.mayakSessionToken().isEmpty());
        QVERIFY(cancelled.message().contains(QStringLiteral("отменена"), Qt::CaseInsensitive));
        QCOMPARE(delayedNetwork.calls.size(), 1);

        const QString provisionOrg = QStringLiteral("MayakAuthProvisionStandalone-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        TestSecureQSettings provisionSecureSettings(provisionOrg, QStringLiteral("amnezia-client"), nullptr, true);
        SecureAppSettingsRepository provisionSettings(&provisionSecureSettings);
        SecureServersRepository serversRepository(&provisionSecureSettings);
        ServersController serversController(&serversRepository, &provisionSettings);
        ImportController importCore(&serversRepository, &provisionSettings);
        ImportUiController importer(&importCore);
        MockMayakProvisioner provisioner;
        MockNetworkAccessManager provisionNetwork;
        provisionNetwork.enqueue(200, authResponse(QStringLiteral("onboarding-session")));
        provisionNetwork.enqueue(200, appKeyResponse());
        provisionNetwork.enqueue(200, appKeyResponse());
        provisionNetwork.enqueue(204, QByteArray()); // API logout revokes this bearer with no content
        provisionNetwork.enqueue(200, authResponse(QStringLiteral("relogin-session")));
        provisionNetwork.enqueue(200, appKeyResponse());
        MayakInviteUiController onboarding(&provisionSettings, &importer, &serversController, &provisioner,
                                           &provisionNetwork, QUrl(QStringLiteral("https://mock.mayak/api/")));
        onboarding.login(QStringLiteral("member@example.org"), QStringLiteral("correct horse battery"));
        QTRY_COMPARE_WITH_TIMEOUT(provisioner.pending.size(), 1, 5000);
        QCOMPARE(serversRepository.serversCount(), 1);
        const QString installationId = provisionSettings.getInstallationUuid(true);
        QCOMPARE(provisionSettings.mayakSessionToken(), QStringLiteral("onboarding-session"));
        provisioner.completeNext(ErrorCode::NoError);
        QTRY_VERIFY_WITH_TIMEOUT(!onboarding.busy(), 5000);
        QCOMPARE(provisionSettings.mayakSessionToken(), QStringLiteral("onboarding-session"));

        onboarding.retrySetup();
        QTRY_COMPARE_WITH_TIMEOUT(provisioner.pending.size(), 1, 5000);
        QCOMPARE(serversRepository.serversCount(), 1); // app-key reuses the existing API-key subscription
        QCOMPARE(provisionSettings.getInstallationUuid(true), installationId);
        provisioner.completeNext(ErrorCode::NoError);
        QTRY_VERIFY_WITH_TIMEOUT(!onboarding.busy(), 5000);
        QCOMPARE(provisionSettings.mayakSessionToken(), QStringLiteral("onboarding-session"));

        onboarding.logout();
        QVERIFY(provisionSettings.mayakSessionToken().isEmpty());
        QTRY_COMPARE_WITH_TIMEOUT(provisionNetwork.calls.size(), 4, 5000);
        QCOMPARE(provisionNetwork.calls.at(3).operation, QNetworkAccessManager::PostOperation);
        QCOMPARE(provisionNetwork.calls.at(3).url.path(), QStringLiteral("/api/logout"));
        QCOMPARE(provisionNetwork.calls.at(3).request.rawHeader("Authorization"), QByteArrayLiteral("Bearer onboarding-session"));
        onboarding.login(QStringLiteral("member@example.org"), QStringLiteral("correct horse battery"));
        QTRY_COMPARE_WITH_TIMEOUT(provisioner.pending.size(), 1, 5000);
        QCOMPARE(serversRepository.serversCount(), 1);
        QCOMPARE(provisionNetwork.calls.at(4).url.path(), QStringLiteral("/api/auth/login"));
        QCOMPARE(provisionNetwork.calls.at(5).url.path(), QStringLiteral("/api/app-key"));
        provisioner.completeNext(ErrorCode::NoError);
        QTRY_VERIFY_WITH_TIMEOUT(!onboarding.busy(), 5000);
        QCOMPARE(provisionSettings.mayakSessionToken(), QStringLiteral("relogin-session"));
        QCOMPARE(serversRepository.serversCount(), 1);

        provisionNetwork.enqueueNetworkError(QNetworkReply::RemoteHostClosedError);
        onboarding.logout();
        QVERIFY(provisionSettings.mayakSessionToken().isEmpty()); // local logout completes even if revocation cannot reach the API
        QTRY_COMPARE_WITH_TIMEOUT(provisionNetwork.calls.size(), 7, 5000);
        QTest::qWait(50);
        QCOMPARE(provisionNetwork.calls.at(6).operation, QNetworkAccessManager::PostOperation);
        QCOMPARE(provisionNetwork.calls.at(6).url.path(), QStringLiteral("/api/logout"));
        QCOMPARE(provisionNetwork.calls.at(6).request.rawHeader("Authorization"), QByteArrayLiteral("Bearer relogin-session"));
        standaloneAuthAssertionsCompleted = true;
    }

    void standaloneMayakKeyBootstrapAssertions()
    {
        const auto createShell = [] {
            ApiV2ServerConfig shell;
            shell.configVersion = serverConfigUtils::ConfigSource::AmneziaGateway;
            shell.name = QStringLiteral("Mayak bootstrap shell");
            shell.apiConfig.serviceType = QStringLiteral("amnezia-premium");
            shell.apiConfig.serviceProtocol = QString(configKey::awg);
            shell.apiConfig.vpnKey = QStringLiteral("vpn://bootstrap-shell");
            shell.containers.clear();
            return shell;
        };
        const auto keyOnlyContainer = [](const SubscriptionController::ProtocolData &keys, int oldPort) {
            ContainerConfig container;
            container.container = DockerContainer::Awg;
            AwgProtocolConfig protocol;
            AwgClientConfig client;
            client.clientPrivateKey = keys.wireGuardClientPrivKey;
            client.clientPublicKey = keys.wireGuardClientPubKey;
            client.port = oldPort; // old builds could serialize an uninitialized value here
            protocol.setClientConfig(client);
            container.protocolConfig = protocol;
            return container;
        };
        const auto saveLegacyShell = [&](SecureServersRepository &target, const QString &name,
                                         const SubscriptionController::ProtocolData &keys,
                                         bool addRealAwg2, const SubscriptionController::ProtocolData &otherKeys) {
            ApiV2ServerConfig legacy = createShell();
            legacy.name = name;
            legacy.hostName = QStringLiteral("legacy-mayak.example");
            legacy.authData.apiKey = QStringLiteral("legacy-account-api-identity");
            legacy.apiConfig.activeDeviceCount = 2;
            legacy.apiConfig.maxDeviceCount = 8;
            legacy.apiConfig.userCountryCode = QStringLiteral("RU");
            legacy.apiConfig.serverCountryName = QStringLiteral("Legacy exit");
            legacy.apiConfig.serviceInfo.adHeader = QStringLiteral("Preserved metadata");
            legacy.containers.insert(DockerContainer::Awg, keyOnlyContainer(keys, 45127));
            if (addRealAwg2) {
                ApiV2ServerConfig full = ApiV2ServerConfig::fromJson(gatewayAwg2Allocation(
                        otherKeys.wireGuardClientPrivKey, otherKeys.wireGuardClientPubKey,
                        QStringLiteral("old-awg2.example"), 51820));
                ContainerConfig fullAwg2 = full.containers.value(DockerContainer::Awg2);
                AwgProtocolConfig *fullProtocol = fullAwg2.getAwgProtocolConfig();
                if (!fullProtocol || !fullProtocol->clientConfig.has_value()) return QString();
                AwgClientConfig actualClient = *fullProtocol->clientConfig;
                actualClient.nativeConfig.replace(QStringLiteral("$WIREGUARD_CLIENT_PRIVATE_KEY"),
                                                  actualClient.clientPrivateKey);
                fullProtocol->setClientConfig(actualClient);
                legacy.containers.insert(DockerContainer::Awg2, fullAwg2);
                legacy.defaultContainer = DockerContainer::Awg2;
            }
            const QJsonObject json = legacy.toJson();
            return target.addServer(name, json, serverConfigUtils::configTypeFromJson(json));
        };
        const QString org = QStringLiteral("MayakKeyStandalone-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        {
            TestSecureQSettings secureSettings(org, QStringLiteral("amnezia-client"), nullptr, true);
            QVERIFY2(secureSettings.encryptedStorageAvailable(), "isolated encrypted settings are unavailable");
            SecureServersRepository repository(&secureSettings);
            SecureAppSettingsRepository appSettings(&secureSettings);
            SubscriptionController subscription(&repository, &appSettings);
            const QJsonObject shellJson = createShell().toJson();
            const QString serverId = repository.addServer(QStringLiteral("shell"), shellJson,
                    serverConfigUtils::configTypeFromJson(shellJson));
            QVERIFY(!serverId.isEmpty());

            SubscriptionController::ProtocolData first;
            QCOMPARE(subscription.getOrCreateMayakAwgProtocolData(serverId, &first), ErrorCode::NoError);
            QVERIFY(!first.wireGuardClientPrivKey.isEmpty());
            QVERIFY(!first.wireGuardClientPubKey.isEmpty());
            const QString installation = subscription.mayakInstallationUuid();
            QVERIFY(!installation.isEmpty());
            const auto persisted = repository.apiV2Config(serverId);
            QVERIFY(persisted.has_value());
            const auto awgIt = persisted->containers.constFind(DockerContainer::Awg);
            QStringList persistedContainerIds;
            for (auto it = persisted->containers.cbegin(); it != persisted->containers.cend(); ++it)
                persistedContainerIds.append(QString::number(static_cast<int>(it.key())));
            QVERIFY2(awgIt != persisted->containers.cend(),
                     qPrintable(QStringLiteral("bootstrap persisted container count=%1 enumKeys=[%2] default=%3")
                                .arg(persisted->containers.size()).arg(persistedContainerIds.join(QLatin1Char(',')))
                                .arg(static_cast<int>(persisted->defaultContainer))));
            QVERIFY(awgIt->getAwgProtocolConfig() && awgIt->getAwgProtocolConfig()->clientConfig.has_value());
            QVERIFY(awgIt->getAwgProtocolConfig()->clientConfig->nativeConfig.isEmpty());
            QVERIFY(awgIt->getAwgProtocolConfig()->clientConfig->hostName.isEmpty());

            SecureServersRepository restoredRepository(&secureSettings);
            SecureAppSettingsRepository restoredAppSettings(&secureSettings);
            SubscriptionController restoredSubscription(&restoredRepository, &restoredAppSettings);
            SubscriptionController::ProtocolData retry;
            QCOMPARE(restoredSubscription.getOrCreateMayakAwgProtocolData(serverId, &retry), ErrorCode::NoError);
            QCOMPARE(retry.wireGuardClientPrivKey, first.wireGuardClientPrivKey);
            QCOMPARE(retry.wireGuardClientPubKey, first.wireGuardClientPubKey);
            QCOMPARE(restoredSubscription.mayakInstallationUuid(), installation);

            // Migration A: sole legacy key-only AWG, default unset, including
            // the stale numeric port emitted by old builds.
            const QString migrationAId = saveLegacyShell(restoredRepository, QStringLiteral("legacy A"), first,
                                                          false, {});
            QVERIFY(!migrationAId.isEmpty());
            QVERIFY(restoredAppSettings.markMayakManagedServer(migrationAId));
            const auto beforeA = restoredRepository.apiV2Config(migrationAId);
            QVERIFY(beforeA.has_value());
            QCOMPARE(beforeA->defaultContainer, DockerContainer::None);
            SubscriptionController::ProtocolData migratedA;
            QCOMPARE(restoredSubscription.getOrCreateMayakAwgProtocolData(migrationAId, &migratedA), ErrorCode::NoError);
            QCOMPARE(migratedA.wireGuardClientPrivKey, first.wireGuardClientPrivKey);
            QCOMPARE(migratedA.wireGuardClientPubKey, first.wireGuardClientPubKey);
            const auto afterA = restoredRepository.apiV2Config(migrationAId);
            QVERIFY(afterA.has_value());
            QCOMPARE(afterA->defaultContainer, DockerContainer::Awg);
            QCOMPARE(afterA->containers.size(), 1);
            QCOMPARE(afterA->authData.apiKey, beforeA->authData.apiKey);
            QCOMPARE(afterA->apiConfig.activeDeviceCount, beforeA->apiConfig.activeDeviceCount);
            QCOMPARE(afterA->apiConfig.serviceInfo.adHeader, beforeA->apiConfig.serviceInfo.adHeader);
            SecureServersRepository reloadARepository(&secureSettings);
            SecureAppSettingsRepository reloadASettings(&secureSettings);
            SubscriptionController reloadASubscription(&reloadARepository, &reloadASettings);
            const QJsonObject stableA = reloadARepository.apiV2Config(migrationAId)->toJson();
            SubscriptionController::ProtocolData migratedARetry;
            QCOMPARE(reloadASubscription.getOrCreateMayakAwgProtocolData(migrationAId, &migratedARetry), ErrorCode::NoError);
            QCOMPARE(migratedARetry.wireGuardClientPrivKey, first.wireGuardClientPrivKey);
            QCOMPARE(reloadARepository.apiV2Config(migrationAId)->toJson(), stableA);

            // Migration B: selected real AWG2 plus the old key-only AWG. The
            // stable AWG key pair wins, and all stale transport is discarded.
            const auto oldBootstrapKeys = SubscriptionController::generateProtocolData(configKey::awg);
            const auto otherAwg2Keys = SubscriptionController::generateProtocolData(configKey::awg);
            QVERIFY(!oldBootstrapKeys.wireGuardClientPrivKey.isEmpty());
            QVERIFY(!otherAwg2Keys.wireGuardClientPrivKey.isEmpty());
            QVERIFY(oldBootstrapKeys.wireGuardClientPubKey != otherAwg2Keys.wireGuardClientPubKey);
            const QString migrationBId = saveLegacyShell(restoredRepository, QStringLiteral("legacy B"),
                    oldBootstrapKeys, true, otherAwg2Keys);
            QVERIFY(!migrationBId.isEmpty());
            QVERIFY(restoredAppSettings.markMayakManagedServer(migrationBId));
            const auto beforeB = restoredRepository.apiV2Config(migrationBId);
            QVERIFY(beforeB.has_value());
            QCOMPARE(beforeB->defaultContainer, DockerContainer::Awg2);
            QCOMPARE(beforeB->containers.size(), 2);
            SubscriptionController::ProtocolData migratedB;
            QCOMPARE(restoredSubscription.getOrCreateMayakAwgProtocolData(migrationBId, &migratedB), ErrorCode::NoError);
            QCOMPARE(migratedB.wireGuardClientPrivKey, oldBootstrapKeys.wireGuardClientPrivKey);
            QCOMPARE(migratedB.wireGuardClientPubKey, oldBootstrapKeys.wireGuardClientPubKey);
            const auto afterB = restoredRepository.apiV2Config(migrationBId);
            QVERIFY(afterB.has_value());
            QCOMPARE(afterB->defaultContainer, DockerContainer::Awg2);
            QCOMPARE(afterB->containers.size(), 1);
            QVERIFY(!afterB->containers.contains(DockerContainer::Awg));
            QCOMPARE(afterB->authData.apiKey, beforeB->authData.apiKey);
            QCOMPARE(afterB->hostName, beforeB->hostName);
            QCOMPARE(afterB->apiConfig.activeDeviceCount, beforeB->apiConfig.activeDeviceCount);
            QCOMPARE(afterB->apiConfig.serviceInfo.adHeader, beforeB->apiConfig.serviceInfo.adHeader);
            QVERIFY(afterB->containers.contains(DockerContainer::Awg2));
            const AwgProtocolConfig *migratedBProtocol = afterB->containers.constFind(DockerContainer::Awg2)
                    ->getAwgProtocolConfig();
            QVERIFY(migratedBProtocol);
            // Empty server settings serialize five empty special-junk strings.
            // Compare against the empty model to prove stale transport is gone.
            QCOMPARE(migratedBProtocol->serverConfig.toJson(), AwgServerConfig{}.toJson());
            QVERIFY(migratedBProtocol->clientConfig.has_value());
            const QJsonObject migratedBClient = migratedBProtocol->clientConfig->toJson();
            QCOMPARE(migratedBClient.size(), 2);
            QVERIFY(migratedBClient.contains(configKey::clientPrivKey));
            QVERIFY(migratedBClient.contains(configKey::clientPubKey));
            SecureServersRepository reloadBRepository(&secureSettings);
            SecureAppSettingsRepository reloadBSettings(&secureSettings);
            SubscriptionController reloadBSubscription(&reloadBRepository, &reloadBSettings);
            const QJsonObject stableB = reloadBRepository.apiV2Config(migrationBId)->toJson();
            SubscriptionController::ProtocolData migratedBRetry;
            QCOMPARE(reloadBSubscription.getOrCreateMayakAwgProtocolData(migrationBId, &migratedBRetry), ErrorCode::NoError);
            QCOMPARE(migratedBRetry.wireGuardClientPrivKey, oldBootstrapKeys.wireGuardClientPrivKey);
            QCOMPARE(reloadBRepository.apiV2Config(migrationBId)->toJson(), stableB);
            const QByteArray freshBResponse = gatewayResponse(gatewayAwg2Allocation(
                    QString::fromLatin1(privateKeyPlaceholder), oldBootstrapKeys.wireGuardClientPubKey));
            const QString freshBEncoded = QJsonDocument::fromJson(freshBResponse).object()
                    .value(apiDefs::key::config).toString();
            QCOMPARE(reloadBSubscription.applyMayakAcquireConfig(migrationBId, migratedBRetry, freshBEncoded,
                    QStringLiteral("81.29.149.103"), 51820), ErrorCode::NoError);
            QCOMPARE(reloadBRepository.apiV2Config(migrationBId)->defaultContainer, DockerContainer::Awg2);

            // A server that is not marked as Mayak-managed must never be repaired.
            const QString unmanagedId = saveLegacyShell(restoredRepository, QStringLiteral("unmanaged legacy"),
                    first, false, {});
            QVERIFY(!unmanagedId.isEmpty());
            const QJsonObject unmanagedBefore = restoredRepository.apiV2Config(unmanagedId)->toJson();
            SubscriptionController::ProtocolData unmanagedResult;
            QCOMPARE(restoredSubscription.getOrCreateMayakAwgProtocolData(unmanagedId, &unmanagedResult),
                    ErrorCode::ApiConfigEmptyError);
            QVERIFY(unmanagedResult.wireGuardClientPrivKey.isEmpty());
            QCOMPARE(restoredRepository.apiV2Config(unmanagedId)->toJson(), unmanagedBefore);

            const auto assertRejectedLegacyRecord = [&](const QString &name, const ApiV2ServerConfig &legacy) {
                const QJsonObject json = legacy.toJson();
                const QString id = restoredRepository.addServer(name, json,
                        serverConfigUtils::configTypeFromJson(json));
                QVERIFY(!id.isEmpty());
                QVERIFY(restoredAppSettings.markMayakManagedServer(id));
                const QJsonObject before = restoredRepository.apiV2Config(id)->toJson();
                SubscriptionController::ProtocolData rejected;
                QCOMPARE(restoredSubscription.getOrCreateMayakAwgProtocolData(id, &rejected),
                        ErrorCode::ApiConfigEmptyError);
                QVERIFY(rejected.wireGuardClientPrivKey.isEmpty());
                QVERIFY(rejected.wireGuardClientPubKey.isEmpty());
                QCOMPARE(restoredRepository.apiV2Config(id)->toJson(), before);
            };
            ApiV2ServerConfig publicOnly = createShell();
            AwgClientConfig publicOnlyClient;
            publicOnlyClient.clientPublicKey = first.wireGuardClientPubKey;
            publicOnlyClient.port = 48123;
            ContainerConfig publicOnlyAwg;
            publicOnlyAwg.container = DockerContainer::Awg;
            AwgProtocolConfig publicOnlyProtocol;
            publicOnlyProtocol.setClientConfig(publicOnlyClient);
            publicOnlyAwg.protocolConfig = publicOnlyProtocol;
            publicOnly.containers.insert(DockerContainer::Awg, publicOnlyAwg);
            assertRejectedLegacyRecord(QStringLiteral("public-only legacy"), publicOnly);

            ApiV2ServerConfig mismatchedKeys = createShell();
            SubscriptionController::ProtocolData wrongPair = first;
            wrongPair.wireGuardClientPubKey = otherAwg2Keys.wireGuardClientPubKey;
            mismatchedKeys.containers.insert(DockerContainer::Awg, keyOnlyContainer(wrongPair, 54321));
            assertRejectedLegacyRecord(QStringLiteral("mismatched legacy keys"), mismatchedKeys);

            ApiV2ServerConfig wrongSelected = *beforeB;
            wrongSelected.defaultContainer = DockerContainer::Awg;
            assertRejectedLegacyRecord(QStringLiteral("wrong selected legacy container"), wrongSelected);

            ApiV2ServerConfig invalidSelectedPair = *beforeB;
            ContainerConfig invalidSelectedContainer = invalidSelectedPair.containers.value(DockerContainer::Awg2);
            AwgProtocolConfig *invalidSelectedProtocol = invalidSelectedContainer.getAwgProtocolConfig();
            QVERIFY(invalidSelectedProtocol && invalidSelectedProtocol->clientConfig.has_value());
            AwgClientConfig invalidSelectedClient = *invalidSelectedProtocol->clientConfig;
            invalidSelectedClient.clientPublicKey = first.wireGuardClientPubKey;
            invalidSelectedProtocol->setClientConfig(invalidSelectedClient);
            invalidSelectedPair.containers.insert(DockerContainer::Awg2, invalidSelectedContainer);
            assertRejectedLegacyRecord(QStringLiteral("mismatched selected AWG2 pair"), invalidSelectedPair);

            ApiV2ServerConfig publicOnlySelectedPair = *beforeB;
            ContainerConfig publicOnlySelectedContainer = publicOnlySelectedPair.containers.value(DockerContainer::Awg2);
            AwgProtocolConfig *publicOnlySelectedProtocol = publicOnlySelectedContainer.getAwgProtocolConfig();
            QVERIFY(publicOnlySelectedProtocol && publicOnlySelectedProtocol->clientConfig.has_value());
            AwgClientConfig publicOnlySelectedClient = *publicOnlySelectedProtocol->clientConfig;
            publicOnlySelectedClient.clientPrivateKey.clear();
            publicOnlySelectedProtocol->setClientConfig(publicOnlySelectedClient);
            publicOnlySelectedPair.containers.insert(DockerContainer::Awg2, publicOnlySelectedContainer);
            assertRejectedLegacyRecord(QStringLiteral("public-only selected AWG2 pair"), publicOnlySelectedPair);

            ApiV2ServerConfig realExtraAwg = *beforeB;
            ContainerConfig configuredAwg = realExtraAwg.containers.value(DockerContainer::Awg);
            AwgProtocolConfig *configuredProtocol = configuredAwg.getAwgProtocolConfig();
            QVERIFY(configuredProtocol && configuredProtocol->clientConfig.has_value());
            AwgClientConfig configuredClient = *configuredProtocol->clientConfig;
            configuredClient.hostName = QStringLiteral("configured-extra.example");
            configuredClient.nativeConfig = QStringLiteral("[Interface]\nPrivateKey = %1\n")
                    .arg(configuredClient.clientPrivateKey);
            configuredProtocol->setClientConfig(configuredClient);
            realExtraAwg.containers.insert(DockerContainer::Awg, configuredAwg);
            assertRejectedLegacyRecord(QStringLiteral("real extra AWG transport"), realExtraAwg);

            ApiV2ServerConfig nonAwgDefault = createShell();
            nonAwgDefault.defaultContainer = DockerContainer::Xray;
            nonAwgDefault.containers.insert(DockerContainer::Awg, keyOnlyContainer(first, 41987));
            assertRejectedLegacyRecord(QStringLiteral("non-AWG legacy default"), nonAwgDefault);

            ApiV2ServerConfig extraContainer = createShell();
            extraContainer.defaultContainer = DockerContainer::Awg;
            extraContainer.containers.insert(DockerContainer::Awg, keyOnlyContainer(first, 41987));
            QJsonObject extraContainerJson = extraContainer.toJson();
            QJsonArray extraContainers = extraContainerJson.value(configKey::containers).toArray();
            extraContainers.append(QJsonObject{{configKey::container, QStringLiteral("amnezia-xray")},
                                               {QStringLiteral("xray"), QJsonObject{}}});
            extraContainerJson.insert(configKey::containers, extraContainers);
            assertRejectedLegacyRecord(QStringLiteral("extra non-AWG container"),
                    ApiV2ServerConfig::fromJson(extraContainerJson));

            // Failed encrypted sync rolls the in-memory mutation back and keeps
            // the previously stored record available after repository reload.
            for (const bool addRealAwg2 : {false, true}) {
                TestSecureQSettings failedSyncSettings(org + QStringLiteral("-migration-sync-failure-%1").arg(addRealAwg2),
                        QStringLiteral("amnezia-client"), nullptr, false);
                SecureServersRepository failedSyncRepository(&failedSyncSettings);
                SecureAppSettingsRepository failedSyncAppSettings(&failedSyncSettings);
                SubscriptionController failedSyncSubscription(&failedSyncRepository, &failedSyncAppSettings);
                const QString failedId = saveLegacyShell(failedSyncRepository, QStringLiteral("migration write failure"),
                        first, addRealAwg2, otherAwg2Keys);
                QVERIFY(!failedId.isEmpty());
                failedSyncSettings.setValue(QStringLiteral("Mayak/managedServers"), QStringList{failedId});
                const QJsonObject failedBefore = failedSyncRepository.apiV2Config(failedId)->toJson();
                SubscriptionController::ProtocolData failedMigration;
                QCOMPARE(failedSyncSubscription.getOrCreateMayakAwgProtocolData(failedId, &failedMigration),
                        ErrorCode::InternalError);
                QVERIFY(failedMigration.wireGuardClientPrivKey.isEmpty());
                QCOMPARE(failedSyncRepository.apiV2Config(failedId)->toJson(), failedBefore);
                SecureServersRepository failedReload(&failedSyncSettings);
                QCOMPARE(failedReload.apiV2Config(failedId)->toJson(), failedBefore);
            }

            const QJsonObject response = QJsonDocument::fromJson(gatewayResponse(gatewayServerConfig())).object();
            const QString encoded = response.value(apiDefs::key::config).toString();
            const QString wrongPrivate = QStringLiteral("bm90LXRoZS1wZXJzaXN0ZWQta2V5");
            auto wrongKeyData = retry;
            wrongKeyData.wireGuardClientPrivKey = wrongPrivate;
            QCOMPARE(restoredSubscription.applyMayakAcquireConfig(serverId, wrongKeyData,
                    encoded,
                    QStringLiteral("81.29.149.103"), 51820), ErrorCode::InternalError);

            QCOMPARE(restoredSubscription.applyMayakAcquireConfig(serverId, retry, encoded,
                    QStringLiteral("81.29.149.103"), 51820), ErrorCode::InternalError);

            ApiV2ServerConfig awg2Seed = ApiV2ServerConfig::fromJson(gatewayAwg2Allocation(
                    retry.wireGuardClientPrivKey, retry.wireGuardClientPubKey,
                    QStringLiteral("81.29.149.103"), 51820, QStringLiteral("amnezia-awg")));
            awg2Seed.authData.apiKey = QStringLiteral("existing-account-api-identity");
            const QJsonObject awg2Json = awg2Seed.toJson();
            const QString awg2ServerId = restoredRepository.addServer(QStringLiteral("factory AWG2"), awg2Json,
                    serverConfigUtils::configTypeFromJson(awg2Json));
            QVERIFY(!awg2ServerId.isEmpty());
            SubscriptionController::ProtocolData awg2Retry;
            QCOMPARE(restoredSubscription.getOrCreateMayakAwgProtocolData(awg2ServerId, &awg2Retry), ErrorCode::NoError);
            QCOMPARE(awg2Retry.wireGuardClientPrivKey, retry.wireGuardClientPrivKey);
            QCOMPARE(awg2Retry.wireGuardClientPubKey, retry.wireGuardClientPubKey);
            const QByteArray awg2Response = gatewayResponse(gatewayAwg2Allocation(
                    QString::fromLatin1(privateKeyPlaceholder), retry.wireGuardClientPubKey));
            const QString awg2Encoded = QJsonDocument::fromJson(awg2Response).object().value(apiDefs::key::config).toString();
            QCOMPARE(restoredSubscription.applyMayakAcquireConfig(awg2ServerId, retry, awg2Encoded,
                    QStringLiteral("81.29.149.103"), 51820), ErrorCode::NoError);
            const auto appliedAwg2 = restoredRepository.apiV2Config(awg2ServerId);
            QVERIFY(appliedAwg2.has_value());
            QCOMPARE(appliedAwg2->defaultContainer, DockerContainer::Awg2);
            QVERIFY(appliedAwg2->containers.contains(DockerContainer::Awg2));
            QVERIFY(!appliedAwg2->containers.contains(DockerContainer::Awg));
            QCOMPARE(appliedAwg2->authData.apiKey, QStringLiteral("existing-account-api-identity"));
            const auto *appliedAwg2Config = appliedAwg2->containers.constFind(DockerContainer::Awg2)->getAwgProtocolConfig();
            QVERIFY(appliedAwg2Config && appliedAwg2Config->clientConfig.has_value());
            QCOMPARE(appliedAwg2Config->clientConfig->hostName, QStringLiteral("81.29.149.103"));
            QCOMPARE(appliedAwg2Config->clientConfig->port, 51820);
            QVERIFY(appliedAwg2Config->clientConfig->nativeConfig.contains(QStringLiteral("Endpoint = 81.29.149.103:51820")));
            QVERIFY(appliedAwg2Config->clientConfig->nativeConfig.contains(
                    QStringLiteral("PrivateKey = %1").arg(retry.wireGuardClientPrivKey)));
            SubscriptionController::ProtocolData afterAwg2;
            QCOMPARE(restoredSubscription.getOrCreateMayakAwgProtocolData(awg2ServerId, &afterAwg2), ErrorCode::NoError);
            QCOMPARE(afterAwg2.wireGuardClientPrivKey, retry.wireGuardClientPrivKey);
            QCOMPARE(afterAwg2.wireGuardClientPubKey, retry.wireGuardClientPubKey);
            QCOMPARE(restoredSubscription.applyMayakAcquireConfig(awg2ServerId, afterAwg2, awg2Encoded,
                    QStringLiteral("81.29.149.103"), 51820), ErrorCode::NoError);

            const QJsonObject beforeRejected = restoredRepository.apiV2Config(awg2ServerId)->toJson();
            ApiV2ServerConfig ambiguousCurrent = *appliedAwg2;
            ContainerConfig duplicateAwg = ambiguousCurrent.containers.value(DockerContainer::Awg2);
            duplicateAwg.container = DockerContainer::Awg;
            ambiguousCurrent.containers.insert(DockerContainer::Awg, duplicateAwg);
            const QString ambiguousCurrentId = restoredRepository.addServer(QStringLiteral("ambiguous AWG state"),
                    ambiguousCurrent.toJson(), serverConfigUtils::configTypeFromJson(ambiguousCurrent.toJson()));
            const QJsonObject ambiguousCurrentBefore = restoredRepository.apiV2Config(ambiguousCurrentId)->toJson();
            SubscriptionController::ProtocolData ambiguousKeys;
            QCOMPARE(restoredSubscription.getOrCreateMayakAwgProtocolData(ambiguousCurrentId, &ambiguousKeys),
                    ErrorCode::ApiConfigEmptyError);
            QVERIFY(ambiguousKeys.wireGuardClientPrivKey.isEmpty());
            QCOMPARE(restoredRepository.apiV2Config(ambiguousCurrentId)->toJson(), ambiguousCurrentBefore);

            ApiV2ServerConfig missingDefaultCurrent = *appliedAwg2;
            missingDefaultCurrent.defaultContainer = DockerContainer::None;
            const QString missingDefaultCurrentId = restoredRepository.addServer(QStringLiteral("missing default"),
                    missingDefaultCurrent.toJson(), serverConfigUtils::configTypeFromJson(missingDefaultCurrent.toJson()));
            const QJsonObject missingDefaultBefore = restoredRepository.apiV2Config(missingDefaultCurrentId)->toJson();
            SubscriptionController::ProtocolData missingDefaultKeys;
            QCOMPARE(restoredSubscription.getOrCreateMayakAwgProtocolData(missingDefaultCurrentId, &missingDefaultKeys),
                    ErrorCode::ApiConfigEmptyError);
            QVERIFY(missingDefaultKeys.wireGuardClientPrivKey.isEmpty());
            QCOMPARE(restoredRepository.apiV2Config(missingDefaultCurrentId)->toJson(), missingDefaultBefore);

            const auto rejectWithoutMutation = [&](const QJsonObject &invalidAllocation) {
                const QString invalidEncoded = QJsonDocument::fromJson(gatewayResponse(invalidAllocation)).object()
                        .value(apiDefs::key::config).toString();
                const ErrorCode error = restoredSubscription.applyMayakAcquireConfig(awg2ServerId, afterAwg2, invalidEncoded,
                        QStringLiteral("81.29.149.103"), 51820);
                QVERIFY(error != ErrorCode::NoError);
                QCOMPARE(restoredRepository.apiV2Config(awg2ServerId)->toJson(), beforeRejected);
            };
            const QJsonObject validAllocation = gatewayAwg2Allocation(
                    QString::fromLatin1(privateKeyPlaceholder), retry.wireGuardClientPubKey);
            QJsonObject ambiguousAllocation = validAllocation;
            QJsonArray duplicateContainers = ambiguousAllocation.value(configKey::containers).toArray();
            duplicateContainers.append(duplicateContainers.at(0));
            ambiguousAllocation.insert(configKey::containers, duplicateContainers);
            rejectWithoutMutation(ambiguousAllocation);

            QJsonObject defaultMismatch = validAllocation;
            defaultMismatch.insert(configKey::defaultContainer, QStringLiteral("amnezia-awg"));
            rejectWithoutMutation(defaultMismatch);

            QJsonObject nonAwgAllocation = validAllocation;
            QJsonArray nonAwgContainers = nonAwgAllocation.value(configKey::containers).toArray();
            QJsonObject nonAwgContainer = nonAwgContainers.at(0).toObject();
            nonAwgContainer.insert(configKey::container, QStringLiteral("amnezia-xray"));
            nonAwgContainers.replace(0, nonAwgContainer);
            nonAwgAllocation.insert(configKey::defaultContainer, QStringLiteral("amnezia-xray"));
            nonAwgAllocation.insert(configKey::containers, nonAwgContainers);
            rejectWithoutMutation(nonAwgAllocation);

            QJsonObject missingDefault = validAllocation;
            missingDefault.remove(configKey::defaultContainer);
            rejectWithoutMutation(missingDefault);

            QJsonObject malformedLastConfig = validAllocation;
            QJsonArray malformedContainers = malformedLastConfig.value(configKey::containers).toArray();
            QJsonObject malformedContainer = malformedContainers.at(0).toObject();
            QJsonObject malformedAwg = malformedContainer.value(QString(configKey::awg)).toObject();
            malformedAwg.insert(configKey::lastConfig, QStringLiteral("{malformed-json"));
            malformedContainer.insert(QString(configKey::awg), malformedAwg);
            malformedContainers.replace(0, malformedContainer);
            malformedLastConfig.insert(configKey::containers, malformedContainers);
            rejectWithoutMutation(malformedLastConfig);

            QJsonObject wrongNativeEndpoint = validAllocation;
            QJsonArray endpointContainers = wrongNativeEndpoint.value(configKey::containers).toArray();
            QJsonObject endpointContainer = endpointContainers.at(0).toObject();
            QJsonObject endpointAwg = endpointContainer.value(QString(configKey::awg)).toObject();
            QJsonObject endpointLast = QJsonDocument::fromJson(endpointAwg.value(configKey::lastConfig).toString().toUtf8()).object();
            endpointLast.insert(configKey::config, endpointLast.value(configKey::config).toString()
                    .replace(QStringLiteral("Endpoint = 81.29.149.103:51820"), QStringLiteral("Endpoint = 10.0.0.4:51820")));
            endpointAwg.insert(configKey::lastConfig, QString::fromUtf8(QJsonDocument(endpointLast).toJson(QJsonDocument::Compact)));
            endpointContainer.insert(QString(configKey::awg), endpointAwg);
            endpointContainers.replace(0, endpointContainer);
            wrongNativeEndpoint.insert(configKey::containers, endpointContainers);
            rejectWithoutMutation(wrongNativeEndpoint);

            const QString wrongEndpoint = QJsonDocument::fromJson(gatewayResponse(gatewayAwg2Allocation(
                    QString::fromLatin1(privateKeyPlaceholder), retry.wireGuardClientPubKey,
                    QStringLiteral("10.0.0.4")))).object()
                    .value(apiDefs::key::config).toString();
            QCOMPARE(restoredSubscription.applyMayakAcquireConfig(awg2ServerId, retry, wrongEndpoint,
                    QStringLiteral("81.29.149.103"), 51820), ErrorCode::InternalError);
            QCOMPARE(restoredRepository.apiV2Config(awg2ServerId)->toJson(), beforeRejected);

            ApiV2ServerConfig legacySeed = ApiV2ServerConfig::fromJson(gatewayAwg2Allocation(
                    retry.wireGuardClientPrivKey, retry.wireGuardClientPubKey,
                    QStringLiteral("81.29.149.103"), 51820, QStringLiteral("amnezia-awg")));
            const QJsonObject legacyJson = legacySeed.toJson();
            const QString legacyServerId = restoredRepository.addServer(QStringLiteral("factory legacy AWG"), legacyJson,
                    serverConfigUtils::configTypeFromJson(legacyJson));
            QVERIFY(!legacyServerId.isEmpty());
            const QString legacyEncoded = QJsonDocument::fromJson(gatewayResponse(gatewayAwg2Allocation(
                    QString::fromLatin1(privateKeyPlaceholder), retry.wireGuardClientPubKey,
                    QStringLiteral("81.29.149.103"), 51820,
                    QStringLiteral("amnezia-awg")))).object().value(apiDefs::key::config).toString();
            QCOMPARE(restoredSubscription.applyMayakAcquireConfig(legacyServerId, retry, legacyEncoded,
                    QStringLiteral("81.29.149.103"), 51820), ErrorCode::NoError);
            QCOMPARE(restoredRepository.apiV2Config(legacyServerId)->defaultContainer, DockerContainer::Awg);
        }

        // With secure persistence unavailable, bootstrap must return before any
        // request can be sent and must not leave the generated pair in the model.
        {
            TestSecureQSettings unavailableSettings(org + QStringLiteral("-sync-failure"),
                    QStringLiteral("amnezia-client"), nullptr, false);
            SecureServersRepository repository(&unavailableSettings);
            SecureAppSettingsRepository appSettings(&unavailableSettings);
            SubscriptionController subscription(&repository, &appSettings);
            const QJsonObject shellJson = createShell().toJson();
            const QString serverId = repository.addServer(QStringLiteral("shell"), shellJson,
                    serverConfigUtils::configTypeFromJson(shellJson));
            SubscriptionController::ProtocolData failed;
            QCOMPARE(subscription.getOrCreateMayakAwgProtocolData(serverId, &failed), ErrorCode::InternalError);
            QVERIFY(failed.wireGuardClientPrivKey.isEmpty());
            SecureServersRepository restored(&unavailableSettings);
            const auto restoredConfig = restored.apiV2Config(serverId);
            QVERIFY(restoredConfig.has_value());
            const auto awgIt = restoredConfig->containers.constFind(DockerContainer::Awg);
            QVERIFY(awgIt == restoredConfig->containers.cend()
                    || !awgIt->getAwgProtocolConfig() || !awgIt->getAwgProtocolConfig()->clientConfig.has_value());
        }
        standaloneMayakKeyAssertionsCompleted = true;
    }

    void importsCompressedGatewayConfig()
    {
        const ErrorCode errorCode = m_coreController->m_subscriptionController->applyImportedServiceConfigForTest(
                QStringLiteral("NL"), QStringLiteral("amnezia-premium"), configKey::awg, awgProtocolData(),
                gatewayResponse(gatewayServerConfig()));

        QCOMPARE(errorCode, ErrorCode::NoError);
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 1);

        const QJsonObject server = storedServer();
        QCOMPARE(server.value(configKey::name).toString(), QStringLiteral("Amnezia Premium"));
        QCOMPARE(server.value(configKey::hostName).toString(), QStringLiteral("gateway.example.org"));
    }

    void substitutesWireguardPrivateKey()
    {
        const SubscriptionController::ProtocolData protocolData = awgProtocolData();
        const ErrorCode errorCode = m_coreController->m_subscriptionController->applyImportedServiceConfigForTest(
                QStringLiteral("NL"), QStringLiteral("amnezia-premium"), configKey::awg, protocolData,
                gatewayResponse(gatewayServerConfig()));

        QCOMPARE(errorCode, ErrorCode::NoError);

        const QJsonObject container = storedServer().value(configKey::containers).toArray().first().toObject();
        const QJsonObject awgConfig = container.value(QString(configKey::awg)).toObject();
        const QJsonObject lastConfig =
                QJsonDocument::fromJson(awgConfig.value(configKey::lastConfig).toString().toUtf8()).object();

        QCOMPARE(lastConfig.value(configKey::clientPrivKey).toString(), protocolData.wireGuardClientPrivKey);
        QVERIFY(!lastConfig.value(configKey::clientPrivKey).toString().contains(privateKeyPlaceholder));
    }

    void keepsAwg3RangeValuesAsStrings()
    {
        const ErrorCode errorCode = m_coreController->m_subscriptionController->applyImportedServiceConfigForTest(
                QStringLiteral("NL"), QStringLiteral("amnezia-premium"), configKey::awg, awgProtocolData(),
                gatewayResponse(gatewayServerConfig()));

        QCOMPARE(errorCode, ErrorCode::NoError);

        const QJsonObject container = storedServer().value(configKey::containers).toArray().first().toObject();
        const QJsonObject awgConfig = container.value(QString(configKey::awg)).toObject();
        const QJsonObject lastConfig =
                QJsonDocument::fromJson(awgConfig.value(configKey::lastConfig).toString().toUtf8()).object();

        // awg3 ships ranges such as "25-35"; they must survive import verbatim.
        QCOMPARE(lastConfig.value(configKey::persistentKeepAlive).toString(), QStringLiteral("25-35"));
    }

    void storesServiceMetadataFromResponse()
    {
        const ErrorCode errorCode = m_coreController->m_subscriptionController->applyImportedServiceConfigForTest(
                QStringLiteral("DE"), QStringLiteral("amnezia-premium"), configKey::awg, awgProtocolData(),
                gatewayResponse(gatewayServerConfig()));

        QCOMPARE(errorCode, ErrorCode::NoError);

        const QJsonObject apiConfig = storedServer().value(apiDefs::key::apiConfig).toObject();
        QCOMPARE(apiConfig.value(apiDefs::key::userCountryCode).toString(), QStringLiteral("DE"));
        QCOMPARE(apiConfig.value(apiDefs::key::serviceType).toString(), QStringLiteral("amnezia-premium"));
        QCOMPARE(apiConfig.value(apiDefs::key::serviceProtocol).toString(), QString(configKey::awg));
        const QJsonObject serviceInfo = apiConfig.value(apiDefs::key::serviceInfo).toObject();
        QCOMPARE(serviceInfo.value(apiDefs::key::isAdVisible).toBool(), true);
        QCOMPARE(serviceInfo.value(apiDefs::key::adHeader).toString(), QStringLiteral("Promo header"));
    }

    void rejectsEmptyConfigField()
    {
        QJsonObject response;
        response[apiDefs::key::config] = QString();

        const ErrorCode errorCode = m_coreController->m_subscriptionController->applyImportedServiceConfigForTest(
                QStringLiteral("NL"), QStringLiteral("amnezia-premium"), configKey::awg, awgProtocolData(),
                QJsonDocument(response).toJson(QJsonDocument::Compact));

        QCOMPARE(errorCode, ErrorCode::ApiConfigEmptyError);
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 0);
    }

    void rejectsConfigWithoutContainers()
    {
        QJsonObject config = gatewayServerConfig();
        config[configKey::containers] = QJsonArray {};

        const ErrorCode errorCode = m_coreController->m_subscriptionController->applyImportedServiceConfigForTest(
                QStringLiteral("NL"), QStringLiteral("amnezia-premium"), configKey::awg, awgProtocolData(),
                gatewayResponse(config));

        QCOMPARE(errorCode, ErrorCode::ApiConfigEmptyError);
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 0);
    }

    void rejectsUnsupportedFormatVersion()
    {
        const int unsupported = serverConfigUtils::currentConfigFormatVersion + 1;

        const ErrorCode errorCode = m_coreController->m_subscriptionController->applyImportedServiceConfigForTest(
                QStringLiteral("NL"), QStringLiteral("amnezia-premium"), configKey::awg, awgProtocolData(),
                gatewayResponse(gatewayServerConfig(serverConfigUtils::ConfigSource::AmneziaGateway, unsupported)));

        QCOMPARE(errorCode, ErrorCode::ConfigFormatVersionNotSupportedError);
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 0);
    }

    // --- live gateway update (requires AMNEZIA_TEST_API_KEY) ---

    void updatesServiceFromLiveGateway()
    {
        const QString apiKey = envValue("AMNEZIA_TEST_API_KEY");
        if (apiKey.isEmpty()) {
            QSKIP("AMNEZIA_TEST_API_KEY is not set, skipping live update test");
        }
        m_coreController->m_appSettingsRepository->setGatewayEndpoint(m_liveGatewayEndpoint);

        const QString userCountryCode = QStringLiteral("ru");
        const QString serverCountryCode = QStringLiteral("de");

        // one fixed device identity for the suite, so test runs never consume new device slots
        m_settings->setValue("Conf/installationUuid",
                             QUuid::createUuidV5(QUuid(), QByteArrayLiteral("amnezia-gateway-service-import-test"))
                                     .toString(QUuid::WithoutBraces));

        // updateServiceFromGateway builds its payload from the stored subscription, so seed one first.
        ApiV2ServerConfig seed = storedSubscription();
        seed.apiConfig.userCountryCode = userCountryCode;
        seed.authData.apiKey = apiKey;
        const QString serverId = addStoredServer(seed);
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 1);

        SubscriptionController::CaptchaInfo captchaInfo;
        const ErrorCode errorCode = m_coreController->m_subscriptionController->updateServiceFromGateway(
                serverId, serverCountryCode, /*isConnectEvent=*/false, &captchaInfo, nullptr);

        if (errorCode == ErrorCode::ApiCaptchaRequiredError) {
            QSKIP("Gateway requested a captcha, skipping live update test");
        }

        QCOMPARE(errorCode, ErrorCode::NoError);
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 1);

        const QJsonObject server = storedServer();
        QVERIFY(!server.value(configKey::hostName).toString().isEmpty());
        QVERIFY(server.value(configKey::hostName).toString() != QStringLiteral("gateway.example.org"));
        QVERIFY(!server.value(configKey::containers).toArray().isEmpty());
        QCOMPARE(server.value(configKey::configVersion).toInt(), int(serverConfigUtils::ConfigSource::AmneziaGateway));

        const QJsonObject apiConfig = server.value(apiDefs::key::apiConfig).toObject();
        QCOMPARE(apiConfig.value(apiDefs::key::serviceType).toString(), seed.apiConfig.serviceType);
        QCOMPARE(apiConfig.value(apiDefs::key::serviceProtocol).toString(), seed.apiConfig.serviceProtocol);
        QCOMPARE(apiConfig.value(apiDefs::key::userCountryCode).toString(), userCountryCode);
        QCOMPARE(apiConfig.value(apiDefs::key::serverCountryCode).toString().toLower(), serverCountryCode);

        // QVERIFY, not QCOMPARE: a mismatch must not print the key into CI logs
        const QJsonObject authData = server.value(apiDefs::key::authData).toObject();
        QVERIFY(authData.value(apiDefs::key::apiKey).toString() == apiKey);
    }

    void rejectsNonGatewayConfigSource()
    {
        const ErrorCode errorCode = m_coreController->m_subscriptionController->applyImportedServiceConfigForTest(
                QStringLiteral("NL"), QStringLiteral("amnezia-premium"), configKey::awg, awgProtocolData(),
                gatewayResponse(gatewayServerConfig(serverConfigUtils::ConfigSource::Telegram)));

        QCOMPARE(errorCode, ErrorCode::InternalError);
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 0);
    }

    // --- update of a stored subscription (offline) ---

    void updatesStoredServerInPlace()
    {
        const QString serverId = addStoredServer(storedSubscription());

        QCOMPARE(applyUpdate(serverId, gatewayResponse(updatedGatewayServerConfig())), ErrorCode::NoError);
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 1);
        QCOMPARE(m_coreController->m_serversRepository->serverIdAt(0), serverId);

        const QJsonObject server = storedServer();
        QCOMPARE(server.value(configKey::name).toString(), QStringLiteral("Amnezia Premium Updated"));
        QCOMPARE(server.value(configKey::hostName).toString(), QStringLiteral("gateway-updated.example.org"));
        QVERIFY(!server.value(configKey::containers).toArray().isEmpty());

        const QJsonObject apiConfig = server.value(apiDefs::key::apiConfig).toObject();
        QCOMPARE(apiConfig.value(apiDefs::key::serviceType).toString(), QStringLiteral("amnezia-premium"));
        QCOMPARE(apiConfig.value(apiDefs::key::serviceProtocol).toString(), QString(configKey::awg));
        QCOMPARE(apiConfig.value(apiDefs::key::userCountryCode).toString(), QStringLiteral("NL"));
        QCOMPARE(apiConfig.value(apiDefs::key::serviceInfo).toObject().value(apiDefs::key::adHeader).toString(),
                 QStringLiteral("Promo header"));
    }

    void preservesCredentialsOnUpdate()
    {
        const QString serverId = addStoredServer(storedSubscription());

        QCOMPARE(applyUpdate(serverId, gatewayResponse(updatedGatewayServerConfig())), ErrorCode::NoError);

        const QJsonObject server = storedServer();
        QCOMPARE(server.value(apiDefs::key::authData).toObject().value(apiDefs::key::apiKey).toString(),
                 QStringLiteral("stored-api-key"));
        QCOMPARE(server.value(apiDefs::key::apiConfig).toObject().value(apiDefs::key::vpnKey).toString(),
                 QStringLiteral("vpn://stored-key"));
        QCOMPARE(server.value(configKey::crc).toInt(), 42);
    }

    void keepsNameOverriddenByUserOnUpdate()
    {
        ApiV2ServerConfig seed = storedSubscription();
        seed.name = QStringLiteral("My VPN");
        seed.nameOverriddenByUser = true;
        const QString serverId = addStoredServer(seed);

        QCOMPARE(applyUpdate(serverId, gatewayResponse(updatedGatewayServerConfig())), ErrorCode::NoError);

        const QJsonObject server = storedServer();
        QCOMPARE(server.value(configKey::name).toString(), QStringLiteral("My VPN"));
        QVERIFY(server.value(configKey::nameOverriddenByUser).toBool());
        QCOMPARE(server.value(configKey::hostName).toString(), QStringLiteral("gateway-updated.example.org"));
    }

    void clearsSubscriptionExpiredFlagOnUpdate()
    {
        ApiV2ServerConfig seed = storedSubscription();
        seed.apiConfig.subscriptionExpiredByServer = true;
        const QString serverId = addStoredServer(seed);
        QVERIFY(storedServer().value(apiDefs::key::apiConfig).toObject().value(apiDefs::key::subscriptionExpiredByServer).toBool());

        QCOMPARE(applyUpdate(serverId, gatewayResponse(updatedGatewayServerConfig())), ErrorCode::NoError);

        QVERIFY(!storedServer().value(apiDefs::key::apiConfig).toObject().value(apiDefs::key::subscriptionExpiredByServer).toBool());
    }

    void rejectsUpdateOfUnknownServer()
    {
        QCOMPARE(applyUpdate(QStringLiteral("missing-server"), gatewayResponse(updatedGatewayServerConfig())),
                 ErrorCode::InternalError);
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 0);
    }

    void rejectsUnsupportedFormatVersionOnUpdate()
    {
        const QString serverId = addStoredServer(storedSubscription());
        const int unsupported = serverConfigUtils::currentConfigFormatVersion + 1;

        QCOMPARE(applyUpdate(serverId, gatewayResponse(gatewayServerConfig(serverConfigUtils::ConfigSource::AmneziaGateway, unsupported))),
                 ErrorCode::ConfigFormatVersionNotSupportedError);

        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 1);
        QCOMPARE(storedServer().value(configKey::hostName).toString(), QStringLiteral("gateway.example.org"));
    }

    void rejectsNonGatewaySourceOnUpdate()
    {
        const QString serverId = addStoredServer(storedSubscription());

        QCOMPARE(applyUpdate(serverId, gatewayResponse(gatewayServerConfig(serverConfigUtils::ConfigSource::Telegram))),
                 ErrorCode::InternalError);

        const QJsonObject server = storedServer();
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 1);
        QCOMPARE(server.value(configKey::hostName).toString(), QStringLiteral("gateway.example.org"));
        QCOMPARE(server.value(apiDefs::key::authData).toObject().value(apiDefs::key::apiKey).toString(),
                 QStringLiteral("stored-api-key"));
    }

    void inviteFlowPersistsEncryptedSessionAndWaitsForProvisioning()
    {
        const QString org = QStringLiteral("MayakFlowTest-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        TestSecureQSettings secureSettings(org, QStringLiteral("amnezia-client"), nullptr, true);
        SecureAppSettingsRepository appSettings(&secureSettings);
        ImportUiController importer(m_coreController->m_importCoreController);
        MockNetworkAccessManager network;
        MockMayakProvisioner provisioner;
        network.enqueue(200, authResponse(QStringLiteral("test-session-token"), false));
        network.enqueue(200, appKeyResponse());
        MayakInviteUiController controller(&appSettings, &importer, m_coreController->m_serversController, &provisioner,
                                           &network, QUrl(QStringLiteral("https://mock.mayak/api/")));
        QSignalSpy finished(&controller, &MayakInviteUiController::setupFinished);

        controller.acceptInvite(QStringLiteral("one-time-code"));
        QTRY_COMPARE_WITH_TIMEOUT(provisioner.pending.size(), 1, 5000);
        QVERIFY(controller.busy());
        QCOMPARE(finished.count(), 0);
        QCOMPARE(appSettings.mayakSessionToken(), QStringLiteral("test-session-token"));
        QVERIFY(secureSettings.isEncryptedValueStored(QStringLiteral("Mayak/sessionToken")));
        QVERIFY(!secureSettings.backupAppConfig().contains("test-session-token"));
        QSettings rawSettings(org, QStringLiteral("amnezia-client"));
        rawSettings.sync();
        QVERIFY(rawSettings.value(QStringLiteral("Mayak/sessionToken")).toByteArray().startsWith("EncData"));
        QVERIFY(!rawSettings.value(QStringLiteral("Mayak/sessionToken")).toByteArray().contains("test-session-token"));
        {
            // A new instance must read the encrypted value and OS-backed keys;
            // the writer's in-memory cache cannot satisfy this check.
            SecureQSettings reopened(org, QStringLiteral("amnezia-client"), nullptr, true);
            QVERIFY(reopened.value(QStringLiteral("Mayak/sessionToken")).toString() == QStringLiteral("test-session-token"));
        }
        for (const auto &tag : {QStringLiteral("settingsKeyTag"), QStringLiteral("settingsIvTag")}) {
            QKeychain::ReadPasswordJob read(testKeychainService);
            read.setKey(testCredentialKey(tag));
            QVERIFY(waitForKeychainJob(read));
            QCOMPARE(read.error(), QKeychain::NoError);
            QCOMPARE(read.binaryData().size(), 32);
        }

        const QString stableInstallationId = appSettings.getInstallationUuid(true);
        provisioner.completeNext(ErrorCode::NoError);
        QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 5000);
        QCOMPARE(appSettings.mayakSessionToken(), QStringLiteral("test-session-token"));
        QCOMPARE(appSettings.getInstallationUuid(true), stableInstallationId);
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 1);
    }

    void emailRegistrationExtractsSupportedInviteAndPersistsSession()
    {
        const QString org = QStringLiteral("MayakEmailRegisterTest-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        TestSecureQSettings secureSettings(org, QStringLiteral("amnezia-client"), nullptr, true);
        SecureAppSettingsRepository appSettings(&secureSettings);
        ImportUiController importer(m_coreController->m_importCoreController);
        MockNetworkAccessManager network;
        MockMayakProvisioner provisioner;
        network.enqueue(200, authResponse(QStringLiteral("email-session-token")));
        network.enqueue(200, appKeyResponse());
        MayakInviteUiController controller(&appSettings, &importer, m_coreController->m_serversController, &provisioner,
                                           &network, QUrl(QStringLiteral("https://mock.mayak/api/")));

        controller.registerAccount(QStringLiteral("https://mayaklight.ru/my/?invite=abc_DEF-012"),
                                   QStringLiteral("member@example.org"), QStringLiteral("correct horse battery"));
        QTRY_COMPARE_WITH_TIMEOUT(provisioner.pending.size(), 1, 5000);
        QCOMPARE(network.calls.size(), 2);
        QCOMPARE(network.calls.at(0).url.path(), QStringLiteral("/api/auth/register"));
        const QJsonObject requestBody = QJsonDocument::fromJson(network.calls.at(0).body).object();
        QCOMPARE(requestBody.value(QStringLiteral("invite")).toString(), QStringLiteral("abc_DEF-012"));
        QCOMPARE(requestBody.value(QStringLiteral("email")).toString(), QStringLiteral("member@example.org"));
        QCOMPARE(requestBody.value(QStringLiteral("password")).toString(), QStringLiteral("correct horse battery"));
        QCOMPARE(network.calls.at(1).url.path(), QStringLiteral("/api/app-key"));
        QCOMPARE(appSettings.mayakSessionToken(), QStringLiteral("email-session-token"));
        provisioner.completeNext(ErrorCode::NoError);
        QTRY_VERIFY_WITH_TIMEOUT(!controller.busy(), 5000);
        QCOMPARE(appSettings.mayakSessionToken(), QStringLiteral("email-session-token"));
    }

    void rejectsUntrustedOrAmbiguousInviteUrlsBeforeNetwork()
    {
        const QString org = QStringLiteral("MayakInviteParseTest-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        TestSecureQSettings secureSettings(org, QStringLiteral("amnezia-client"), nullptr, true);
        SecureAppSettingsRepository appSettings(&secureSettings);
        ImportUiController importer(m_coreController->m_importCoreController);
        MockNetworkAccessManager network;
        MockMayakProvisioner provisioner;
        MayakInviteUiController controller(&appSettings, &importer, m_coreController->m_serversController, &provisioner,
                                           &network, QUrl(QStringLiteral("https://mock.mayak/api/")));
        for (const QString &invite : {QStringLiteral("http://mayaklight.ru/my/?invite=token"),
                                      QStringLiteral("https://attacker.invalid/my/?invite=token"),
                                      QStringLiteral("https://mayaklight.ru/my/?invite=a&invite=b"),
                                      QStringLiteral("https://user@mayaklight.ru/my/?invite=token")}) {
            controller.registerAccount(invite, QStringLiteral("user@example.org"), QStringLiteral("correct horse battery"));
            QVERIFY(!controller.busy());
            QVERIFY(!controller.message().isEmpty());
        }
        QVERIFY(network.calls.isEmpty());
    }

    void failedEmailLoginKeepsWorkingSession()
    {
        const QString org = QStringLiteral("MayakLoginFailureTest-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        TestSecureQSettings secureSettings(org, QStringLiteral("amnezia-client"), nullptr, true);
        SecureAppSettingsRepository appSettings(&secureSettings);
        QVERIFY(appSettings.setMayakSessionToken(QStringLiteral("existing-working-token")));
        ImportUiController importer(m_coreController->m_importCoreController);
        MockNetworkAccessManager network;
        MockMayakProvisioner provisioner;
        network.enqueue(401, QByteArrayLiteral("{\"error\":\"Неверный адрес или пароль.\"}"));
        MayakInviteUiController controller(&appSettings, &importer, m_coreController->m_serversController, &provisioner,
                                           &network, QUrl(QStringLiteral("https://mock.mayak/api/")));
        controller.login(QStringLiteral("member@example.org"), QStringLiteral("incorrect password"));
        QTRY_VERIFY_WITH_TIMEOUT(!controller.busy(), 5000);
        QCOMPARE(network.calls.size(), 1);
        QCOMPARE(network.calls.first().url.path(), QStringLiteral("/api/auth/login"));
        QCOMPARE(appSettings.mayakSessionToken(), QStringLiteral("existing-working-token"));
        QVERIFY(controller.hasSession());
        QVERIFY(provisioner.pending.isEmpty());
    }

    void cancellationIgnoresLateAuthenticationReply()
    {
        const QString org = QStringLiteral("MayakAuthCancelTest-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        TestSecureQSettings secureSettings(org, QStringLiteral("amnezia-client"), nullptr, true);
        SecureAppSettingsRepository appSettings(&secureSettings);
        ImportUiController importer(m_coreController->m_importCoreController);
        MockNetworkAccessManager network;
        MockMayakProvisioner provisioner;
        network.enqueue(200, authResponse(QStringLiteral("late-session-token")));
        MayakInviteUiController controller(&appSettings, &importer, m_coreController->m_serversController, &provisioner,
                                           &network, QUrl(QStringLiteral("https://mock.mayak/api/")));
        controller.login(QStringLiteral("member@example.org"), QStringLiteral("correct horse battery"));
        controller.cancelPendingRequests();
        QTRY_COMPARE_WITH_TIMEOUT(network.calls.size(), 1, 5000);
        QTest::qWait(50); // the mock still emits its delayed finished signal after abort()
        QVERIFY(!controller.busy());
        QVERIFY(appSettings.mayakSessionToken().isEmpty());
        QVERIFY(provisioner.pending.isEmpty());
        QVERIFY(controller.message().contains(QStringLiteral("отменена"), Qt::CaseInsensitive));
    }

    void gatewayFailureRetriesAppKeyWithoutPostingInviteOrAddingAnotherServer()
    {
        const QString org = QStringLiteral("MayakRetryTest-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        TestSecureQSettings secureSettings(org, QStringLiteral("amnezia-client"), nullptr, true);
        SecureAppSettingsRepository appSettings(&secureSettings);
        ImportUiController importer(m_coreController->m_importCoreController);
        MockNetworkAccessManager network;
        MockMayakProvisioner provisioner;
        network.enqueue(200, authResponse(QStringLiteral("test-session-token"), false));
        network.enqueue(200, appKeyResponse());
        network.enqueue(200, appKeyResponse());
        MayakInviteUiController controller(&appSettings, &importer, m_coreController->m_serversController, &provisioner,
                                           &network, QUrl(QStringLiteral("https://mock.mayak/api/")));

        controller.acceptInvite(QStringLiteral("one-time-code"));
        QTRY_COMPARE_WITH_TIMEOUT(provisioner.pending.size(), 1, 5000);
        const QString installationId = appSettings.getInstallationUuid(true);
        provisioner.completeNext(ErrorCode::ApiConfigDownloadError);
        QTRY_VERIFY_WITH_TIMEOUT(!controller.busy(), 5000);
        QCOMPARE(appSettings.mayakSessionToken(), QStringLiteral("test-session-token"));
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 1);

        controller.retrySetup();
        QTRY_COMPARE_WITH_TIMEOUT(provisioner.pending.size(), 1, 5000);
        QCOMPARE(appSettings.getInstallationUuid(true), installationId);
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 1);
        QCOMPARE(network.calls.size(), 3);
        QCOMPARE(network.calls.at(0).operation, QNetworkAccessManager::PostOperation);
        QCOMPARE(network.calls.at(0).url.path(), QStringLiteral("/api/auth/invite"));
        QCOMPARE(network.calls.at(1).url.path(), QStringLiteral("/api/app-key"));
        QCOMPARE(network.calls.at(2).url.path(), QStringLiteral("/api/app-key"));

        provisioner.completeNext(ErrorCode::NoError);
        QTRY_VERIFY_WITH_TIMEOUT(!controller.busy(), 5000);
        QCOMPARE(appSettings.mayakSessionToken(), QStringLiteral("test-session-token"));
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 1);
    }

    void appKeyUnauthorizedClearsSessionAndAcceptsNewInvite()
    {
        const QString org = QStringLiteral("MayakAuthExpiryTest-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        TestSecureQSettings secureSettings(org, QStringLiteral("amnezia-client"), nullptr, true);
        SecureAppSettingsRepository appSettings(&secureSettings);
        ImportUiController importer(m_coreController->m_importCoreController);
        MockNetworkAccessManager network;
        MockMayakProvisioner provisioner;
        network.enqueue(200, authResponse(QStringLiteral("expired-token"), false));
        network.enqueue(401, QByteArrayLiteral("{}"));
        network.enqueue(200, authResponse(QStringLiteral("fresh-token")));
        network.enqueue(200, appKeyResponse());
        MayakInviteUiController controller(&appSettings, &importer, m_coreController->m_serversController, &provisioner,
                                           &network, QUrl(QStringLiteral("https://mock.mayak/api/")));

        controller.acceptInvite(QStringLiteral("old-code"));
        QTRY_VERIFY_WITH_TIMEOUT(!controller.busy(), 5000);
        QVERIFY(!controller.hasSession());
        QCOMPARE(appSettings.mayakSessionToken(), QString());
        QVERIFY(controller.message().contains(QStringLiteral("почты"), Qt::CaseInsensitive));

        controller.login(QStringLiteral("member@example.org"), QStringLiteral("long-password-1"));
        QTRY_COMPARE_WITH_TIMEOUT(provisioner.pending.size(), 1, 5000);
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 1);
        provisioner.completeNext(ErrorCode::NoError);
        QTRY_VERIFY_WITH_TIMEOUT(!controller.busy(), 5000);
        QCOMPARE(network.calls.at(0).url.path(), QStringLiteral("/api/auth/invite"));
        QCOMPARE(network.calls.at(1).url.path(), QStringLiteral("/api/app-key"));
        QCOMPARE(network.calls.at(2).url.path(), QStringLiteral("/api/auth/login"));
        QCOMPARE(network.calls.at(3).url.path(), QStringLiteral("/api/app-key"));
    }

    void inviteDoesNotContinueWhenEncryptedStorageIsUnavailable()
    {
        const QString org = QStringLiteral("MayakNoSecureStoreTest-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        TestSecureQSettings insecureSettings(org, QStringLiteral("amnezia-client"), nullptr, false);
        SecureAppSettingsRepository appSettings(&insecureSettings);
        ImportUiController importer(m_coreController->m_importCoreController);
        MockNetworkAccessManager network;
        MockMayakProvisioner provisioner;
        network.enqueue(200, authResponse(QStringLiteral("must-not-persist"), false));
        MayakInviteUiController controller(&appSettings, &importer, m_coreController->m_serversController, &provisioner,
                                           &network, QUrl(QStringLiteral("https://mock.mayak/api/")));

        controller.acceptInvite(QStringLiteral("one-time-code"));
        QTRY_VERIFY_WITH_TIMEOUT(!controller.busy(), 5000);
        QCOMPARE(network.calls.size(), 1);
        QVERIFY(provisioner.pending.isEmpty());
        QVERIFY(!controller.hasSession());
        QVERIFY(controller.message().contains(QStringLiteral("безопасно"), Qt::CaseInsensitive));
    }

    void redirectsDoNotForwardInviteOrBearerToAnotherOrigin()
    {
        const QString org = QStringLiteral("MayakRedirectTest-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        TestSecureQSettings secureSettings(org, QStringLiteral("amnezia-client"), nullptr, true);
        SecureAppSettingsRepository appSettings(&secureSettings);
        ImportUiController importer(m_coreController->m_importCoreController);
        MockNetworkAccessManager network;
        MockMayakProvisioner provisioner;
        network.enqueueRedirect(QUrl(QStringLiteral("https://other.invalid/collect")));
        network.enqueue(200, authResponse(QStringLiteral("redirect-test-token"), false));
        network.enqueueRedirect(QUrl(QStringLiteral("https://other.invalid/collect")));
        MayakInviteUiController controller(&appSettings, &importer, m_coreController->m_serversController, &provisioner,
                                           &network, QUrl(QStringLiteral("https://mock.mayak/api/")));

        controller.acceptInvite(QStringLiteral("one-time-code"));
        QTRY_VERIFY_WITH_TIMEOUT(!controller.busy(), 5000);
        QCOMPARE(network.calls.size(), 1);
        QVERIFY(!controller.hasSession());
        QVERIFY(provisioner.pending.isEmpty());
        controller.acceptInvite(QStringLiteral("new-code"));
        QTRY_VERIFY_WITH_TIMEOUT(!controller.busy(), 5000);
        QCOMPARE(network.calls.size(), 3);
        QVERIFY(controller.hasSession());
        QVERIFY(provisioner.pending.isEmpty());
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 0);
        for (const auto &call : std::as_const(network.calls)) {
            QCOMPARE(call.url.host(), QStringLiteral("mock.mayak"));
            QCOMPARE(call.request.attribute(QNetworkRequest::RedirectPolicyAttribute).toInt(),
                     int(QNetworkRequest::ManualRedirectPolicy));
        }
        QVERIFY(!network.calls.at(0).request.hasRawHeader("Authorization"));
        QVERIFY(!network.calls.at(1).request.hasRawHeader("Authorization"));
        QVERIFY(network.calls.at(2).request.rawHeader("Authorization") == QByteArrayLiteral("Bearer redirect-test-token"));
    }
};

int main(int argc, char *argv[])
{
    int writeIndex = 1;
    for (int readIndex = 1; readIndex < argc; ++readIndex) {
        if (QByteArray(argv[readIndex]) == QByteArrayLiteral("--standalone-auth")) {
            standaloneAuthMode = true;
            continue;
        }
        if (QByteArray(argv[readIndex]) == QByteArrayLiteral("--standalone-mayak-keys")) {
            standaloneMayakKeyMode = true;
            continue;
        }
        argv[writeIndex++] = argv[readIndex];
    }
    argc = writeIndex;
    argv[argc] = nullptr;

    // AmneziaApplication itself constructs settings before initTestCase. Keep
    // those, as well as every fixture, away from the user's registry/settings.
    QTemporaryDir settingsDirectory;
    if (!settingsDirectory.isValid()) qFatal("Could not isolate gateway test settings");
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, settingsDirectory.path());
    QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope, settingsDirectory.path());

    // CoreController reaches the gateway through amnApp->networkManager(), so the
    // application instance has to really be an AmneziaApplication.
    TestGatewayServiceImport tc;
    QTEST_SET_MAIN_SOURCE_PATH
    if (standaloneAuthMode || standaloneMayakKeyMode) {
        QApplication app(argc, argv);
        const int testResult = QTest::qExec(&tc, argc, argv);
        const bool assertionsCompleted = standaloneAuthMode ? standaloneAuthAssertionsCompleted : standaloneMayakKeyAssertionsCompleted;
        if (!assertionsCompleted) {
            qCritical("Standalone assertions did not complete");
            return testResult == 0 ? 3 : testResult;
        }
        qInfo(standaloneAuthMode ? "Standalone auth controller assertions completed"
                                 : "Standalone Mayak key assertions completed");
        return testResult;
    }
    AmneziaApplication app(argc, argv);
    return QTest::qExec(&tc, argc, argv);
}
#include "testGatewayServiceImport.moc"
