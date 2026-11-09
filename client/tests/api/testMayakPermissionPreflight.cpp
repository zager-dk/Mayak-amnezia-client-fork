#include <QApplication>
#include <QJsonDocument>
#include <QPromise>
#include <QTemporaryDir>
#include <QTest>
#include <QUuid>
#include "core/controllers/mayakAutoConnectRuntime.h"
#include "core/controllers/mayakBackendBridge.h"
#include "core/controllers/api/subscriptionController.h"
#include "core/controllers/connectionController.h"
#include "core/repositories/secureAppSettingsRepository.h"
#include "core/repositories/secureServersRepository.h"
#include "core/models/api/apiV2ServerConfig.h"
#include "secureQSettings.h"

using namespace amnezia;
using B = MayakBackendBridge;

namespace {
QString guid() { return QUuid::createUuid().toString(QUuid::WithoutBraces); }

struct Fixture : QObject {
    SecureQSettings settings{QStringLiteral("MayakPermission-") + guid(), QStringLiteral("test"), nullptr, true};
    SecureServersRepository servers{&settings};
    SecureAppSettingsRepository app{&settings};
    SubscriptionController subscription{&servers, &app};
    ConnectionController connection{&servers, &app, nullptr};
    QString serverId;
    QString permissionRequestId;
    B::PermissionDone permissionDone;
    int fetches = 0;
    int permissionCancels = 0;
    QString lastMessage;
    std::unique_ptr<MayakAutoConnectRuntime> runtime;

    Fixture() {
        ApiV2ServerConfig config;
        config.configVersion = serverConfigUtils::ConfigSource::AmneziaGateway;
        config.name = QStringLiteral("Mayak permission fixture");
        config.defaultContainer = DockerContainer::Awg;
        config.apiConfig.serviceType = QStringLiteral("amnezia-premium");
        config.apiConfig.serviceProtocol = QStringLiteral("awg");
        config.apiConfig.userCountryCode = QStringLiteral("ru");
        config.authData.apiKey = QStringLiteral("synthetic-credential");
        serverId = servers.addServer(guid(), config.toJson(),
                                     serverConfigUtils::configTypeFromJson(config.toJson()));
        app.setMayakSessionToken(QStringLiteral("synthetic-session"));
        app.markMayakManagedServer(serverId);

        B::Port port;
        port.owner = this;
        port.observe = [](QObject *, auto, auto) {};
        port.inspect = [](QString request, qint64, B::Inspected done) {
            done({B::OwnState::Off, request, {}, {}});
        };
        port.preparePermissions = [this](QString requestId, B::PermissionDone done) {
            permissionRequestId = std::move(requestId);
            permissionDone = std::move(done);
        };
        port.cancelPermissionPreparation = [this](QString requestId) {
            ++permissionCancels;
            if (requestId == permissionRequestId) permissionDone = {};
        };

        auto transport = [this](const QString &, const QJsonObject &, int) {
            ++fetches;
            auto promise = std::make_shared<QPromise<GatewayPostResult>>();
            promise->start();
            auto future = promise->future();
            promise->addResult({ErrorCode::UnknownError, {}, false});
            promise->finish();
            return future;
        };
        runtime = std::make_unique<MayakAutoConnectRuntime>(&settings, &servers, &app, &subscription,
                                                           &connection, std::move(port), nullptr,
                                                           std::move(transport));
        connection.setMayakRuntime(runtime.get());
        connect(runtime.get(), &MayakAutoConnectRuntime::stateChanged, this,
                [this](Vpn::ConnectionState, const QString &message) { lastMessage = message; });
    }

    ~Fixture() { runtime.reset(); settings.clearSettings(); }
};
}

class MayakPermissionPreflightTest final : public QObject {
    Q_OBJECT
private slots:
    void heldPermissionDoesNotStartGatewayBudgetOrFetch() {
        Fixture fixture;
        fixture.runtime->begin(fixture.serverId);
        QTRY_VERIFY2_WITH_TIMEOUT(bool(fixture.permissionDone), qPrintable(fixture.lastMessage), 3000);
        QCOMPARE(fixture.fetches, 0);

        // Simulate the OS consent sheet remaining visible beyond both the
        // connect-before lease and proof windows. No backend request may start.
        QTest::qWait(30100);
        QCOMPARE(fixture.fetches, 0);
        QVERIFY(fixture.permissionDone);

        auto done = std::move(fixture.permissionDone);
        done(fixture.permissionRequestId, B::PermissionResult::Ready);
        // The fake intentionally returns an API failure; observing exactly one
        // fetch proves that Ready starts one fresh coordinator cycle.
        QTRY_COMPARE_WITH_TIMEOUT(fixture.fetches, 1, 5000);
        QTest::qWait(250);
        QCOMPARE(fixture.fetches, 1);
    }

    void deniedPermissionDoesNotFetch() {
        Fixture fixture;
        fixture.runtime->begin(fixture.serverId);
        QTRY_VERIFY2_WITH_TIMEOUT(bool(fixture.permissionDone), qPrintable(fixture.lastMessage), 3000);
        auto done = std::move(fixture.permissionDone);
        done(fixture.permissionRequestId, B::PermissionResult::Denied);
        QTest::qWait(100);
        QCOMPARE(fixture.fetches, 0);
    }

    void cancellationMakesLateReadyInert() {
        Fixture fixture;
        fixture.runtime->begin(fixture.serverId);
        QTRY_VERIFY2_WITH_TIMEOUT(bool(fixture.permissionDone), qPrintable(fixture.lastMessage), 3000);
        auto late = std::move(fixture.permissionDone);
        fixture.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(fixture.permissionCancels > 0, 1000);
        late(fixture.permissionRequestId, B::PermissionResult::Ready);
        QTest::qWait(100);
        QCOMPARE(fixture.fetches, 0);
    }
};

int main(int argc, char **argv) {
    QTemporaryDir temp;
    if (!temp.isValid()) return 2;
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, temp.path());
    QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope, temp.path());
    QApplication app(argc, argv);
    MayakPermissionPreflightTest test;
    return QTest::qExec(&test, argc, argv);
}

#include "testMayakPermissionPreflight.moc"
