#include "subscriptionController.h"

#include <QDebug>
#include <QDateTime>
#include <QFutureWatcher>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMap>
#include <QPromise>
#include <QUuid>
#include <QtConcurrent/QtConcurrentRun>
#include <openssl/evp.h>

#include "core/configurators/openVpnConfigurator.h"
#include "core/configurators/wireguardConfigurator.h"
#include "core/utils/containerEnum.h"
#include "core/utils/containers/containerUtils.h"
#include "core/utils/protocolEnum.h"
#include "core/utils/serverConfigUtils.h"
#include "core/utils/constants/apiKeys.h"
#include "core/utils/constants/apiConstants.h"
#include "core/utils/api/apiUtils.h"
#include "core/utils/api/gatewayPayloadBuilder.h"
#include "core/controllers/gatewayController.h"
#include "core/utils/protocolEnum.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "version.h"
#include "core/models/containerConfig.h"
#include "core/models/api/apiConfig.h"

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    #include "core/utils/swiftBridge.h"
#endif

using namespace amnezia;

namespace
{
QString getSubscriptionStatusForRenewal(const ApiConfig &apiConfig)
{
    if (apiConfig.subscriptionExpiredByServer) {
        return QStringLiteral("expired");
    }

    if (!apiConfig.subscription.endDate.isEmpty()) {
        if (apiUtils::isSubscriptionExpired(apiConfig.subscription.endDate)) {
            return QStringLiteral("expired");
        }
        if (apiUtils::isSubscriptionExpiringSoon(apiConfig.subscription.endDate)) {
            return QStringLiteral("expire_soon");
        }
    }

    return QStringLiteral("active");
}

QString normalizeCaptchaSolution(const QString &captchaSolution)
{
    QString normalizedSolution;
    normalizedSolution.reserve(captchaSolution.size());
    for (const QChar &ch : captchaSolution) {
        const ushort u = ch.unicode();
        if (u >= '0' && u <= '9') {
            normalizedSolution += ch;
        } else if (u >= 0xFF10 && u <= 0xFF19) {
            normalizedSolution += QChar(static_cast<char16_t>(u - 0xFF10 + '0'));
        }
    }
    return normalizedSolution.isEmpty() ? captchaSolution.trimmed() : normalizedSolution;
}

bool fillCaptchaInfoFromResponse(const QByteArray &responseBody, SubscriptionController::CaptchaInfo &captchaInfo)
{
    const QJsonDocument jsonDoc = QJsonDocument::fromJson(responseBody);
    if (!jsonDoc.isObject()) {
        return false;
    }
    const QJsonObject jsonObj = jsonDoc.object();
    if (!jsonObj.contains(QStringLiteral("captcha_id")) || !jsonObj.contains(QStringLiteral("captcha_image"))) {
        return false;
    }
    captchaInfo.captchaId = jsonObj.value(QStringLiteral("captcha_id")).toString();
    captchaInfo.captchaImageBase64 = jsonObj.value(QStringLiteral("captcha_image")).toString();
    captchaInfo.hint = jsonObj.value(QStringLiteral("hint")).toString();
    captchaInfo.isRequired = true;
    return true;
}

bool deriveAwgPublicKey(const QString &privateKey, QString *publicKey)
{
    const QByteArray raw = QByteArray::fromBase64(privateKey.toLatin1(), QByteArray::AbortOnBase64DecodingErrors);
    if (raw.size() != 32 || !publicKey) return false;
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                 reinterpret_cast<const unsigned char *>(raw.constData()), raw.size());
    if (!key) return false;
    unsigned char bytes[32]; size_t size = sizeof(bytes);
    const bool ok = EVP_PKEY_get_raw_public_key(key, bytes, &size) == 1 && size == sizeof(bytes);
    EVP_PKEY_free(key);
    if (!ok) return false;
    *publicKey = QByteArray(reinterpret_cast<const char *>(bytes), static_cast<qsizetype>(size)).toBase64();
    return true;
}

bool nativeAwgFields(const QString &nativeConfig, QMap<QString, QString> *fields)
{
    if (!fields || nativeConfig.isEmpty()) return false;
    fields->clear();
    QString section;
    for (QString line : nativeConfig.split(QLatin1Char('\n'))) {
        line = line.trimmed();
        if (line.isEmpty() || line.startsWith(QLatin1Char('#')) || line.startsWith(QLatin1Char(';'))) continue;
        if (line.startsWith(QLatin1Char('[')) && line.endsWith(QLatin1Char(']'))) {
            section = line.mid(1, line.size() - 2).trimmed().toLower();
            continue;
        }
        const qsizetype equals = line.indexOf(QLatin1Char('='));
        if (section.isEmpty() || equals <= 0) continue;
        const QString key = section + QLatin1Char('.') + line.left(equals).trimmed().toLower();
        if (fields->contains(key)) return false;
        fields->insert(key, line.mid(equals + 1).trimmed());
    }
    return true;
}

bool matchesAwgAllocation(const QString &encodedConfig, DockerContainer expectedContainer,
                          const QString &candidateHost, quint16 candidatePort,
                          const QString &clientPrivateKey, const QString &clientPublicKey)
{
    if ((expectedContainer != DockerContainer::Awg && expectedContainer != DockerContainer::Awg2)
        || candidateHost.isEmpty() || candidatePort == 0 || clientPrivateKey.isEmpty() || clientPublicKey.isEmpty())
        return false;

    QString encoded = encodedConfig;
    encoded.replace(QStringLiteral("vpn://"), QString());
    QByteArray compressed = QByteArray::fromBase64(encoded.toUtf8(),
            QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    if (compressed.isEmpty()) return false;
    const QByteArray uncompressed = qUncompress(compressed);
    if (!uncompressed.isEmpty()) compressed = uncompressed;
    QJsonParseError rootError;
    const QJsonDocument rootDoc = QJsonDocument::fromJson(compressed, &rootError);
    if (rootError.error != QJsonParseError::NoError || !rootDoc.isObject()) return false;
    const QJsonObject root = rootDoc.object();

    const QString rootHost = root.value(configKey::hostName).toString();
    if (rootHost.compare(candidateHost, Qt::CaseInsensitive) != 0) return false;
    const QString defaultName = root.value(configKey::defaultContainer).toString();
    const DockerContainer defaultContainer = ContainerUtils::containerFromString(defaultName);
    if (defaultContainer != expectedContainer) return false;

    const QJsonArray containers = root.value(configKey::containers).toArray();
    // Duplicate entries can be silently collapsed by ApiV2ServerConfig's enum-keyed map.
    if (containers.size() != 1 || !containers.at(0).isObject()) return false;
    const QJsonObject container = containers.at(0).toObject();
    if (ContainerUtils::containerFromString(container.value(configKey::container).toString()) != expectedContainer)
        return false;
    const QString protocolName = ContainerUtils::containerTypeToString(expectedContainer);
    const QJsonValue protocolValue = container.value(protocolName);
    if (!protocolValue.isObject()) return false;
    const QJsonObject protocol = protocolValue.toObject();

    bool outerPortOk = false;
    const uint outerPort = protocol.value(configKey::port).toString().toUInt(&outerPortOk);
    if (!outerPortOk || outerPort != candidatePort) return false;

    const QString lastConfigText = protocol.value(configKey::lastConfig).toString();
    if (lastConfigText.isEmpty()) return false;
    QJsonParseError lastError;
    const QJsonDocument lastDoc = QJsonDocument::fromJson(lastConfigText.toUtf8(), &lastError);
    if (lastError.error != QJsonParseError::NoError || !lastDoc.isObject()) return false;
    const QJsonObject last = lastDoc.object();
    if (last.value(configKey::hostName).toString().compare(candidateHost, Qt::CaseInsensitive) != 0
        || !last.value(configKey::port).isDouble()
        || last.value(configKey::port).toInt(-1) != candidatePort
        || last.value(configKey::clientPrivKey).toString() != QStringLiteral("$WIREGUARD_CLIENT_PRIVATE_KEY")
        || last.value(configKey::clientPubKey).toString() != clientPublicKey
        || last.value(QStringLiteral("clientId")).toString() != clientPublicKey) return false;

    QString native = last.value(configKey::config).toString();
    if (native.isEmpty()) return false;
    native.replace(QStringLiteral("$WIREGUARD_CLIENT_PRIVATE_KEY"), clientPrivateKey);
    QMap<QString, QString> fields;
    if (!nativeAwgFields(native, &fields)) return false;
    const QString expectedEndpoint = candidateHost.contains(QLatin1Char(':'))
            ? QStringLiteral("[%1]:%2").arg(candidateHost).arg(candidatePort)
            : QStringLiteral("%1:%2").arg(candidateHost).arg(candidatePort);
    if (fields.value(QStringLiteral("interface.privatekey")) != clientPrivateKey
        || fields.value(QStringLiteral("peer.endpoint")).compare(expectedEndpoint, Qt::CaseInsensitive) != 0
        || fields.value(QStringLiteral("peer.publickey")) != last.value(configKey::serverPubKey).toString()) return false;

    const QString lastPsk = last.value(configKey::pskKey).toString();
    if (fields.value(QStringLiteral("peer.presharedkey")) != lastPsk) return false;
    QString derivedPublicKey;
    return deriveAwgPublicKey(clientPrivateKey, &derivedPublicKey) && derivedPublicKey == clientPublicKey;
}

bool hasValidAwgClientKeyPair(const AwgClientConfig &client)
{
    if (client.clientPrivateKey.isEmpty() || client.clientPublicKey.isEmpty()) return false;
    QString derived;
    return deriveAwgPublicKey(client.clientPrivateKey, &derived) && derived == client.clientPublicKey;
}

bool isMayakLegacyKeyOnlyAwg(const ContainerConfig &container)
{
    const AwgProtocolConfig *awg = container.getAwgProtocolConfig();
    if (!awg || !awg->clientConfig.has_value()) return false;
    const QJsonObject serverFields = awg->serverConfig.toJson();
    for (auto it = serverFields.constBegin(); it != serverFields.constEnd(); ++it) {
        if ((it.value().isString() && !it.value().toString().trimmed().isEmpty())
            || (it.value().isBool() && it.value().toBool())
            || (!it.value().isString() && !it.value().isBool() && !it.value().isNull())) return false;
    }

    const AwgClientConfig &client = *awg->clientConfig;
    if (!hasValidAwgClientKeyPair(client)) return false;
    QJsonObject clientFields = client.toJson();
    // Old clients did not initialize AwgClientConfig::port. It may have been
    // serialized as any number, so it is not evidence of transport settings.
    clientFields.remove(configKey::port);
    return clientFields.size() == 2
            && clientFields.contains(configKey::clientPrivKey)
            && clientFields.contains(configKey::clientPubKey);
}

bool hasRealAwgTransport(const ContainerConfig &container)
{
    const AwgProtocolConfig *awg = container.getAwgProtocolConfig();
    if (!awg || !awg->clientConfig.has_value()) return false;
    const AwgClientConfig &client = *awg->clientConfig;
    if (client.nativeConfig.isEmpty() || client.hostName.isEmpty() || client.port <= 0
        || client.clientIp.isEmpty() || client.serverPublicKey.isEmpty()) return false;
    if (!hasValidAwgClientKeyPair(client)) return false;
    QMap<QString, QString> fields;
    return nativeAwgFields(client.nativeConfig, &fields)
            && !fields.value(QStringLiteral("interface.privatekey")).isEmpty()
            && !fields.value(QStringLiteral("peer.endpoint")).isEmpty()
            && !fields.value(QStringLiteral("peer.publickey")).isEmpty();
}
}


SubscriptionController::SubscriptionController(SecureServersRepository* serversRepository,
                                               SecureAppSettingsRepository* appSettingsRepository)
    : m_serversRepository(serversRepository), m_appSettingsRepository(appSettingsRepository)
{
}

SubscriptionController::ProtocolData SubscriptionController::generateProtocolData(const QString &protocol)
{
    ProtocolData protocolData;
    if (protocol == configKey::awg) {
        auto connData = WireguardConfigurator::genClientKeys();
        protocolData.wireGuardClientPubKey = connData.clientPubKey;
        protocolData.wireGuardClientPrivKey = connData.clientPrivKey;
    } else if (protocol == configKey::vless) {
        protocolData.xrayUuid = QUuid::createUuid().toString(QUuid::WithoutBraces);
    }

    return protocolData;
}

QString SubscriptionController::publicKeyForProtocol(const QString &protocol, const ProtocolData &protocolData)
{
    if (protocol == configKey::awg) {
        return protocolData.wireGuardClientPubKey;
    }
    if (protocol == configKey::vless) {
        return protocolData.xrayUuid;
    }
    return {};
}

ErrorCode SubscriptionController::extractServerConfigJsonFromResponse(const QByteArray &apiResponseBody, const QString &protocol,
                                                                        const ProtocolData &protocolData, QJsonObject &serverConfigJson)
{
    QString data = QJsonDocument::fromJson(apiResponseBody).object().value(configKey::config).toString();

    data.replace("vpn://", "");
    QByteArray ba = QByteArray::fromBase64(data.toUtf8(), QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

    if (ba.isEmpty()) {
        qDebug() << "empty vpn key";
        return ErrorCode::ApiConfigEmptyError;
    }

    QByteArray ba_uncompressed = qUncompress(ba);
    if (!ba_uncompressed.isEmpty()) {
        ba = ba_uncompressed;
    }

    QString configStr = ba;
    if (protocol == configKey::awg) {
        configStr.replace("$WIREGUARD_CLIENT_PRIVATE_KEY", protocolData.wireGuardClientPrivKey);
        auto newServerConfig = QJsonDocument::fromJson(configStr.toUtf8()).object();
        auto containers = newServerConfig.value(configKey::containers).toArray();
        if (containers.isEmpty()) {
            qDebug() << "missing containers field";
            return ErrorCode::ApiConfigEmptyError;
        }
        auto container = containers.at(0).toObject();
        const DockerContainer dockerContainer = ContainerUtils::containerFromString(
                    container.value(configKey::container).toString());
        if (dockerContainer != DockerContainer::Awg && dockerContainer != DockerContainer::Awg2)
            return ErrorCode::ApiConfigEmptyError;
        QString containerName = ContainerUtils::containerTypeToString(dockerContainer);
        auto serverProtocolConfig = container.value(containerName).toObject();
        auto clientProtocolConfig =
                QJsonDocument::fromJson(serverProtocolConfig.value(configKey::lastConfig).toString().toUtf8()).object();

        // TODO looks like this block can be removed after v1 configs EOL

        const QStringList awgProtocolKeys = configKey::awgProtocolKeys();

        for (const QString &key : awgProtocolKeys) {
            const QJsonValue value = clientProtocolConfig.value(key);
            if (value.isString() && !value.toString().isEmpty()) {
                serverProtocolConfig[key] = value;
            }
        }

        //

        container[containerName] = serverProtocolConfig;
        containers.replace(0, container);
        newServerConfig[configKey::containers] = containers;
        configStr = QString(QJsonDocument(newServerConfig).toJson());
    }

    serverConfigJson = QJsonDocument::fromJson(configStr.toUtf8()).object();
    return ErrorCode::NoError;
}

void SubscriptionController::updateApiConfigInJson(QJsonObject &serverConfigJson, const QString &serviceType,
                                                    const QString &serviceProtocol, const QString &userCountryCode,
                                                    const QByteArray &apiResponseBody)
{
    QJsonObject apiConfig = serverConfigJson.value(apiDefs::key::apiConfig).toObject();

    apiConfig[apiDefs::key::serviceType] = serviceType;
    apiConfig[apiDefs::key::serviceProtocol] = serviceProtocol;
    apiConfig[apiDefs::key::userCountryCode] = userCountryCode;

    if (serverConfigJson.value(configKey::configVersion).toInt() == serverConfigUtils::ConfigSource::AmneziaGateway) {
        QJsonObject responseObj = QJsonDocument::fromJson(apiResponseBody).object();
        if (responseObj.contains(apiDefs::key::serviceInfo)) {
            apiConfig.insert(apiDefs::key::serviceInfo, responseObj.value(apiDefs::key::serviceInfo).toObject());
        }
    }

    serverConfigJson[apiDefs::key::apiConfig] = apiConfig;
}

ErrorCode SubscriptionController::executeRequest(const QString &endpoint, const QJsonObject &apiPayload, QByteArray &responseBody, bool isTestPurchase)
{
    GatewayController gatewayController(m_appSettingsRepository->getGatewayEndpoint(isTestPurchase), m_appSettingsRepository->isDevGatewayEnv(isTestPurchase), apiDefs::requestTimeoutMsecs,
                                        m_appSettingsRepository->isStrictKillSwitchEnabled(), m_appSettingsRepository);
    return gatewayController.post(endpoint, apiPayload, responseBody);
}

ErrorCode SubscriptionController::importServiceFromGateway(const QString &userCountryCode, const QString &serviceType,
                                                            const QString &serviceProtocol, const ProtocolData &protocolData,
                                                            CaptchaInfo &captchaInfo)
{
    QJsonObject apiPayload = GatewayPayloadBuilder(m_appSettingsRepository)
                                     .addField(apiDefs::key::userCountryCode, userCountryCode)
                                     .addField(apiDefs::key::serviceType, serviceType)
                                     .addField(apiDefs::key::serviceProtocol, serviceProtocol)
                                     .addField(apiDefs::key::publicKey, publicKeyForProtocol(serviceProtocol, protocolData))
                                     .build();

    QByteArray responseBody;
    ErrorCode errorCode = executeRequest(QString("%1v1/config"), apiPayload, responseBody);

    if (errorCode == ErrorCode::ApiCaptchaRequiredError) {
        fillCaptchaInfoFromResponse(responseBody, captchaInfo);
        return errorCode;
    }

    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    return applyImportedServiceConfig(userCountryCode, serviceType, serviceProtocol, protocolData, responseBody);
}

ErrorCode SubscriptionController::applyImportedServiceConfig(const QString &userCountryCode, const QString &serviceType,
                                                             const QString &serviceProtocol, const ProtocolData &protocolData,
                                                             const QByteArray &responseBody)
{
    QJsonObject serverConfigJson;
    ErrorCode errorCode = extractServerConfigJsonFromResponse(responseBody, serviceProtocol, protocolData, serverConfigJson);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    updateApiConfigInJson(serverConfigJson, serviceType, serviceProtocol, userCountryCode, responseBody);

    if (!serverConfigUtils::isConfigFormatVersionSupported(serverConfigJson)) {
        return ErrorCode::ConfigFormatVersionNotSupportedError;
    }
    if (serverConfigJson.value(configKey::configVersion).toInt() != serverConfigUtils::ConfigSource::AmneziaGateway) {
        return ErrorCode::InternalError;
    }

    ApiV2ServerConfig apiV2ServerConfig = ApiV2ServerConfig::fromJson(serverConfigJson);
    m_serversRepository->addServer(QString(), apiV2ServerConfig.toJson(),
                                   serverConfigUtils::configTypeFromJson(apiV2ServerConfig.toJson()));
    return ErrorCode::NoError;
}

ErrorCode SubscriptionController::importTrialFromGateway(const QString &userCountryCode, const QString &serviceType,
                                                         const QString &serviceProtocol, const QString &email)
{
    const QString trimmedEmail = email.trimmed();
    if (trimmedEmail.isEmpty()) {
        return ErrorCode::ApiConfigEmptyError;
    }

    ProtocolData protocolData = generateProtocolData(serviceProtocol);

    QJsonObject apiPayload = GatewayPayloadBuilder(m_appSettingsRepository)
                                     .addField(apiDefs::key::userCountryCode, userCountryCode)
                                     .addField(apiDefs::key::serviceType, serviceType)
                                     .addField(apiDefs::key::serviceProtocol, serviceProtocol)
                                     .addField(apiDefs::key::publicKey, publicKeyForProtocol(serviceProtocol, protocolData))
                                     .addField(apiDefs::key::email, trimmedEmail)
                                     .build();

    QByteArray responseBody;
    ErrorCode errorCode = executeRequest(QString("%1v1/trial"), apiPayload, responseBody);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    QJsonObject responseObject = QJsonDocument::fromJson(responseBody).object();
    QString key = responseObject.value(apiDefs::key::config).toString();
    if (key.isEmpty()) {
        return ErrorCode::ApiConfigEmptyError;
    }

    key.replace(QStringLiteral("vpn://"), QString());
    QByteArray configBytes = QByteArray::fromBase64(key.toUtf8(), QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    QByteArray uncompressed = qUncompress(configBytes);
    if (!uncompressed.isEmpty()) {
        configBytes = uncompressed;
    }

    if (configBytes.isEmpty()) {
        return ErrorCode::ApiConfigEmptyError;
    }

    QJsonObject configObject = QJsonDocument::fromJson(configBytes).object();
    if (!serverConfigUtils::isConfigFormatVersionSupported(configObject)) {
        return ErrorCode::ConfigFormatVersionNotSupportedError;
    }
    if (configObject.value(configKey::configVersion).toInt() != serverConfigUtils::ConfigSource::AmneziaGateway) {
        return ErrorCode::InternalError;
    }

    ApiV2ServerConfig apiV2ServerConfig = ApiV2ServerConfig::fromJson(configObject);
    m_serversRepository->addServer(QString(), apiV2ServerConfig.toJson(),
                                   serverConfigUtils::configTypeFromJson(apiV2ServerConfig.toJson()));
    return ErrorCode::NoError;
}

ErrorCode SubscriptionController::updateServiceFromGateway(const QString &serverId, const QString &newCountryCode, bool isConnectEvent,
                                                           CaptchaInfo *captchaInfoOut, ProtocolData *usedProtocolDataOut)
{
    auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (!apiV2.has_value()) {
        return ErrorCode::InternalError;
    }
    const bool isTestPurchase = apiV2->apiConfig.isTestPurchase;
    QString serviceProtocol = apiV2->serviceProtocol();

    if (!newCountryCode.isEmpty()) {
        const auto availableCountries = apiV2->apiConfig.availableCountries;
        for (const auto &country : availableCountries) {
            const auto countryObject = country.toObject();
            if (countryObject.value(apiDefs::key::serverCountryCode).toString() != newCountryCode) {
                continue;
            }

            const auto availableProtocols = countryObject.value(apiDefs::key::availableProtocols).toArray();
            if (!availableProtocols.isEmpty() && !availableProtocols.contains(serviceProtocol)) {
                serviceProtocol = availableProtocols.first().toString();
            }
            break;
        }
    }

    ProtocolData protocolData = generateProtocolData(serviceProtocol);

    QJsonObject apiPayload = GatewayPayloadBuilder(m_appSettingsRepository)
                                     .addField(apiDefs::key::userCountryCode, apiV2->apiConfig.userCountryCode)
                                     .addField(apiDefs::key::serverCountryCode, newCountryCode)
                                     .addField(apiDefs::key::serviceType, apiV2->serviceType())
                                     .addField(apiDefs::key::serviceProtocol, serviceProtocol)
                                     .addField(apiDefs::key::publicKey, publicKeyForProtocol(serviceProtocol, protocolData))
                                     .addField(apiDefs::key::authData, apiV2->authData.toJson())
                                     .addField(apiDefs::key::isConnectEvent, isConnectEvent ? QJsonValue(true) : QJsonValue())
                                     .build();

    QByteArray responseBody;
    ErrorCode errorCode = executeRequest(QString("%1v1/config"), apiPayload, responseBody, isTestPurchase);
    if (errorCode != ErrorCode::NoError) {
        if (errorCode == ErrorCode::ApiCaptchaRequiredError && captchaInfoOut) {
            if (fillCaptchaInfoFromResponse(responseBody, *captchaInfoOut) && usedProtocolDataOut) {
                *usedProtocolDataOut = protocolData;
            }
        }
        if (errorCode == ErrorCode::ApiSubscriptionExpiredError && !apiV2->apiConfig.isInAppPurchase) {
            markSubscriptionExpiredByServer(serverId, *apiV2);
        }
        return errorCode;
    }

    return applyUpdatedServiceConfig(serverId, serviceProtocol, protocolData, responseBody);
}

ErrorCode SubscriptionController::fetchServiceConfig(const QString &serverId, const QString &serviceProtocol,
                                                     QJsonObject &serverConfigJson)
{
    auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (!apiV2.has_value()) {
        return ErrorCode::InternalError;
    }

    ProtocolData protocolData = generateProtocolData(serviceProtocol);

    QJsonObject apiPayload = GatewayPayloadBuilder(m_appSettingsRepository)
                                     .addField(apiDefs::key::userCountryCode, apiV2->apiConfig.userCountryCode)
                                     .addField(apiDefs::key::serviceType, apiV2->serviceType())
                                     .addField(apiDefs::key::serviceProtocol, serviceProtocol)
                                     .addField(apiDefs::key::publicKey, publicKeyForProtocol(serviceProtocol, protocolData))
                                     .addField(apiDefs::key::authData, apiV2->authData.toJson())
                                     .build();

    QByteArray responseBody;
    ErrorCode errorCode = executeRequest(QString("%1v1/config"), apiPayload, responseBody, apiV2->apiConfig.isTestPurchase);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    return extractServerConfigJsonFromResponse(responseBody, serviceProtocol, protocolData, serverConfigJson);
}

QFuture<SubscriptionController::GatewayConfigResult> SubscriptionController::requestGatewayConfigAsync(const QString &serverId)
{
    GatewayConfigResult result;
    result.serverId = serverId;
    const auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (!apiV2.has_value()) {
        return QtConcurrent::run([result]() { return result; });
    }

    result.serviceProtocol = apiV2->serviceProtocol();
    result.protocolData = generateProtocolData(result.serviceProtocol);
    const QJsonObject apiPayload = GatewayPayloadBuilder(m_appSettingsRepository)
                                           .addField(apiDefs::key::userCountryCode, apiV2->apiConfig.userCountryCode)
                                           .addField(apiDefs::key::serviceType, apiV2->serviceType())
                                           .addField(apiDefs::key::serviceProtocol, result.serviceProtocol)
                                           .addField(apiDefs::key::publicKey, publicKeyForProtocol(result.serviceProtocol, result.protocolData))
                                           .addField(apiDefs::key::authData, apiV2->authData.toJson())
                                           .build();

    const QString endpoint = m_appSettingsRepository->getGatewayEndpoint(apiV2->apiConfig.isTestPurchase);
    const bool isDevEnvironment = m_appSettingsRepository->isDevGatewayEnv(apiV2->apiConfig.isTestPurchase);
    const bool strictKillSwitch = m_appSettingsRepository->isStrictKillSwitchEnabled();
    SecureAppSettingsRepository *settings = m_appSettingsRepository;
    return QtConcurrent::run([result, apiPayload, endpoint, isDevEnvironment, strictKillSwitch, settings]() mutable {
        GatewayController gateway(endpoint, isDevEnvironment, apiDefs::requestTimeoutMsecs, strictKillSwitch, settings);
        result.error = gateway.post(QStringLiteral("%1v1/config"), apiPayload, result.responseBody);
        return result;
    });
}

QFuture<SubscriptionController::GatewayConfigResult> SubscriptionController::requestMayakGatewayConfigAsync(const QString &serverId)
{
    GatewayConfigResult result; result.serverId = serverId; result.serviceProtocol = QStringLiteral("awg");
    const auto cfg = m_serversRepository->apiV2Config(serverId);
    if (!cfg || getOrCreateMayakAwgProtocolData(serverId, &result.protocolData) != ErrorCode::NoError)
        return QtConcurrent::run([result] { return result; });
    const QJsonObject payload = GatewayPayloadBuilder(m_appSettingsRepository)
        .addField(apiDefs::key::authData, cfg->authData.toJson())
        .addField(apiDefs::key::serviceType, cfg->serviceType())
        .addField(apiDefs::key::serviceProtocol, result.serviceProtocol)
        .addField(apiDefs::key::userCountryCode, cfg->apiConfig.userCountryCode)
        .addField(apiDefs::key::publicKey, result.protocolData.wireGuardClientPubKey).build();
    // Repository values are captured on their owner thread; no worker dereferences settings.
    return QtConcurrent::run([result, payload]() mutable {
        GatewayController gateway(QStringLiteral("https://mayaklight.ru/gw/"), false, 10000, false, nullptr);
        result.error = gateway.post(QStringLiteral("%1v1/config"), payload, result.responseBody);
        return result;
    });
}

ErrorCode SubscriptionController::applyGatewayConfig(const GatewayConfigResult &result)
{
    if (result.error != ErrorCode::NoError) {
        return result.error;
    }
    if (result.serverId.isEmpty() || result.responseBody.isEmpty()) {
        return ErrorCode::ApiConfigEmptyError;
    }
    return applyUpdatedServiceConfig(result.serverId, result.serviceProtocol, result.protocolData, result.responseBody);
}

ErrorCode SubscriptionController::getOrCreateMayakAwgProtocolData(const QString &serverId, ProtocolData *protocolData)
{
    if (!protocolData || serverId.isEmpty()) return ErrorCode::InternalError;
    auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (!apiV2.has_value()) return ErrorCode::InternalError;
    DockerContainer selected = apiV2->defaultContainer;
    if (apiV2->containers.contains(DockerContainer::Awg)) {
        const bool legacyKeyOnlyAwg = isMayakLegacyKeyOnlyAwg(apiV2->containers.value(DockerContainer::Awg));
        const bool managed = m_appSettingsRepository
                && m_appSettingsRepository->isMayakManagedServer(serverId);

        // Legacy A: old bootstrap stored only a key pair in an AWG container
        // and left defaultContainer unset. Repair only records explicitly marked
        // as Mayak-managed; ordinary imported configs remain untouched.
        if (managed && selected == DockerContainer::None && apiV2->containers.size() == 1
            && legacyKeyOnlyAwg) {
            apiV2->defaultContainer = DockerContainer::Awg;
            selected = DockerContainer::Awg;
            if (!m_serversRepository->editServerAndSync(serverId, apiV2->toJson(),
                    serverConfigUtils::configTypeFromJson(apiV2->toJson()))) return ErrorCode::InternalError;
        // Legacy B: old bootstrap added a second, key-only AWG beside the real
        // selected AWG2 config. Carry the old stable pair forward in a clean
        // AWG2 placeholder and let the normal authenticated acquire refresh all
        // transport fields. Do not carry the old endpoint or AWG transport.
        } else if (managed && selected == DockerContainer::Awg2 && apiV2->containers.size() == 2
                   && legacyKeyOnlyAwg && apiV2->containers.contains(DockerContainer::Awg2)
                   && hasRealAwgTransport(apiV2->containers.value(DockerContainer::Awg2))) {
            const AwgClientConfig legacyClient = *apiV2->containers.value(DockerContainer::Awg)
                    .getAwgProtocolConfig()->clientConfig;
            ContainerConfig keyOnlyAwg2;
            keyOnlyAwg2.container = DockerContainer::Awg2;
            AwgProtocolConfig keyOnlyProtocol;
            AwgClientConfig stableClient;
            stableClient.clientPrivateKey = legacyClient.clientPrivateKey;
            stableClient.clientPublicKey = legacyClient.clientPublicKey;
            keyOnlyProtocol.setClientConfig(stableClient);
            keyOnlyAwg2.protocolConfig = keyOnlyProtocol;

            apiV2->containers.remove(DockerContainer::Awg);
            apiV2->containers.insert(DockerContainer::Awg2, keyOnlyAwg2);
            apiV2->defaultContainer = DockerContainer::Awg2;
            selected = DockerContainer::Awg2;
            if (!m_serversRepository->editServerAndSync(serverId, apiV2->toJson(),
                    serverConfigUtils::configTypeFromJson(apiV2->toJson()))) return ErrorCode::InternalError;
        }
    }
    if (m_appSettingsRepository && m_appSettingsRepository->isMayakManagedServer(serverId)
        && !apiV2->containers.isEmpty()
        && ((selected != DockerContainer::Awg && selected != DockerContainer::Awg2)
            || apiV2->containers.size() != 1 || !apiV2->containers.contains(selected)))
        return ErrorCode::ApiConfigEmptyError;
    if (apiV2->containers.isEmpty()) {
        if (selected != DockerContainer::None && selected != DockerContainer::Awg && selected != DockerContainer::Awg2)
            return ErrorCode::ApiConfigEmptyError;
        if (selected == DockerContainer::None) selected = DockerContainer::Awg;
        // The generated placeholder is a real selectable container. Persist its
        // selection too; otherwise the serialized shell has a container but no
        // default and cannot be reopened consistently by the normal config path.
        apiV2->defaultContainer = selected;
    } else {
        int awgContainerCount = 0;
        for (auto it = apiV2->containers.cbegin(); it != apiV2->containers.cend(); ++it) {
            if (it.key() == DockerContainer::Awg || it.key() == DockerContainer::Awg2) ++awgContainerCount;
        }
        if (awgContainerCount != 1 || (selected != DockerContainer::Awg && selected != DockerContainer::Awg2)
            || !apiV2->containers.contains(selected)) return ErrorCode::ApiConfigEmptyError;
    }
    auto containerIt = apiV2->containers.find(selected);
    if (containerIt == apiV2->containers.end() && apiV2->containers.isEmpty()) {
        ContainerConfig placeholder;
        placeholder.container = selected;
        placeholder.protocolConfig = AwgProtocolConfig{};
        containerIt = apiV2->containers.insert(selected, placeholder);
    }
    if (containerIt == apiV2->containers.end()) return ErrorCode::ApiConfigEmptyError;
    AwgProtocolConfig *awg = containerIt->getAwgProtocolConfig();
    if (!awg) return ErrorCode::ApiConfigEmptyError;

    AwgClientConfig client;
    if (awg->clientConfig.has_value()) client = *awg->clientConfig;
    bool persist = false;
    const bool hasPrivate = !client.clientPrivateKey.isEmpty();
    const bool hasPublic = !client.clientPublicKey.isEmpty();
    if (hasPrivate) {
        QString derived;
        if (!deriveAwgPublicKey(client.clientPrivateKey, &derived)) return ErrorCode::ApiConfigEmptyError;
        if (hasPublic && derived != client.clientPublicKey) return ErrorCode::ApiConfigEmptyError;
        if (!hasPublic) { client.clientPublicKey = derived; persist = true; }
    } else if (hasPublic) {
        return ErrorCode::ApiConfigEmptyError;
    } else {
        const auto generated = WireguardConfigurator::genClientKeys();
        if (generated.clientPrivKey.isEmpty() || generated.clientPubKey.isEmpty()) return ErrorCode::InternalError;
        client.clientPrivateKey = generated.clientPrivKey;
        client.clientPublicKey = generated.clientPubKey;
        QString derived;
        if (!deriveAwgPublicKey(client.clientPrivateKey, &derived) || derived != client.clientPublicKey)
            return ErrorCode::InternalError;
        persist = true;
    }

    if (persist || !awg->clientConfig.has_value()) {
        awg->setClientConfig(client);
        if (!m_serversRepository->editServerAndSync(serverId, apiV2->toJson(),
                serverConfigUtils::configTypeFromJson(apiV2->toJson()))) return ErrorCode::InternalError;
    }
    protocolData->wireGuardClientPrivKey = client.clientPrivateKey;
    protocolData->wireGuardClientPubKey = client.clientPublicKey;
    return ErrorCode::NoError;
}

QString SubscriptionController::mayakInstallationUuid() const
{
    return m_appSettingsRepository ? m_appSettingsRepository->getInstallationUuid(true) : QString();
}

ErrorCode SubscriptionController::applyMayakAcquireConfig(const QString &serverId, const ProtocolData &protocolData,
                                                          const QString &encodedConfig, const QString &candidateHost,
                                                          quint16 candidatePort)
{
    if (serverId.isEmpty() || protocolData.wireGuardClientPrivKey.isEmpty()
        || protocolData.wireGuardClientPubKey.isEmpty() || candidateHost.isEmpty() || candidatePort == 0
        || encodedConfig.isEmpty()) return ErrorCode::ApiConfigEmptyError;
    const auto current = m_serversRepository->apiV2Config(serverId);
    if (!current.has_value()) return ErrorCode::InternalError;
    const DockerContainer currentContainer = current->defaultContainer;
    if (currentContainer != DockerContainer::Awg && currentContainer != DockerContainer::Awg2)
        return ErrorCode::ApiConfigEmptyError;
    int awgContainerCount = 0;
    for (auto it = current->containers.cbegin(); it != current->containers.cend(); ++it)
        if (it.key() == DockerContainer::Awg || it.key() == DockerContainer::Awg2) ++awgContainerCount;
    if (awgContainerCount != 1 || !current->containers.contains(currentContainer)) return ErrorCode::ApiConfigEmptyError;
    const auto awgIt = current->containers.constFind(currentContainer);
    if (awgIt == current->containers.cend() || !awgIt->getAwgProtocolConfig()
        || !awgIt->getAwgProtocolConfig()->clientConfig.has_value()) return ErrorCode::ApiConfigEmptyError;
    const auto &stable = *awgIt->getAwgProtocolConfig()->clientConfig;
    if (stable.clientPrivateKey != protocolData.wireGuardClientPrivKey
        || stable.clientPublicKey != protocolData.wireGuardClientPubKey) return ErrorCode::InternalError;
    QString derivedPublicKey;
    if (!deriveAwgPublicKey(stable.clientPrivateKey, &derivedPublicKey) || derivedPublicKey != stable.clientPublicKey)
        return ErrorCode::InternalError;

    const QByteArray body = QJsonDocument(QJsonObject{{configKey::config, encodedConfig}}).toJson(QJsonDocument::Compact);
    QJsonObject decoded;
    const ErrorCode decodeError = extractServerConfigJsonFromResponse(body, configKey::awg, protocolData, decoded);
    if (decodeError != ErrorCode::NoError) return decodeError;
    const ApiV2ServerConfig admitted = ApiV2ServerConfig::fromJson(decoded);
    const DockerContainer admittedContainer = admitted.defaultContainer;
    if ((admittedContainer != DockerContainer::Awg && admittedContainer != DockerContainer::Awg2)
        || admitted.containers.size() != 1 || !admitted.containers.contains(admittedContainer))
        return ErrorCode::ApiConfigEmptyError;
    const auto admittedAwgIt = admitted.containers.constFind(admittedContainer);
    if (admittedAwgIt == admitted.containers.cend() || !admittedAwgIt->getAwgProtocolConfig()
        || !admittedAwgIt->getAwgProtocolConfig()->clientConfig.has_value()) return ErrorCode::ApiConfigEmptyError;
    const auto &client = *admittedAwgIt->getAwgProtocolConfig()->clientConfig;
    if (client.hostName != candidateHost || client.port != candidatePort
        || client.clientPrivateKey != protocolData.wireGuardClientPrivKey) return ErrorCode::InternalError;
    if (client.clientPublicKey != stable.clientPublicKey) return ErrorCode::InternalError;
    if (!matchesAwgAllocation(encodedConfig, admittedContainer, candidateHost, candidatePort,
                              protocolData.wireGuardClientPrivKey, protocolData.wireGuardClientPubKey))
        return ErrorCode::ApiConfigEmptyError;

    // The admission response carries only the selected config. Carry forward existing service
    // metadata so applying the same-key allocation cannot change account or server selection.
    QJsonObject wrapper{{configKey::config, encodedConfig}};
    wrapper.insert(apiDefs::key::serviceInfo, current->apiConfig.serviceInfo.toJson());
    return applyUpdatedServiceConfig(serverId, configKey::awg, protocolData,
                                     QJsonDocument(wrapper).toJson(QJsonDocument::Compact));
}

void SubscriptionController::markSubscriptionExpiredByServer(const QString &serverId, const ApiV2ServerConfig &apiV2)
{
    ApiV2ServerConfig expiredApiV2 = apiV2;
    expiredApiV2.apiConfig.subscriptionExpiredByServer = true;
    m_serversRepository->editServer(serverId, expiredApiV2.toJson(),
                                    serverConfigUtils::configTypeFromJson(expiredApiV2.toJson()));
}

ErrorCode SubscriptionController::applyUpdatedServiceConfig(const QString &serverId, const QString &serviceProtocol,
                                                           const ProtocolData &protocolData, const QByteArray &responseBody,
                                                           bool preserveCurrentSelection)
{
    auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (!apiV2.has_value()) {
        return ErrorCode::InternalError;
    }

    QJsonObject serverConfigJson;
    ErrorCode errorCode = extractServerConfigJsonFromResponse(responseBody, serviceProtocol, protocolData, serverConfigJson);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    updateApiConfigInJson(serverConfigJson, apiV2->apiConfig.serviceType,
                          preserveCurrentSelection ? apiV2->serviceProtocol() : serviceProtocol,
                          apiV2->apiConfig.userCountryCode, responseBody);

    if (!serverConfigUtils::isConfigFormatVersionSupported(serverConfigJson)) {
        return ErrorCode::ConfigFormatVersionNotSupportedError;
    }
    if (serverConfigJson.value(configKey::configVersion).toInt() != serverConfigUtils::ConfigSource::AmneziaGateway) {
        return ErrorCode::InternalError;
    }

    ApiV2ServerConfig newApiV2Config = ApiV2ServerConfig::fromJson(serverConfigJson);

    if (preserveCurrentSelection) {
        newApiV2Config.defaultContainer = apiV2->defaultContainer;
    }

    newApiV2Config.apiConfig.vpnKey = apiV2->apiConfig.vpnKey;
    newApiV2Config.apiConfig.subscriptionExpiredByServer = false;

    newApiV2Config.authData = apiV2->authData;
    newApiV2Config.crc = apiV2->crc;

    if (apiV2->nameOverriddenByUser) {
        newApiV2Config.name = apiV2->name;
        newApiV2Config.displayName = apiV2->displayName;
        newApiV2Config.nameOverriddenByUser = true;
    }

    m_serversRepository->editServer(serverId, newApiV2Config.toJson(),
                                   serverConfigUtils::configTypeFromJson(newApiV2Config.toJson()));
    return ErrorCode::NoError;
}

ErrorCode SubscriptionController::resolveUpdateServiceCaptcha(const QString &serverId, const QString &newCountryCode,
                                                              bool isConnectEvent, const ProtocolData &protocolData,
                                                              const QString &captchaId, const QString &captchaSolution,
                                                              CaptchaInfo *retryCaptchaOut)
{
    auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (!apiV2.has_value()) {
        return ErrorCode::InternalError;
    }
    const bool isTestPurchase = apiV2->apiConfig.isTestPurchase;
    QString serviceProtocol = apiV2->serviceProtocol();

    QJsonObject apiPayload = GatewayPayloadBuilder(m_appSettingsRepository)
                                     .addField(apiDefs::key::userCountryCode, apiV2->apiConfig.userCountryCode)
                                     .addField(apiDefs::key::serverCountryCode, newCountryCode)
                                     .addField(apiDefs::key::serviceType, apiV2->serviceType())
                                     .addField(apiDefs::key::serviceProtocol, serviceProtocol)
                                     .addField(apiDefs::key::publicKey, publicKeyForProtocol(serviceProtocol, protocolData))
                                     .addField(apiDefs::key::authData, apiV2->authData.toJson())
                                     .addField(apiDefs::key::captchaId, captchaId)
                                     .addField(apiDefs::key::captchaSolution, normalizeCaptchaSolution(captchaSolution))
                                     .addField(apiDefs::key::isConnectEvent, isConnectEvent ? QJsonValue(true) : QJsonValue())
                                     .build();

    QByteArray responseBody;
    ErrorCode errorCode = executeRequest(QString("%1v1/config"), apiPayload, responseBody, isTestPurchase);
    if (errorCode != ErrorCode::NoError) {
        if (retryCaptchaOut
            && (errorCode == ErrorCode::ApiCaptchaInvalidError || errorCode == ErrorCode::ApiCaptchaRefreshError
                || errorCode == ErrorCode::ApiCaptchaRequiredError)) {
            fillCaptchaInfoFromResponse(responseBody, *retryCaptchaOut);
        }
        if (errorCode == ErrorCode::ApiSubscriptionExpiredError && !apiV2->apiConfig.isInAppPurchase) {
            markSubscriptionExpiredByServer(serverId, *apiV2);
        }
        return errorCode;
    }

    return applyUpdatedServiceConfig(serverId, serviceProtocol, protocolData, responseBody);
}

ErrorCode SubscriptionController::deactivateDevice(const QString &serverId)
{
    auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (!apiV2.has_value()) {
        return ErrorCode::NoError;
    }

    if (!apiV2->isPremium() && !apiV2->isExternalPremium()) {
        return ErrorCode::NoError;
    }

    QJsonObject apiPayload = GatewayPayloadBuilder(m_appSettingsRepository)
                                     .addField(apiDefs::key::userCountryCode, apiV2->apiConfig.userCountryCode)
                                     .addField(apiDefs::key::serverCountryCode, apiV2->apiConfig.serverCountryCode)
                                     .addField(apiDefs::key::serviceType, apiV2->serviceType())
                                     .addField(apiDefs::key::authData, apiV2->authData.toJson())
                                     .build();

    const bool isTestPurchase = apiV2->apiConfig.isTestPurchase;
    QByteArray responseBody;
    ErrorCode errorCode = executeRequest(QString("%1v1/revoke_config"), apiPayload, responseBody, isTestPurchase);
    if (errorCode != ErrorCode::NoError && errorCode != ErrorCode::ApiNotFoundError) {
        return errorCode;
    }

    apiV2->containers.clear();
    m_serversRepository->editServer(serverId, apiV2->toJson(),
                                    serverConfigUtils::configTypeFromJson(apiV2->toJson()));
    return ErrorCode::NoError;
}

ErrorCode SubscriptionController::deactivateExternalDevice(const QString &serverId, const QString &uuid, const QString &serverCountryCode)
{
    auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (!apiV2.has_value()) {
        return ErrorCode::NoError;
    }

    if (!apiV2->isPremium() && !apiV2->isExternalPremium()) {
        return ErrorCode::NoError;
    }

    QJsonObject apiPayload = GatewayPayloadBuilder(m_appSettingsRepository)
                                     .addField(apiDefs::key::installationUuid, uuid)
                                     .addField(apiDefs::key::userCountryCode, apiV2->apiConfig.userCountryCode)
                                     .addField(apiDefs::key::serverCountryCode, serverCountryCode)
                                     .addField(apiDefs::key::serviceType, apiV2->serviceType())
                                     .addField(apiDefs::key::authData, apiV2->authData.toJson())
                                     .build();

    const bool isTestPurchase = apiV2->apiConfig.isTestPurchase;
    QByteArray responseBody;
    ErrorCode errorCode = executeRequest(QString("%1v1/revoke_config"), apiPayload, responseBody, isTestPurchase);
    if (errorCode != ErrorCode::NoError && errorCode != ErrorCode::ApiNotFoundError) {
        return errorCode;
    }

    if (uuid == m_appSettingsRepository->getInstallationUuid(true)) {
        apiV2->containers.clear();
        m_serversRepository->editServer(serverId, apiV2->toJson(),
                                        serverConfigUtils::configTypeFromJson(apiV2->toJson()));
    }

    return ErrorCode::NoError;
}

ErrorCode SubscriptionController::exportNativeConfig(const QString &serverId, const QString &serverCountryCode, QString &nativeConfig)
{
    auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (!apiV2.has_value()) {
        return ErrorCode::InternalError;
    }
    const bool isTestPurchase = apiV2->apiConfig.isTestPurchase;
    QString protocol = configKey::awg;
    ProtocolData protocolData = generateProtocolData(protocol);

    QJsonObject apiPayload = GatewayPayloadBuilder(m_appSettingsRepository)
                                     .addField(apiDefs::key::userCountryCode, apiV2->apiConfig.userCountryCode)
                                     .addField(apiDefs::key::serverCountryCode, serverCountryCode)
                                     .addField(apiDefs::key::serviceType, apiV2->serviceType())
                                     .addField(apiDefs::key::serviceProtocol, protocol)
                                     .addField(apiDefs::key::publicKey, publicKeyForProtocol(protocol, protocolData))
                                     .addField(apiDefs::key::authData, apiV2->authData.toJson())
                                     .build();

    QByteArray responseBody;
    ErrorCode errorCode = executeRequest(QString("%1v1/native_config"), apiPayload, responseBody, isTestPurchase);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    QJsonObject jsonConfig = QJsonDocument::fromJson(responseBody).object();
    nativeConfig = jsonConfig.value(configKey::config).toString();
    nativeConfig.replace("$WIREGUARD_CLIENT_PRIVATE_KEY", protocolData.wireGuardClientPrivKey);
    return ErrorCode::NoError;
}

ErrorCode SubscriptionController::revokeNativeConfig(const QString &serverId, const QString &serverCountryCode)
{
    auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (!apiV2.has_value()) {
        return ErrorCode::InternalError;
    }
    const bool isTestPurchase = apiV2->apiConfig.isTestPurchase;
    QString protocol = configKey::awg;

    QJsonObject apiPayload = GatewayPayloadBuilder(m_appSettingsRepository)
                                     .addField(apiDefs::key::userCountryCode, apiV2->apiConfig.userCountryCode)
                                     .addField(apiDefs::key::serverCountryCode, serverCountryCode)
                                     .addField(apiDefs::key::serviceType, apiV2->serviceType())
                                     .addField(apiDefs::key::serviceProtocol, protocol)
                                     .addField(apiDefs::key::authData, apiV2->authData.toJson())
                                     .build();

    QByteArray responseBody;
    ErrorCode errorCode = executeRequest(QString("%1v1/revoke_native_config"), apiPayload, responseBody, isTestPurchase);
    if (errorCode != ErrorCode::NoError && errorCode != ErrorCode::ApiNotFoundError) {
        return errorCode;
    }

    return ErrorCode::NoError;
}

ErrorCode SubscriptionController::prepareVpnKeyExport(const QString &serverId, QString &vpnKey)
{
    auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (!apiV2.has_value()) {
        return ErrorCode::ApiConfigEmptyError;
    }
    vpnKey = apiV2->vpnKey();
    if (vpnKey.isEmpty()) {
        vpnKey = apiUtils::getPremiumV2VpnKey(apiV2->toJson());
        if (vpnKey.isEmpty()) {
            return ErrorCode::ApiConfigEmptyError;
        }
        apiV2->apiConfig.vpnKey = vpnKey;
        m_serversRepository->editServer(serverId, apiV2->toJson(),
                                         serverConfigUtils::configTypeFromJson(apiV2->toJson()));
    }

    return ErrorCode::NoError;
}

ErrorCode SubscriptionController::validateAndUpdateConfig(const QString &serverId, bool hasInstalledContainers,
                                                         CaptchaInfo *captchaInfoOut, ProtocolData *usedProtocolDataOut)
{
    if (!m_serversRepository->apiV2Config(serverId).has_value()) {
        return ErrorCode::NoError;
    }

    if (!hasInstalledContainers) {
        return updateServiceFromGateway(serverId, "", true, captchaInfoOut, usedProtocolDataOut);
    }

    if (isApiKeyExpired(serverId)) {
        qDebug() << "attempt to update api config by expires_at event";
        return updateServiceFromGateway(serverId, "", true, captchaInfoOut, usedProtocolDataOut);
    }

    return ErrorCode::NoError;
}

void SubscriptionController::removeApiConfig(const QString &serverId)
{
    auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (!apiV2.has_value()) {
        return;
    }

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    QString description = apiV2->description;
    QString hostName = apiV2->hostName;
    QString vpncName = QString("%1 (%2) %3")
                               .arg(description)
                               .arg(hostName)
                               .arg("");

    SWIFT_BRIDGE_NAMESPACE::removeVPNC(vpncName.toStdString());
#endif

    apiV2->dns1.clear();
    apiV2->dns2.clear();
    apiV2->containers.clear();
    apiV2->hostName.clear();
    apiV2->defaultContainer = DockerContainer::None;
    apiV2->apiConfig.publicKey = ApiConfig::PublicKeyInfo{};

    m_serversRepository->editServer(serverId, apiV2->toJson(),
                                    serverConfigUtils::configTypeFromJson(apiV2->toJson()));
}

bool SubscriptionController::removeServer(const QString &serverId)
{
    if (serverId.isEmpty()) {
        return false;
    }

    if (!m_serversRepository->apiV2Config(serverId).has_value()) {
        qWarning().noquote() << "SubscriptionController::removeServer: not an Api V2 server, id" << serverId;
        return false;
    }

    const ErrorCode revokeError = deactivateDevice(serverId);
    if (revokeError != ErrorCode::NoError && revokeError != ErrorCode::ApiNotFoundError) {
        qWarning().noquote() << "SubscriptionController::removeServer: deactivateDevice failed (error"
                             << static_cast<int>(revokeError) << "); removing locally anyway.";
    }

    m_serversRepository->removeServer(serverId);
    return true;
}

bool SubscriptionController::isApiKeyExpired(const QString &serverId) const
{
    auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (!apiV2.has_value()) {
        return false;
    }
    const QString expiresAt = apiV2->apiConfig.publicKey.expiresAt;

    if (expiresAt.isEmpty()) {
        return false;
    }

    auto expiresAtDateTime = QDateTime::fromString(expiresAt, Qt::ISODate).toUTC();
    if (expiresAtDateTime < QDateTime::currentDateTimeUtc()) {
        return true;
    }

    return false;
}

void SubscriptionController::setCurrentProtocol(const QString &serverId, const QString &protocolName)
{
    auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (apiV2.has_value()) {
        apiV2->apiConfig.serviceProtocol = protocolName;
        m_serversRepository->editServer(serverId, apiV2->toJson(),
                                        serverConfigUtils::configTypeFromJson(apiV2->toJson()));
    }
}

bool SubscriptionController::isVlessProtocol(const QString &serverId) const
{
    auto apiV2 = m_serversRepository->apiV2Config(serverId);
    return apiV2.has_value() && apiV2->serviceProtocol() == "vless";
}

QString SubscriptionController::currentProtocol(const QString &serverId) const
{
    auto apiV2 = m_serversRepository->apiV2Config(serverId);
    return apiV2.has_value() ? apiV2->serviceProtocol() : QString();
}

QStringList SubscriptionController::availableProtocols(const QString &serverId) const
{
    auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (!apiV2.has_value()) {
        return {};
    }

    const auto currentCountryCode = apiV2->apiConfig.serverCountryCode;
    const auto availableCountries = apiV2->apiConfig.availableCountries;

    QStringList protocols;
    for (const auto &country : availableCountries) {
        const auto countryObject = country.toObject();
        if (countryObject.value(apiDefs::key::serverCountryCode).toString() != currentCountryCode) {
            continue;
        }
        for (const auto &protocol : countryObject.value(apiDefs::key::availableProtocols).toArray()) {
            protocols.push_back(protocol.toString());
        }
        break;
    }
    return protocols;
}

ErrorCode SubscriptionController::getAccountInfo(const QString &serverId, QJsonObject &accountInfo)
{
    auto apiV2Opt = m_serversRepository->apiV2Config(serverId);
    if (!apiV2Opt.has_value()) {
        return ErrorCode::InternalError;
    }

    const ApiV2ServerConfig* apiV2 = &apiV2Opt.value();
    bool isTestPurchase = apiV2->apiConfig.isTestPurchase;

    QJsonObject apiPayload = GatewayPayloadBuilder(m_appSettingsRepository)
                                     .addField(apiDefs::key::userCountryCode, apiV2->apiConfig.userCountryCode)
                                     .addField(apiDefs::key::serviceType, apiV2->serviceType())
                                     .addField(apiDefs::key::authData, apiV2->authData.toJson())
                                     .addField(apiDefs::key::cliVersion, QString(APP_VERSION))
                                     .addField(apiDefs::key::subscriptionStatus, getSubscriptionStatusForRenewal(apiV2->apiConfig))
                                     .build();

    QByteArray responseBody;
    ErrorCode errorCode = executeRequest(QString("%1v1/account_info"), apiPayload, responseBody, isTestPurchase);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    accountInfo = QJsonDocument::fromJson(responseBody).object();    

    return ErrorCode::NoError;
}

QFuture<QPair<ErrorCode, QString>> SubscriptionController::getRenewalLink(const QString &serverId)
{
    auto promise = QSharedPointer<QPromise<QPair<ErrorCode, QString>>>::create();
    promise->start();

    auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (!apiV2.has_value()) {
        promise->addResult(qMakePair(ErrorCode::InternalError, QString()));
        promise->finish();
        return promise->future();
    }

    bool isTestPurchase = apiV2->apiConfig.isTestPurchase;
    QJsonObject apiPayload = GatewayPayloadBuilder(m_appSettingsRepository)
                                     .addField(apiDefs::key::userCountryCode, apiV2->apiConfig.userCountryCode)
                                     .addField(apiDefs::key::serviceType, apiV2->serviceType())
                                     .addField(apiDefs::key::authData, apiV2->authData.toJson())
                                     .addField(apiDefs::key::cliVersion, QString(APP_VERSION))
                                     .addField(apiDefs::key::subscriptionStatus, getSubscriptionStatusForRenewal(apiV2->apiConfig))
                                     .build();

    auto gatewayController = QSharedPointer<GatewayController>::create(m_appSettingsRepository->getGatewayEndpoint(isTestPurchase),
                                                                       m_appSettingsRepository->isDevGatewayEnv(isTestPurchase),
                                                                       apiDefs::requestTimeoutMsecs,
                                                                       m_appSettingsRepository->isStrictKillSwitchEnabled(),
                                                                       m_appSettingsRepository);
    auto postFuture = gatewayController->postAsync(QString("%1v1/renewal_link"), apiPayload);
    auto *watcher = new QFutureWatcher<QPair<ErrorCode, QByteArray>>();
    QObject::connect(watcher, &QFutureWatcher<QPair<ErrorCode, QByteArray>>::finished,
                     [promise, watcher, gatewayController]() {
                         const auto [errorCode, responseBody] = watcher->result();
                         watcher->deleteLater();
                         if (errorCode != ErrorCode::NoError) {
                             promise->addResult(qMakePair(errorCode, QString()));
                             promise->finish();
                             return;
                         }

                         QJsonObject responseJson = QJsonDocument::fromJson(responseBody).object();
                         const QString url = responseJson.value("renewal_url").toString();
                         promise->addResult(qMakePair(ErrorCode::NoError, url));
                         promise->finish();
                     });
    watcher->setFuture(postFuture);
    return promise->future();
}

ErrorCode SubscriptionController::resolveImportServiceCaptcha(const QString &userCountryCode,
                                                              const QString &serviceType,
                                                              const QString &serviceProtocol,
                                                              const ProtocolData &protocolData,
                                                              const QString &captchaId,
                                                              const QString &captchaSolution,
                                                              CaptchaInfo *retryCaptchaOut)
{
    QJsonObject apiPayload = GatewayPayloadBuilder(m_appSettingsRepository)
                                     .addField(apiDefs::key::userCountryCode, userCountryCode)
                                     .addField(apiDefs::key::serviceType, serviceType)
                                     .addField(apiDefs::key::serviceProtocol, serviceProtocol)
                                     .addField(apiDefs::key::publicKey, publicKeyForProtocol(serviceProtocol, protocolData))
                                     .addField(apiDefs::key::captchaId, captchaId)
                                     .addField(apiDefs::key::captchaSolution, normalizeCaptchaSolution(captchaSolution))
                                     .build();

    QByteArray responseBody;
    ErrorCode errorCode = executeRequest(QString("%1v1/config"), apiPayload, responseBody);
    if (errorCode != ErrorCode::NoError) {
        if (retryCaptchaOut
            && (errorCode == ErrorCode::ApiCaptchaInvalidError || errorCode == ErrorCode::ApiCaptchaRefreshError
                || errorCode == ErrorCode::ApiCaptchaRequiredError)) {
            fillCaptchaInfoFromResponse(responseBody, *retryCaptchaOut);
        }
        return errorCode;
    }

    return applyImportedServiceConfig(userCountryCode, serviceType, serviceProtocol, protocolData, responseBody);
}
