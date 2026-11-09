#include "mayakInviteUiController.h"

#include "core/controllers/gatewayController.h"
#include "core/controllers/serversController.h"
#include "core/repositories/secureAppSettingsRepository.h"
#include "core/utils/constants/apiConstants.h"
#include "core/utils/constants/apiKeys.h"
#include "core/utils/api/gatewayPayloadBuilder.h"
#include "core/utils/mayakDeviceIdentity.h"
#include "importUiController.h"
#include "version.h"

#include <QFutureWatcher>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUrlQuery>
#include <QMetaObject>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPointer>
#include <QRegularExpression>
#include <QSslSocket>
#include <QUrl>
#include <QDebug>

GatewayMayakProvisioner::GatewayMayakProvisioner(SubscriptionController *subscriptionController,
                                                 ServersController *serversController, QObject *parent)
    : GatewayMayakProvisioner(subscriptionController, serversController, parent,
                              [subscriptionController](const QString &serverId) {
        return subscriptionController->requestMayakGatewayConfigAsync(serverId);
    })
{
}

GatewayMayakProvisioner::GatewayMayakProvisioner(SubscriptionController *subscriptionController,
                                                 ServersController *serversController, QObject *parent,
                                                 GatewayConfigRequest request)
    : MayakSubscriptionProvisioner(parent),
      m_subscriptionController(subscriptionController),
      m_serversController(serversController),
      m_request(std::move(request))
{
}

void GatewayMayakProvisioner::provision(const QString &serverId, IsCurrent isCurrent, Completion completion)
{
    auto *watcher = new QFutureWatcher<SubscriptionController::GatewayConfigResult>(this);
    connect(watcher, &QFutureWatcher<SubscriptionController::GatewayConfigResult>::finished, this,
            [this, watcher, isCurrent = std::move(isCurrent), completion = std::move(completion)]() mutable {
        const auto result = watcher->result();
        watcher->deleteLater();
        // A stale gateway response must not mutate the subscription or default server.
        if (!isCurrent || !isCurrent()) return;
        const ErrorCode error = m_subscriptionController->applyGatewayConfig(result);
        if (error == ErrorCode::NoError) {
            m_serversController->setDefaultServer(result.serverId);
        }
        completion(error);
    });
    watcher->setFuture(m_request(serverId));
}

MayakInviteUiController::MayakInviteUiController(SecureAppSettingsRepository *settings, ImportUiController *importer,
                                                 ServersController *serversController, MayakSubscriptionProvisioner *provisioner,
                                                 QNetworkAccessManager *network, QUrl apiRoot, QObject *parent)
    : QObject(parent),
      m_settings(settings),
      m_importer(importer),
      m_serversController(serversController),
      m_provisioner(provisioner),
      m_network(network),
      m_apiRoot(apiRoot.isEmpty() ? QUrl(QStringLiteral("https://mayaklight.ru/api/")) : std::move(apiRoot))
{
    if (m_network == nullptr) {
        m_network = new QNetworkAccessManager(this);
    }
    m_telegramPollTimer = new QTimer(this);
    m_telegramPollTimer->setInterval(5000);
    connect(m_telegramPollTimer, &QTimer::timeout, this, &MayakInviteUiController::pollTelegramLink);

    if (m_importer != nullptr) {
        connect(m_importer, &ImportUiController::importFinished, this, [this]() {
            if (!m_importStarted) return;
            m_importStarted = false;
            const QString serverId = findServerForApiKey(m_pendingApiKey);
            if (serverId.isEmpty()) {
                m_busy = false;
                setMessage(tr("Подписка добавлена, но сервер не найден. Сеанс сохранён — повторите настройку."));
                return;
            }
            startProvisioning(serverId);
        });
        connect(m_importer, &ImportUiController::importErrorOccurred, this, [this](ErrorCode error, bool) {
            if (!m_importStarted) return;
            m_importStarted = false;
            const QString serverId = findServerForApiKey(m_pendingApiKey);
            if (error == ErrorCode::ApiConfigAlreadyAdded && !serverId.isEmpty()) {
                startProvisioning(serverId);
                return;
            }
            m_busy = false;
            setMessage(tr("Не удалось загрузить доступ. Вход сохранён — повторите настройку."));
        });
    }
}

bool MayakInviteUiController::hasSession() const
{
    return !m_requiresFreshInvite && !m_settings->mayakSessionToken().isEmpty();
}

void MayakInviteUiController::setMessage(const QString &message)
{
    m_message = message;
    emit stateChanged();
}

void MayakInviteUiController::trackReply(QNetworkReply *reply)
{
    m_activeReplies.insert(reply);
    connect(reply, &QObject::destroyed, this, [this, reply]() { m_activeReplies.remove(reply); });
}

void MayakInviteUiController::invalidatePendingRequests()
{
    ++m_requestGeneration;
    ++m_accountRequestGeneration;
    const auto replies = m_activeReplies;
    for (QNetworkReply *reply : replies) {
        if (reply != nullptr) reply->abort();
    }
}

void MayakInviteUiController::updateAccountMetadata(const QJsonObject &account)
{
    const QJsonValue hasPassword = account.value(QStringLiteral("hasPassword"));
    if (!hasPassword.isBool()) {
        clearAccountMetadata();
        return;
    }
    m_accountMetadataKnown = true;
    m_accountHasPassword = hasPassword.toBool();
    m_accountEmail = account.value(QStringLiteral("email")).toString();
    m_telegramName = account.value(QStringLiteral("telegram")).toString();
    m_telegramLinked = account.value(QStringLiteral("telegramLinked")).toBool() || !m_telegramName.isEmpty();
}

void MayakInviteUiController::clearAccountMetadata()
{
    m_accountMetadataKnown = false;
    m_accountHasPassword = false;
    m_accountEmail.clear();
    m_telegramName.clear();
    m_telegramLinked = false;
}

void MayakInviteUiController::cancelPendingRequests()
{
    invalidatePendingRequests();
    m_busy = false;
    m_importStarted = false;
    m_pendingApiKey.clear();
    setMessage(tr("Операция отменена."));
}

void MayakInviteUiController::acceptInvite(const QString &invite)
{
    if (m_busy) return;
    const QString code = parseInvite(invite);
    if (code.isEmpty()) { setMessage(tr("Вставьте действительную ссылку-приглашение Маяка или код из неё.")); return; }

    m_busy = true;
    const quint64 generation = ++m_requestGeneration;
    setMessage(tr("Проверяем приглашение…"));
    QNetworkRequest request(m_apiRoot.resolved(QUrl(QStringLiteral("auth/invite"))));
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    request.setTransferTimeout(20000);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    QNetworkReply *reply = m_network->post(request, QJsonDocument(QJsonObject{{QStringLiteral("invite"), code}})
                                                    .toJson(QJsonDocument::Compact));
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, generation]() {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->readAll();
        const QJsonObject response = QJsonDocument::fromJson(body).object();
        const QString token = response.value(QStringLiteral("token")).toString();
        const bool failed = reply->error() != QNetworkReply::NoError || status < 200 || status >= 300 || token.isEmpty();
        reply->deleteLater();
        if (generation != m_requestGeneration) return;
        if (failed) {
            m_busy = false;
            if (status == 400 || status == 410) {
                setMessage(tr("Код приглашения неверен или уже использован. Попросите администратора выдать новый код."));
            } else if (status == 403) {
                setMessage(tr("Доступ пока не активен. Обратитесь к администратору Маяка."));
            } else {
                setMessage(tr("Ответ входа не получен. Если код уже использован, попросите администратора выдать новый код."));
            }
            return;
        }
        if (!m_settings->setMayakSessionToken(token)) {
            m_busy = false;
            setMessage(tr("Не удалось безопасно сохранить сеанс. Код мог быть использован; запросите новый код и повторите вход."));
            return;
        }
        m_requiresFreshInvite = false;
        updateAccountMetadata(response.value(QStringLiteral("account")).toObject());
        setMessage(tr("Вход выполнен. Настраиваем доступ…"));
        requestAppKey();
    });
}

QString MayakInviteUiController::parseInvite(const QString &invite)
{
    const QString value = invite.trimmed();
    if (value.isEmpty() || value.size() > 2048) return {};

    QString token;
    if (value.contains(QStringLiteral("://"))) {
        const QUrl url(value, QUrl::StrictMode);
        if (!url.isValid() || url.scheme() != QStringLiteral("https") ||
            url.host().compare(QStringLiteral("mayaklight.ru"), Qt::CaseInsensitive) != 0 ||
            !url.userInfo().isEmpty() || url.port(-1) != -1 || url.path() != QStringLiteral("/my/") ||
            url.hasFragment()) return {};
        const QUrlQuery query(url);
        const auto items = query.queryItems(QUrl::FullyDecoded);
        if (items.size() != 1 || items.first().first != QStringLiteral("invite")) return {};
        token = items.first().second;
    } else {
        // Compatibility with a copied raw token from older invitation messages.
        token = value;
    }
    if (token.isEmpty() || token.size() > 256 ||
        !QRegularExpression(QStringLiteral("^[A-Za-z0-9_-]+$")).match(token).hasMatch()) return {};
    return token;
}

void MayakInviteUiController::registerAccount(const QString &invite, const QString &email, const QString &password)
{
    if (m_busy) return;
    const QString token = parseInvite(invite);
    if (token.isEmpty()) { setMessage(tr("Вставьте действительную ссылку-приглашение Маяка или код из неё.")); return; }
    if (email.trimmed().isEmpty() || email.trimmed().size() > 254 || password.size() < 12 || password.size() > 128) {
        setMessage(tr("Проверьте адрес почты и пароль длиной от 12 до 128 символов.")); return;
    }
    postAuthentication(QStringLiteral("auth/register"), QJsonObject{
        {QStringLiteral("invite"), token}, {QStringLiteral("email"), email.trimmed()}, {QStringLiteral("password"), password}
    });
}

void MayakInviteUiController::login(const QString &email, const QString &password)
{
    if (m_busy) return;
    if (email.trimmed().isEmpty() || email.trimmed().size() > 254 || password.isEmpty() || password.size() > 128) {
        setMessage(tr("Введите адрес почты и пароль.")); return;
    }
    postAuthentication(QStringLiteral("auth/login"), QJsonObject{
        {QStringLiteral("email"), email.trimmed()}, {QStringLiteral("password"), password}
    });
}

void MayakInviteUiController::bindCredentials(const QString &email, const QString &password)
{
    if (m_busy) return;
    if (m_settings->mayakSessionToken().isEmpty()) { setMessage(tr("Сначала войдите по приглашению или адресу почты.")); return; }
    if (email.trimmed().isEmpty() || email.trimmed().size() > 254 || password.size() < 12 || password.size() > 128) {
        setMessage(tr("Проверьте адрес почты и пароль длиной от 12 до 128 символов.")); return;
    }
    postAuthentication(QStringLiteral("auth/credentials"), QJsonObject{
        {QStringLiteral("email"), email.trimmed()}, {QStringLiteral("password"), password}
    });
}

void MayakInviteUiController::postAuthentication(const QString &path, const QJsonObject &payload)
{
    m_busy = true;
    m_requiresFreshInvite = false;
    setMessage(tr("Выполняем вход…"));
    const quint64 generation = ++m_requestGeneration;
    QNetworkRequest request(m_apiRoot.resolved(QUrl(path)));
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    request.setTransferTimeout(20000);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    if (path == QStringLiteral("auth/credentials")) {
        request.setRawHeader("Authorization", QByteArray("Bearer ") + m_settings->mayakSessionToken().toUtf8());
    }
    QNetworkReply *reply = m_network->post(request, QJsonDocument(payload).toJson(QJsonDocument::Compact));
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, generation, path]() {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->readAll();
        const int networkError = static_cast<int>(reply->error());
        const int responseBytes = body.size();
        const QJsonObject response = QJsonDocument::fromJson(body).object();
        const QString token = response.value(QStringLiteral("token")).toString();
        const bool failed = reply->error() != QNetworkReply::NoError || status < 200 || status >= 300 || token.isEmpty();
        const QString serverMessage = QJsonDocument::fromJson(body).object().value(QStringLiteral("error")).toString().left(240);
        reply->deleteLater();
        if (generation != m_requestGeneration) return;
        if (failed) {
            qWarning().noquote().nospace()
                << "MayakAuthFailure network_error=" << networkError
                << " http_status=" << status
                << " response_bytes=" << responseBytes
                << " tls_supported=" << (QSslSocket::supportsSsl() ? 1 : 0)
                << " tls_runtime=\"" << QSslSocket::sslLibraryVersionString() << '"';
            m_busy = false;
            if (path == QStringLiteral("auth/credentials") && status == 401) {
                m_requiresFreshInvite = false;
                const bool cleared = m_settings->setMayakSessionToken(QString());
                clearAccountMetadata();
                setMessage(cleared ? tr("Вход завершился. Войдите по адресу почты и паролю.")
                                   : tr("Не удалось обновить вход. Войдите по адресу почты и паролю."));
                return;
            }
            const QString message = status == 401 ? tr("Неверный адрес почты или пароль.")
                : (status == 403 ? tr("Доступ не активен. Обратитесь к администратору Маяка.")
                   : (status == 400 || status == 410 ? tr("Приглашение неверно или истекло. Попросите администратора выдать новое.")
                      : (serverMessage.isEmpty() ? tr("Не удалось выполнить вход. Проверьте соединение и повторите попытку.") : serverMessage)));
            setMessage(message);
            return;
        }
        if (!m_settings->setMayakSessionToken(token)) {
            m_busy = false;
            setMessage(tr("Не удалось безопасно сохранить сеанс. Повторите вход."));
            return;
        }
        m_requiresFreshInvite = false;
        updateAccountMetadata(response.value(QStringLiteral("account")).toObject());
        setMessage(tr("Вход выполнен. Настраиваем доступ…"));
        requestAppKey();
    });
}

void MayakInviteUiController::logout()
{
    const QString token = m_settings->mayakSessionToken();
    invalidatePendingRequests();
    m_busy = false;
    m_requiresFreshInvite = false;
    clearAccountMetadata();
    m_pendingApiKey.clear();
    m_importStarted = false;
    m_limitDevices.clear();
    m_maxDevices = 0;
    m_telegramPollTimer->stop();
    m_telegramLinkRequestId.clear();
    m_telegramConfirmName.clear();
    m_telegramConfirmPending = false;
    m_pendingKeyReused = false;
    m_pendingDeviceId.clear();
    m_telegramConfirmId = 0;
    if (!token.isEmpty()) {
        QNetworkRequest request(m_apiRoot.resolved(QUrl(QStringLiteral("logout"))));
        request.setRawHeader("Authorization", QByteArray("Bearer ") + token.toUtf8());
        request.setTransferTimeout(5000);
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
        QNetworkReply *reply = m_network->post(request, QByteArray());
        connect(reply, &QNetworkReply::finished, reply, &QObject::deleteLater);
    }
    const bool cleared = m_settings->setMayakSessionToken(QString());
    setMessage(cleared ? tr("Вы вышли из аккаунта.") : tr("Не удалось выйти из аккаунта. Попробуйте ещё раз."));
}

void MayakInviteUiController::retrySetup()
{
    if (!hasSession() || m_busy) return;
    m_busy = true;
    setMessage(tr("Продолжаем настройку…"));
    requestAppKey();
}

void MayakInviteUiController::refreshAccount()
{
    if (!hasSession() || m_busy) return;
    const QString token = m_settings->mayakSessionToken();
    m_accountMetadataKnown = false;
    m_accountHasPassword = false;
    m_accountEmail.clear();
    m_busy = true;
    const quint64 generation = ++m_accountRequestGeneration;
    emit stateChanged();

    QNetworkRequest request(m_apiRoot.resolved(QUrl(QStringLiteral("me"))));
    request.setRawHeader("Authorization", QByteArray("Bearer ") + token.toUtf8());
    request.setTransferTimeout(20000);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    QNetworkReply *reply = m_network->get(request);
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, token, generation]() {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->readAll();
        const bool failed = reply->error() != QNetworkReply::NoError || status < 200 || status >= 300;
        const QJsonObject account = QJsonDocument::fromJson(body).object()
                                        .value(QStringLiteral("account")).toObject();
        reply->deleteLater();
        if (generation != m_accountRequestGeneration || token != m_settings->mayakSessionToken()) return;

        m_busy = false;
        if (failed) {
            if (status == 401) {
                m_requiresFreshInvite = false;
                const bool cleared = m_settings->setMayakSessionToken(QString());
                clearAccountMetadata();
                setMessage(cleared ? tr("Вход завершился. Войдите по адресу почты и паролю.")
                                   : tr("Не удалось обновить вход. Войдите по адресу почты и паролю."));
            } else {
                setMessage(tr("Не удалось проверить аккаунт. Повторите попытку."));
            }
            return;
        }
        updateAccountMetadata(account);
        if (!m_accountMetadataKnown) {
            setMessage(tr("Не удалось проверить данные аккаунта. Повторите попытку."));
            return;
        }
        emit stateChanged();
    });
}

// Ключ этого устройства (md1.…): сервер выдаёт его только этой установке и считает место в лимите один раз,
// в том числе после переустановки (по хешу постоянного ID). Старый сервер без метода — прежний ключ аккаунта.
void MayakInviteUiController::requestAppKey(const QString &replaceDeviceId)
{
    const QString token = m_settings->mayakSessionToken();
    if (token.isEmpty()) {
        m_busy = false;
        m_requiresFreshInvite = false;
        setMessage(tr("Сохранённый сеанс недоступен. Войдите по адресу почты и паролю."));
        return;
    }
    m_pendingKeyReused = false;
    m_pendingDeviceId.clear();
    QJsonObject payload{
        {QStringLiteral("installationId"), m_settings->getInstallationUuid(true)},
        {QStringLiteral("os"), mayak::device::osDescription()},
        {QStringLiteral("appVersion"), QString(APP_VERSION)},
    };
    const QString deviceHash = mayak::device::stableDeviceHash();
    if (!deviceHash.isEmpty()) payload.insert(QStringLiteral("deviceHash"), deviceHash);
    if (!replaceDeviceId.isEmpty()) payload.insert(QStringLiteral("replaceDeviceId"), replaceDeviceId);

    QNetworkRequest request(m_apiRoot.resolved(QUrl(QStringLiteral("app/device-key"))));
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    request.setRawHeader("Authorization", QByteArray("Bearer ") + token.toUtf8());
    request.setTransferTimeout(20000);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    QNetworkReply *reply = m_network->post(request, QJsonDocument(payload).toJson(QJsonDocument::Compact));
    trackReply(reply);
    const quint64 generation = m_requestGeneration;
    connect(reply, &QNetworkReply::finished, this, [this, reply, generation]() {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->readAll();
        const QJsonObject response = QJsonDocument::fromJson(body).object();
        const QString key = response.value(QStringLiteral("key")).toString();
        const bool transportFailed = reply->error() != QNetworkReply::NoError && status == 0;
        reply->deleteLater();
        if (generation != m_requestGeneration) return;
        if (!transportFailed && status >= 200 && status < 300 && !key.isEmpty()) {
            m_limitDevices.clear();
            m_maxDevices = response.value(QStringLiteral("maxDevices")).toInt();
            m_pendingKeyReused = response.value(QStringLiteral("reused")).toBool();
            m_pendingDeviceId = response.value(QStringLiteral("deviceId")).toString();
            continueWithAppKey(key);
            return;
        }
        // Нет метода на сервере (маршрут не найден, без текста ошибки) — сервер старше приложения.
        if (status == 404 && !response.contains(QStringLiteral("error"))) {
            requestLegacyAppKey();
            return;
        }
        m_busy = false;
        const QString serverMessage = response.value(QStringLiteral("error")).toString().left(240);
        if (status == 409 && response.value(QStringLiteral("code")).toString() == QStringLiteral("DEVICE_LIMIT")) {
            m_limitDevices = response.value(QStringLiteral("devices")).toArray().toVariantList();
            m_maxDevices = response.value(QStringLiteral("maxDevices")).toInt();
            setMessage(tr("На аккаунте уже %1 из %1 устройств. Выберите, какое заменить этим устройством, "
                          "или попросите администратора увеличить лимит.").arg(m_maxDevices));
            return;
        }
        if (status == 401) {
            m_requiresFreshInvite = false;
            const bool cleared = m_settings->setMayakSessionToken(QString());
            clearAccountMetadata();
            setMessage(cleared ? tr("Вход завершился. Войдите по адресу почты и паролю.")
                               : tr("Не удалось обновить вход. Войдите по адресу почты и паролю."));
        } else if (status == 403) {
            setMessage(serverMessage.isEmpty()
                           ? tr("Доступ сейчас не активен. Проверьте его у администратора Маяка и повторите позже.")
                           : serverMessage);
        } else if (status == 404 || status == 400) {
            setMessage(serverMessage.isEmpty() ? tr("Не удалось настроить доступ. Повторите настройку.") : serverMessage);
        } else {
            setMessage(tr("Не удалось настроить доступ. Вход сохранён; проверьте соединение и повторите настройку."));
        }
    });
}

void MayakInviteUiController::replaceDevice(const QString &deviceId)
{
    if (m_busy || !hasSession() || deviceId.isEmpty()) return;
    bool known = false;
    for (const QVariant &item : std::as_const(m_limitDevices)) {
        if (item.toMap().value(QStringLiteral("id")).toString() == deviceId) known = true;
    }
    if (!known) return;
    m_busy = true;
    setMessage(tr("Заменяем устройство…"));
    requestAppKey(deviceId);
}

void MayakInviteUiController::linkTelegram()
{
    if (m_busy || !hasSession() || !m_telegramLinkRequestId.isEmpty()) return;
    m_busy = true;
    setMessage(tr("Готовим привязку Telegram…"));
    const quint64 generation = ++m_accountRequestGeneration;
    QNetworkRequest request(m_apiRoot.resolved(QUrl(QStringLiteral("auth/telegram/link"))));
    request.setRawHeader("Authorization", QByteArray("Bearer ") + m_settings->mayakSessionToken().toUtf8());
    request.setTransferTimeout(20000);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    QNetworkReply *reply = m_network->post(request, QByteArray());
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, generation]() {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QJsonObject response = QJsonDocument::fromJson(reply->readAll()).object();
        reply->deleteLater();
        if (generation != m_accountRequestGeneration) return;
        m_busy = false;
        const QString requestId = response.value(QStringLiteral("requestId")).toString();
        const QUrl botUrl(response.value(QStringLiteral("botUrl")).toString(), QUrl::StrictMode);
        // Открываем только ссылку на бота в Telegram, а не любой адрес из ответа.
        const bool botLink = botUrl.isValid() && botUrl.scheme() == QStringLiteral("https")
                             && botUrl.host() == QStringLiteral("t.me") && botUrl.userInfo().isEmpty() && botUrl.port(-1) == -1
                             && !botUrl.hasFragment()
                             && QRegularExpression(QStringLiteral("^/[A-Za-z0-9_]{3,64}$")).match(botUrl.path()).hasMatch();
        if (status == 200 && !requestId.isEmpty() && botLink
            && QRegularExpression(QStringLiteral("^[A-Za-z0-9_-]{8,64}$")).match(requestId).hasMatch()) {
            m_telegramLinkRequestId = requestId;
            m_telegramPolls = 0;
            m_telegramConfirmName.clear();
            m_telegramConfirmPending = false;
            m_telegramPollTimer->start();
            setMessage(tr("Откройте Telegram и нажмите «Запустить» в чате с ботом Маяка, затем вернитесь сюда и подтвердите привязку."));
            emit openExternalUrl(botUrl.toString());
            return;
        }
        if (status == 409) {
            m_telegramName = response.value(QStringLiteral("telegram")).toString();
            m_telegramLinked = true;
            setMessage(tr("Telegram уже привязан к аккаунту."));
        } else if (status == 401) {
            cancelTelegramLink();
            m_requiresFreshInvite = false;
            const bool cleared = m_settings->setMayakSessionToken(QString());
            clearAccountMetadata();
            setMessage(cleared ? tr("Вход завершился. Войдите по адресу почты и паролю.")
                               : tr("Не удалось обновить вход. Войдите по адресу почты и паролю."));
        } else if (status == 503) {
            setMessage(tr("Привязка Telegram пока недоступна."));
        } else {
            setMessage(tr("Не удалось начать привязку Telegram. Повторите попытку."));
        }
    });
}

void MayakInviteUiController::cancelTelegramLink()
{
    m_telegramPollTimer->stop();
    m_telegramLinkRequestId.clear();
    m_telegramConfirmName.clear();
    m_telegramConfirmPending = false;
    emit stateChanged();
}

// Второй шаг: человек подтверждает в приложении Telegram, который нажал «Запустить» в боте.
// Без этого шага пересланная ссылка на бота не даёт постороннему доступ к аккаунту.
void MayakInviteUiController::confirmTelegramLink()
{
    if (m_busy || !hasSession() || m_telegramLinkRequestId.isEmpty() || !m_telegramConfirmPending) return;
    m_busy = true;
    setMessage(tr("Привязываем Telegram…"));
    const QString requestId = m_telegramLinkRequestId;
    const quint64 generation = ++m_accountRequestGeneration;
    QNetworkRequest request(m_apiRoot.resolved(QUrl(QStringLiteral("auth/telegram/link/") + requestId + QStringLiteral("/confirm"))));
    request.setRawHeader("Authorization", QByteArray("Bearer ") + m_settings->mayakSessionToken().toUtf8());
    request.setTransferTimeout(20000);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    // Сервер привяжет только тот Telegram, который человек видел в вопросе.
    QNetworkReply *reply = m_network->post(request, QJsonDocument(QJsonObject{
        {QStringLiteral("telegramId"), QString::number(m_telegramConfirmId)}}).toJson(QJsonDocument::Compact));
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, generation, requestId]() {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QJsonObject response = QJsonDocument::fromJson(reply->readAll()).object();
        reply->deleteLater();
        if (generation != m_accountRequestGeneration || requestId != m_telegramLinkRequestId) return;
        m_busy = false;
        if (status == 200 && response.value(QStringLiteral("status")).toString() == QStringLiteral("linked")) {
            m_telegramLinkRequestId.clear();
            m_telegramConfirmName.clear();
            m_telegramConfirmPending = false;
            m_telegramLinked = true;
            m_telegramName = response.value(QStringLiteral("telegram")).toString();
            setMessage(tr("Telegram привязан. Уведомления о новых устройствах будут приходить туда."));
            return;
        }
        const QString serverMessage = response.value(QStringLiteral("error")).toString().left(240);
        if (status == 410) {
            cancelTelegramLink();
            setMessage(tr("Запрос привязки устарел. Нажмите «Привязать Telegram» ещё раз."));
        } else if (status == 401) {
            cancelTelegramLink();
            m_requiresFreshInvite = false;
            const bool cleared = m_settings->setMayakSessionToken(QString());
            clearAccountMetadata();
            setMessage(cleared ? tr("Вход завершился. Войдите по адресу почты и паролю.")
                               : tr("Не удалось обновить вход. Войдите по адресу почты и паролю."));
        } else {
            setMessage(serverMessage.isEmpty() ? tr("Не удалось привязать Telegram. Повторите попытку.") : serverMessage);
        }
    });
}

void MayakInviteUiController::pollTelegramLink()
{
    if (m_telegramLinkRequestId.isEmpty()) { m_telegramPollTimer->stop(); return; }
    if (m_telegramPollInFlight) return; // предыдущий опрос ещё идёт — не накладываем запросы
    if (++m_telegramPolls > 120) { // около 10 минут — столько живёт запрос привязки
        cancelTelegramLink();
        setMessage(tr("Время привязки Telegram истекло. Нажмите «Привязать Telegram» ещё раз."));
        return;
    }
    const QString requestId = m_telegramLinkRequestId;
    QNetworkRequest request(m_apiRoot.resolved(QUrl(QStringLiteral("auth/telegram/") + requestId)));
    request.setTransferTimeout(10000);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    m_telegramPollInFlight = true;
    QNetworkReply *reply = m_network->get(request);
    trackReply(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, requestId]() {
        m_telegramPollInFlight = false;
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QJsonObject response = QJsonDocument::fromJson(reply->readAll()).object();
        reply->deleteLater();
        if (requestId != m_telegramLinkRequestId) return;
        const QString state = status == 200 ? response.value(QStringLiteral("status")).toString() : QString();
        if (state == QStringLiteral("confirm")) {
            m_telegramPollTimer->stop();
            m_telegramConfirmPending = true;
            m_telegramConfirmId = response.value(QStringLiteral("telegramId")).toVariant().toLongLong();
            const QString username = response.value(QStringLiteral("telegram")).toString();
            // Имя (first_name) любой может выставить себе сам — показываем его с пометкой, а @username — как есть.
            m_telegramConfirmName = !username.isEmpty() ? QStringLiteral("@") + username
                : tr("%1 (без имени пользователя)").arg(response.value(QStringLiteral("telegramName")).toString().left(64));
            setMessage(tr("Проверьте, что это ваш Telegram, и подтвердите привязку."));
        } else if (state == QStringLiteral("linked")) {
            m_telegramPollTimer->stop();
            m_telegramLinkRequestId.clear();
            m_telegramLinked = true;
            m_telegramName = response.value(QStringLiteral("telegram")).toString();
            setMessage(tr("Telegram привязан. Уведомления о новых устройствах будут приходить туда."));
        } else if (status == 410) {
            cancelTelegramLink();
            setMessage(tr("Ссылка для привязки устарела. Нажмите «Привязать Telegram» ещё раз."));
        }
        // 202 и сетевые ошибки — продолжаем ждать.
    });
}

void MayakInviteUiController::requestLegacyAppKey()
{
    const QString token = m_settings->mayakSessionToken();
    if (token.isEmpty()) {
        m_busy = false;
        m_requiresFreshInvite = false;
        setMessage(tr("Сохранённый сеанс недоступен. Войдите по адресу почты и паролю."));
        return;
    }
    QNetworkRequest request(m_apiRoot.resolved(QUrl(QStringLiteral("app-key"))));
    request.setRawHeader("Authorization", QByteArray("Bearer ") + token.toUtf8());
    request.setTransferTimeout(20000);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    QNetworkReply *reply = m_network->get(request);
    trackReply(reply);
    const quint64 generation = m_requestGeneration;
    connect(reply, &QNetworkReply::finished, this, [this, reply, generation]() {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->readAll();
        const QString key = QJsonDocument::fromJson(body).object().value(QStringLiteral("key")).toString();
        const bool transportFailed = reply->error() != QNetworkReply::NoError;
        const bool failed = transportFailed || status < 200 || status >= 300 || key.isEmpty();
        reply->deleteLater();
        if (generation != m_requestGeneration) return;
        if (failed) {
            m_busy = false;
            if (status == 401) {
                m_requiresFreshInvite = false;
                const bool cleared = m_settings->setMayakSessionToken(QString());
                clearAccountMetadata();
                setMessage(cleared
                                   ? tr("Вход завершился. Войдите по адресу почты и паролю.")
                                   : tr("Не удалось обновить вход. Войдите по адресу почты и паролю."));
            } else if (status == 403) {
                setMessage(tr("Доступ сейчас не активен. Проверьте его у администратора Маяка и повторите позже."));
            } else {
                setMessage(tr("Не удалось настроить доступ. Вход сохранён; проверьте соединение и повторите настройку."));
            }
            return;
        }
        continueWithAppKey(key);
    });
}

void MayakInviteUiController::continueWithAppKey(const QString &key)
{
    if (!m_importer->extractConfigFromData(key)) {
        m_busy = false;
        setMessage(tr("Не удалось прочитать данные доступа. Вход сохранён; повторите настройку."));
        return;
    }
    const QJsonObject shell = QJsonDocument::fromJson(m_importer->getConfig().toUtf8()).object();
    m_pendingApiKey = shell.value(QStringLiteral("auth_data")).toObject().value(QStringLiteral("api_key")).toString();
    if (m_pendingApiKey.isEmpty()) {
        m_busy = false;
        setMessage(tr("Сервер не вернул ключ доступа. Вход сохранён; повторите настройку."));
        return;
    }

    const QString existingServerId = findServerForApiKey(m_pendingApiKey);
    if (!existingServerId.isEmpty()) {
        startProvisioning(existingServerId);
        return;
    }
    // Пришёл ключ устройства (md1.…), а сервер Маяка уже есть с прежним ключом (ключ аккаунта или старый токен):
    // меняем ключ на месте, чтобы в списке не появился второй «Маяк». Ключи аккаунта по-прежнему импортируются.
    // Только если сервер подтвердил, что это устройство уже было в этом аккаунте (reused): при входе в другой аккаунт
    // в старой подписке осталась бы пара AWG чужого устройства, и сервер отказал бы «ключ уже используется».
    const QString managedServerId = m_pendingApiKey.startsWith(QStringLiteral("md1.")) && m_pendingKeyReused
        ? findServerForDevice() : QString();
    if (!managedServerId.isEmpty() && m_serversController->setApiV2AuthKey(managedServerId, m_pendingApiKey)) {
        startProvisioning(managedServerId);
        return;
    }
    m_importStarted = true;
    m_importer->importConfig();
}

// Подписка именно этого устройства: по записи deviceId → сервер. Записей ещё нет (первый переход со старого ключа
// аккаунта) — только если в списке ровно один сервер Маяка; иначе не угадываем и импортируем новую подписку.
QString MayakInviteUiController::findServerForDevice() const
{
    if (m_serversController == nullptr) return {};
    const QString mapped = m_settings->mayakServerForDevice(m_pendingDeviceId);
    if (!mapped.isEmpty())
        return m_settings->isMayakManagedServer(mapped) && m_serversController->apiV2Config(mapped) ? mapped : QString();
    if (m_settings->hasMayakDeviceServers()) return {};
    int managed = 0;
    for (int index = 0; index < m_serversController->getServersCount(); ++index) {
        const QString serverId = m_serversController->getServerId(index);
        if (m_settings->isMayakManagedServer(serverId) && m_serversController->apiV2Config(serverId)) ++managed;
    }
    return managed == 1 ? findManagedMayakServer() : QString();
}

QString MayakInviteUiController::findManagedMayakServer() const
{
    if (m_serversController == nullptr) return {};
    const QString defaultId = m_serversController->getDefaultServerId();
    if (m_settings->isMayakManagedServer(defaultId) && m_serversController->apiV2Config(defaultId)) return defaultId;
    for (int index = 0; index < m_serversController->getServersCount(); ++index) {
        const QString serverId = m_serversController->getServerId(index);
        if (m_settings->isMayakManagedServer(serverId) && m_serversController->apiV2Config(serverId)) return serverId;
    }
    return {};
}

QString MayakInviteUiController::findServerForApiKey(const QString &apiKey) const
{
    if (apiKey.isEmpty()) return {};
    for (int index = 0; index < m_serversController->getServersCount(); ++index) {
        const QString serverId = m_serversController->getServerId(index);
        const auto config = m_serversController->apiV2Config(serverId);
        if (config && config->authData.apiKey == apiKey) return serverId;
    }
    return {};
}

void MayakInviteUiController::startProvisioning(const QString &serverId)
{
    if (serverId.isEmpty()) {
        m_busy = false;
        setMessage(tr("Не удалось найти сервер доступа. Вход сохранён — повторите настройку."));
        return;
    }
    if (!m_settings->markMayakManagedServer(serverId)) {
        m_busy = false;
        setMessage(tr("Не удалось сохранить доступ на устройстве. Повторите настройку."));
        return;
    }
    m_busy = true;
    setMessage(tr("Получаем конфигурацию сервера…"));
    const quint64 generation = m_requestGeneration;
    const QPointer<MayakInviteUiController> self(this);
    m_provisioner->provision(serverId, [self, generation]() {
        return !self.isNull() && self->m_requestGeneration == generation;
    }, [this, serverId, generation](ErrorCode error) {
        QMetaObject::invokeMethod(this, [this, serverId, generation, error]() {
            if (generation == m_requestGeneration) onProvisioningFinished(serverId, error);
        }, Qt::QueuedConnection);
    });
}

void MayakInviteUiController::onProvisioningFinished(const QString &serverId, ErrorCode error)
{
    m_busy = false;
    if (error != ErrorCode::NoError) {
        if (error == ErrorCode::ApiConfigLimitError) {
            setMessage(tr("Достигнут лимит устройств аккаунта. Удалите ненужное устройство в кабинете или попросите администратора увеличить лимит, затем нажмите «Повторить настройку». Вход сохранён."));
        } else if (error == ErrorCode::ApiConfigTimeoutError) {
            setMessage(tr("Сервер настроек не ответил вовремя. Проверьте интернет и нажмите «Повторить настройку». Вход сохранён."));
        } else {
            setMessage(tr("Не удалось получить настройки (код %1). Вход сохранён; нажмите «Повторить настройку».").arg(static_cast<int>(error)));
        }
        return;
    }
    m_serversController->setDefaultServer(serverId);
    if (!m_pendingDeviceId.isEmpty()) m_settings->setMayakServerForDevice(m_pendingDeviceId, serverId);
    m_requiresFreshInvite = false;
    setMessage(tr("Доступ настроен. Сеанс сохранён для следующего входа. Можно подключаться кнопкой на главном экране."));
    emit setupFinished();
}
