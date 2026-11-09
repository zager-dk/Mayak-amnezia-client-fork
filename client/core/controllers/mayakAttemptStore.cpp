#include "mayakAttemptStore.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSet>
#include <QThread>
#include <QUrl>
#include <QUuid>

namespace mayak::attempts {
namespace {
constexpr auto ledgerKey = "Mayak/pendingAttempts";
constexpr int maxRecords = 32;
constexpr qsizetype maxLedgerBytes = 128 * 1024;
constexpr int maxOpaqueIdLength = 128;

bool boundedText(const QString &value, int maxLength, bool allowEmpty = false)
{
    return (allowEmpty || !value.isEmpty()) && value.size() <= maxLength
        && !value.contains(QChar::Null) && !value.contains(QLatin1Char('\r'))
        && !value.contains(QLatin1Char('\n'));
}

bool validOpaqueId(const QString &value)
{
    return value.size() >= 16 && value.size() <= maxOpaqueIdLength
        && QRegularExpression(QStringLiteral("^[A-Za-z0-9_-]+$")).match(value).hasMatch();
}

bool validUuid(const QString &value)
{
    if (!boundedText(value, 64)) return false;
    const QUuid uuid(value);
    return !uuid.isNull() && uuid.toString(QUuid::WithoutBraces).compare(value, Qt::CaseInsensitive) == 0;
}

bool validCandidate(const QString &value)
{
    static const QRegularExpression guid(QStringLiteral("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"));
    return guid.match(value).hasMatch();
}

bool validAuthority(const CleanupAuthorityInput &authority)
{
    const QUrl endpoint(authority.gatewayEndpoint, QUrl::StrictMode);
    if (!endpoint.isValid() || endpoint.scheme() != QStringLiteral("https")
        || endpoint.host().compare(QStringLiteral("mayaklight.ru"), Qt::CaseInsensitive) != 0
        || !(endpoint.path() == QStringLiteral("/gw") || endpoint.path().startsWith(QStringLiteral("/gw/")))
        || !endpoint.userName().isEmpty() || !endpoint.password().isEmpty()
        || endpoint.hasQuery() || endpoint.hasFragment()
        || (endpoint.port(-1) != -1 && endpoint.port() != 443)) return false;
    const QByteArray publicKey = QByteArray::fromBase64(authority.publicKey.toLatin1());
    static const QRegularExpression countryCode(QStringLiteral("^[A-Za-z0-9_-]{1,32}$"));
    return validUuid(authority.installationUuid)
        && publicKey.size() == 32 && publicKey.toBase64() == authority.publicKey.toLatin1()
        && boundedText(authority.deviceApiKey, 4096)
        && boundedText(authority.serviceType, 64)
        && boundedText(authority.serviceProtocol, 64)
        && boundedText(authority.userCountryCode, 32, true)
        && boundedText(authority.serverCountryCode, 32, true)
        && (authority.userCountryCode.isEmpty() || countryCode.match(authority.userCountryCode).hasMatch())
        && (authority.serverCountryCode.isEmpty() || countryCode.match(authority.serverCountryCode).hasMatch());
}

bool validIdentity(const AttemptIdentity &identity)
{
    return boundedText(identity.localSubscriptionId, 256)
        && validOpaqueId(identity.accountIdentityEpoch)
        && validOpaqueId(identity.cycleToken)
        && validOpaqueId(identity.attemptId)
        && validCandidate(identity.candidateId);
}

QJsonObject identityJson(const AttemptIdentity &identity)
{
    return {{QStringLiteral("subscription"), identity.localSubscriptionId},
            {QStringLiteral("account_epoch"), identity.accountIdentityEpoch},
            {QStringLiteral("cycle_token"), identity.cycleToken},
            {QStringLiteral("attempt_id"), identity.attemptId},
            {QStringLiteral("candidate_id"), identity.candidateId}};
}

QJsonObject authorityJson(const CleanupAuthorityInput &authority)
{
    return {{QStringLiteral("gateway_endpoint"), authority.gatewayEndpoint},
            {QStringLiteral("installation_uuid"), authority.installationUuid},
            {QStringLiteral("public_key"), authority.publicKey},
            {QStringLiteral("device_api_key"), authority.deviceApiKey},
            {QStringLiteral("service_type"), authority.serviceType},
            {QStringLiteral("service_protocol"), authority.serviceProtocol},
            {QStringLiteral("user_country_code"), authority.userCountryCode},
            {QStringLiteral("server_country_code"), authority.serverCountryCode}};
}

bool hasOnlyKeys(const QJsonObject &object, const QStringList &keys)
{
    if (object.size() != keys.size()) return false;
    for (const QString &key : keys) if (!object.contains(key)) return false;
    return true;
}

bool readString(const QJsonObject &object, const QString &key, QString *out)
{
    const QJsonValue value = object.value(key);
    if (!value.isString()) return false;
    *out = value.toString();
    return true;
}

bool decodeRecord(const QJsonValue &value, AttemptInput *out, bool *mayHaveStarted, bool *tombstoned)
{
    if (!value.isObject() || out == nullptr || mayHaveStarted == nullptr || tombstoned == nullptr) return false;
    const QJsonObject object = value.toObject();
    static const QStringList recordKeys = {QStringLiteral("identity"), QStringLiteral("authority"),
        QStringLiteral("may_have_started"), QStringLiteral("tombstoned"), QStringLiteral("allocation_id")};
    static const QStringList identityKeys = {QStringLiteral("subscription"), QStringLiteral("account_epoch"),
        QStringLiteral("cycle_token"), QStringLiteral("attempt_id"), QStringLiteral("candidate_id")};
    static const QStringList authorityKeys = {QStringLiteral("gateway_endpoint"), QStringLiteral("installation_uuid"),
        QStringLiteral("public_key"), QStringLiteral("device_api_key"), QStringLiteral("service_type"),
        QStringLiteral("service_protocol"), QStringLiteral("user_country_code"), QStringLiteral("server_country_code")};
    if (!hasOnlyKeys(object, recordKeys) || !object.value(QStringLiteral("identity")).isObject()
        || !object.value(QStringLiteral("authority")).isObject()
        || !object.value(QStringLiteral("may_have_started")).isBool()
        || !object.value(QStringLiteral("tombstoned")).isBool()) return false;
    const QJsonObject identityObject = object.value(QStringLiteral("identity")).toObject();
    const QJsonObject authorityObject = object.value(QStringLiteral("authority")).toObject();
    if (!hasOnlyKeys(identityObject, identityKeys) || !hasOnlyKeys(authorityObject, authorityKeys)) return false;
    AttemptIdentity identity;
    CleanupAuthorityInput authority;
    if (!readString(identityObject, QStringLiteral("subscription"), &identity.localSubscriptionId)
        || !readString(identityObject, QStringLiteral("account_epoch"), &identity.accountIdentityEpoch)
        || !readString(identityObject, QStringLiteral("cycle_token"), &identity.cycleToken)
        || !readString(identityObject, QStringLiteral("attempt_id"), &identity.attemptId)
        || !readString(identityObject, QStringLiteral("candidate_id"), &identity.candidateId)
        || !readString(authorityObject, QStringLiteral("gateway_endpoint"), &authority.gatewayEndpoint)
        || !readString(authorityObject, QStringLiteral("installation_uuid"), &authority.installationUuid)
        || !readString(authorityObject, QStringLiteral("public_key"), &authority.publicKey)
        || !readString(authorityObject, QStringLiteral("device_api_key"), &authority.deviceApiKey)
        || !readString(authorityObject, QStringLiteral("service_type"), &authority.serviceType)
        || !readString(authorityObject, QStringLiteral("service_protocol"), &authority.serviceProtocol)
        || !readString(authorityObject, QStringLiteral("user_country_code"), &authority.userCountryCode)
        || !readString(authorityObject, QStringLiteral("server_country_code"), &authority.serverCountryCode)) return false;
    QString allocationId;
    if (!readString(object, QStringLiteral("allocation_id"), &allocationId)
        || !validIdentity(identity) || !validAuthority(authority)
        || !boundedText(allocationId, 128, true)
        || (!allocationId.isEmpty() && !validCandidate(allocationId))) return false;
    out->identity = identity;
    out->cleanupAuthority = authority;
    out->allocationId = allocationId;
    *mayHaveStarted = object.value(QStringLiteral("may_have_started")).toBool();
    *tombstoned = object.value(QStringLiteral("tombstoned")).toBool();
    return true;
}

QJsonObject encodeRecord(const AttemptRecord &record)
{
    CleanupAuthorityInput authority{record.gatewayEndpoint(), record.installationUuid(), record.publicKey(),
        record.deviceApiKey(), record.serviceType(), record.serviceProtocol(), record.userCountryCode(), record.serverCountryCode()};
    return {{QStringLiteral("identity"), identityJson(record.identity())},
            {QStringLiteral("authority"), authorityJson(authority)},
            {QStringLiteral("may_have_started"), record.mayHaveStarted()},
            {QStringLiteral("tombstoned"), record.tombstoned()},
            {QStringLiteral("allocation_id"), record.allocationId()}};
}

QByteArray encodeLedger(const QList<AttemptRecord> &records)
{
    QJsonArray array;
    for (const AttemptRecord &record : records) array.append(encodeRecord(record));
    return QJsonDocument(QJsonObject{{QStringLiteral("version"), 1}, {QStringLiteral("records"), array}})
        .toJson(QJsonDocument::Compact);
}

LoadResult failed(Error error)
{
    return {false, error, {}};
}
}

bool AttemptIdentity::operator==(const AttemptIdentity &other) const
{
    return localSubscriptionId == other.localSubscriptionId
        && accountIdentityEpoch == other.accountIdentityEpoch && cycleToken == other.cycleToken
        && attemptId == other.attemptId && candidateId == other.candidateId;
}

AttemptRecord::AttemptRecord(AttemptIdentity identity, CleanupAuthorityInput authority, bool mayHaveStarted,
                             bool tombstoned, QString allocationId)
    : m_identity(std::move(identity)), m_authority(std::move(authority)), m_mayHaveStarted(mayHaveStarted),
      m_tombstoned(tombstoned), m_allocationId(std::move(allocationId)) {}

AttemptIdentity AttemptRecord::identity() const { return m_identity; }
QString AttemptRecord::gatewayEndpoint() const { return m_authority.gatewayEndpoint; }
QString AttemptRecord::installationUuid() const { return m_authority.installationUuid; }
QString AttemptRecord::publicKey() const { return m_authority.publicKey; }
QString AttemptRecord::deviceApiKey() const { return m_authority.deviceApiKey; }
QString AttemptRecord::serviceType() const { return m_authority.serviceType; }
QString AttemptRecord::serviceProtocol() const { return m_authority.serviceProtocol; }
QString AttemptRecord::userCountryCode() const { return m_authority.userCountryCode; }
QString AttemptRecord::serverCountryCode() const { return m_authority.serverCountryCode; }
bool AttemptRecord::mayHaveStarted() const { return m_mayHaveStarted; }
bool AttemptRecord::tombstoned() const { return m_tombstoned; }
QString AttemptRecord::allocationId() const { return m_allocationId; }

MayakAttemptStore::MayakAttemptStore(SecureQSettings *settings, QObject *parent)
    : QObject(parent), m_settings(settings) {}

bool MayakAttemptStore::onOwnerThread() const { return QThread::currentThread() == thread(); }

LoadResult MayakAttemptStore::load() const
{
    if (!onOwnerThread()) return failed(Error::WrongThread);
    if (m_settings == nullptr) return failed(Error::StorageUnavailable);
    // A failed QSettings sync may already have changed its in-memory value.
    // Keep the exact intended encrypted ledger locally and require a successful
    // sync before treating any subsequent read as authoritative.
    if (!m_uncertainCommit.isEmpty()) {
        if (!m_settings->setEncryptedValueAndSync(QString::fromLatin1(ledgerKey), m_uncertainCommit))
            return failed(Error::StorageUnavailable);
        m_uncertainCommit.clear();
    }
    const auto state = m_settings->storedValueClass(QString::fromLatin1(ledgerKey));
    if (state == SecureQSettings::StoredValueClass::Missing) return {true, Error::None, {}};
    if (state != SecureQSettings::StoredValueClass::Encrypted) return failed(Error::Corrupt);
    if (!m_settings->encryptedStorageAvailable()) return failed(Error::StorageUnavailable);
    const QVariant stored = m_settings->value(QString::fromLatin1(ledgerKey));
    if (!stored.isValid() || stored.userType() != QMetaType::QByteArray) return failed(Error::Corrupt);
    const QByteArray bytes = stored.toByteArray();
    if (bytes.isEmpty() || bytes.size() > maxLedgerBytes) return failed(Error::Corrupt);
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(bytes, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) return failed(Error::Corrupt);
    const QJsonObject root = document.object();
    if (!hasOnlyKeys(root, {QStringLiteral("version"), QStringLiteral("records")})
        || !root.value(QStringLiteral("version")).isDouble() || root.value(QStringLiteral("version")).toInt(-1) != 1
        || !root.value(QStringLiteral("records")).isArray()) return failed(Error::Corrupt);
    const QJsonArray array = root.value(QStringLiteral("records")).toArray();
    if (array.size() > maxRecords) return failed(Error::Corrupt);
    QList<AttemptRecord> records;
    QSet<QString> attemptIds;
    for (const QJsonValue &value : array) {
        AttemptInput decoded;
        bool mayHaveStarted = false;
        bool tombstoned = false;
        if (!decodeRecord(value, &decoded, &mayHaveStarted, &tombstoned)
            || attemptIds.contains(decoded.identity.attemptId)) return failed(Error::Corrupt);
        const AttemptRecord record(decoded.identity, decoded.cleanupAuthority, mayHaveStarted, tombstoned, decoded.allocationId);
        attemptIds.insert(record.identity().attemptId);
        records.append(record);
    }
    return {true, Error::None, records};
}

MutationResult MayakAttemptStore::appendBeforeAcquire(const AttemptInput &attempt)
{
    return mutate(Mutation::Append, attempt.identity, &attempt);
}

MutationResult MayakAttemptStore::markMayHaveStarted(const AttemptIdentity &identity)
{
    return mutate(Mutation::MarkStarted, identity, nullptr);
}

MutationResult MayakAttemptStore::attachAllocation(const AttemptIdentity &identity, const QString &allocationId)
{
    return mutate(Mutation::AttachAllocation, identity, nullptr, allocationId);
}

MutationResult MayakAttemptStore::markRetired(const AttemptIdentity &identity)
{
    return mutate(Mutation::Retire, identity, nullptr);
}

MutationResult MayakAttemptStore::removeAfterConfirmedCleanup(const AttemptIdentity &identity)
{
    return mutate(Mutation::Remove, identity, nullptr);
}

MutationResult MayakAttemptStore::mutate(Mutation operation, const AttemptIdentity &identity,
                                         const AttemptInput *input, const QString &allocationId)
{
    if (!onOwnerThread()) return {false, Error::WrongThread, {}};
    const LoadResult current = load();
    if (!current.ok) return {false, current.error, {}};
    QList<AttemptRecord> updated;
    int matchIndex = -1;
    for (int i = 0; i < current.records.size(); ++i) {
        if (current.records.at(i).identity() == identity) matchIndex = i;
        else if (current.records.at(i).identity().attemptId == identity.attemptId)
            return {false, Error::Conflict, {}};
    }
    if (operation == Mutation::Append) {
        if (input == nullptr || !validIdentity(identity) || !validAuthority(input->cleanupAuthority)
            || input->mayHaveStarted || input->tombstoned || !input->allocationId.isEmpty()) return {false, Error::Invalid, {}};
        if (matchIndex >= 0) return {false, Error::Conflict, {}};
        if (current.records.size() >= maxRecords) return {false, Error::Full, {}};
        updated = current.records;
        updated.append(AttemptRecord(identity, input->cleanupAuthority, false, false, {}));
    } else if (operation == Mutation::Remove) {
        if (matchIndex < 0) return {true, Error::None, current.records};
        for (int i = 0; i < current.records.size(); ++i) if (i != matchIndex) updated.append(current.records.at(i));
        // Keep an encrypted, synchronously committed empty ledger. QSettings
        // removal can fail after mutating its in-memory view, making Missing
        // indistinguishable from a durable deletion in this process.
    } else {
        if (matchIndex < 0) return {false, Error::Conflict, {}};
        const AttemptRecord &old = current.records.at(matchIndex);
        if (operation == Mutation::MarkStarted) {
            if (old.tombstoned()) return {false, Error::Conflict, {}};
            if (old.mayHaveStarted()) return {true, Error::None, current.records};
        } else if (operation == Mutation::AttachAllocation) {
            if (!validCandidate(allocationId)) return {false, Error::Invalid, {}};
            if (!old.allocationId().isEmpty()) {
                if (old.allocationId() == allocationId) return {true, Error::None, current.records};
                return {false, Error::Conflict, {}};
            }
        }
        for (int i = 0; i < current.records.size(); ++i) {
            const AttemptRecord &record = current.records.at(i);
            if (i != matchIndex) { updated.append(record); continue; }
            CleanupAuthorityInput authority{record.gatewayEndpoint(), record.installationUuid(), record.publicKey(),
                record.deviceApiKey(), record.serviceType(), record.serviceProtocol(), record.userCountryCode(), record.serverCountryCode()};
            const bool started = record.mayHaveStarted() || operation == Mutation::MarkStarted;
            const bool tombstoned = record.tombstoned() || operation == Mutation::Retire;
            const QString allocation = operation == Mutation::AttachAllocation ? allocationId : record.allocationId();
            updated.append(AttemptRecord(identity, authority, started, tombstoned, allocation));
        }
    }
    const QByteArray encoded = encodeLedger(updated);
    if (encoded.isEmpty() || encoded.size() > maxLedgerBytes) return {false, Error::Full, {}};
    if (m_settings == nullptr) return {false, Error::StorageUnavailable, {}};
    if (!m_settings->setEncryptedValueAndSync(QString::fromLatin1(ledgerKey), encoded)) {
        m_uncertainCommit = encoded;
        return {false, Error::StorageUnavailable, {}};
    }
    return {true, Error::None, updated};
}

} // namespace mayak::attempts
