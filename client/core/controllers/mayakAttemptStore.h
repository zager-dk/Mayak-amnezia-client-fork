#ifndef MAYAKATTEMPTSTORE_H
#define MAYAKATTEMPTSTORE_H

#include <QList>
#include <QObject>
#include <QString>

#include "secureQSettings.h"

namespace mayak::attempts {

struct CleanupAuthorityInput
{
    QString gatewayEndpoint;
    QString installationUuid;
    QString publicKey;
    QString deviceApiKey;
    QString serviceType;
    QString serviceProtocol;
    QString userCountryCode;
    QString serverCountryCode;
};

struct AttemptIdentity
{
    QString localSubscriptionId;
    QString accountIdentityEpoch;
    QString cycleToken;
    QString attemptId;
    QString candidateId;

    bool operator==(const AttemptIdentity &other) const;
};

struct AttemptInput
{
    AttemptIdentity identity;
    CleanupAuthorityInput cleanupAuthority;
    bool mayHaveStarted = false;
    bool tombstoned = false;
    QString allocationId;
};

class AttemptRecord final
{
public:
    AttemptIdentity identity() const;
    QString gatewayEndpoint() const;
    QString installationUuid() const;
    QString publicKey() const;
    QString deviceApiKey() const;
    QString serviceType() const;
    QString serviceProtocol() const;
    QString userCountryCode() const;
    QString serverCountryCode() const;
    bool mayHaveStarted() const;
    bool tombstoned() const;
    QString allocationId() const;

private:
    friend class MayakAttemptStore;
    AttemptRecord(AttemptIdentity identity, CleanupAuthorityInput authority, bool mayHaveStarted,
                  bool tombstoned, QString allocationId);

    AttemptIdentity m_identity;
    CleanupAuthorityInput m_authority;
    bool m_mayHaveStarted;
    bool m_tombstoned;
    QString m_allocationId;
};

enum class Error { None, StorageUnavailable, Corrupt, Conflict, Full, Invalid, WrongThread };

struct LoadResult
{
    bool ok = false;
    Error error = Error::StorageUnavailable;
    QList<AttemptRecord> records;
};

struct MutationResult
{
    bool ok = false;
    Error error = Error::StorageUnavailable;
    QList<AttemptRecord> records;
};

class MayakAttemptStore final : public QObject
{
    Q_OBJECT
public:
    explicit MayakAttemptStore(SecureQSettings *settings, QObject *parent = nullptr);

    LoadResult load() const;
    MutationResult appendBeforeAcquire(const AttemptInput &attempt);
    MutationResult markMayHaveStarted(const AttemptIdentity &identity);
    MutationResult attachAllocation(const AttemptIdentity &identity, const QString &allocationId);
    MutationResult markRetired(const AttemptIdentity &identity);
    MutationResult removeAfterConfirmedCleanup(const AttemptIdentity &identity);

private:
    enum class Mutation { Append, MarkStarted, AttachAllocation, Retire, Remove };
    MutationResult mutate(Mutation operation, const AttemptIdentity &identity, const AttemptInput *input,
                          const QString &allocationId = {});
    bool onOwnerThread() const;

    SecureQSettings *m_settings = nullptr;
};

} // namespace mayak::attempts

#endif // MAYAKATTEMPTSTORE_H
