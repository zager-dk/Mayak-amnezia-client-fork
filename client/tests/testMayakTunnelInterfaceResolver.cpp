#include <QtTest>

#include "core/utils/mayakTunnelInterfaceResolver.h"

#include <utility>

using mayak::tunnel::InterfaceCandidate;
using mayak::tunnel::InterfaceIdentity;
using mayak::tunnel::resolveInterface;

namespace {
const QHostAddress sourceIp(QStringLiteral("10.20.30.40"));

InterfaceCandidate candidate(QString name = QStringLiteral("iftype53_42"),
                              QString alias = QStringLiteral("MayakVPN"),
                              int index = 42,
                              QList<QHostAddress> addresses = {sourceIp}) {
    return {std::move(name), std::move(alias), index, std::move(addresses)};
}

bool resolve(const QVector<InterfaceCandidate> &interfaces, const QString &reportedName,
             InterfaceIdentity *identity = nullptr, const QHostAddress &address = sourceIp) {
    InterfaceIdentity ignored;
    return resolveInterface(interfaces, reportedName, address, identity ? identity : &ignored);
}
}

class MayakTunnelInterfaceResolverTests final : public QObject {
    Q_OBJECT
private slots:
    void resolvesInternalName() {
        InterfaceIdentity identity;
        QVERIFY(resolve({candidate()}, QStringLiteral("iftype53_42"), &identity));
        QCOMPARE(identity.index, 42);
        QCOMPARE(identity.name, QStringLiteral("iftype53_42"));
        QCOMPARE(identity.humanReadableName, QStringLiteral("MayakVPN"));
    }

    void resolvesExactFriendlyAlias() {
        InterfaceIdentity identity;
        QVERIFY(resolve({candidate()}, QStringLiteral("MayakVPN"), &identity));
        QCOMPARE(identity.index, 42);
    }

    void sameIdentityResolvesForRevalidation() {
        const QVector<InterfaceCandidate> before{candidate()};
        const QVector<InterfaceCandidate> after{candidate()};
        InterfaceIdentity bound;
        InterfaceIdentity current;
        QVERIFY(resolve(before, QStringLiteral("MayakVPN"), &bound));
        QVERIFY(resolve(after, QStringLiteral("MayakVPN"), &current));
        QVERIFY(current == bound);
    }

    void missingInterfaceRejected() {
        QVERIFY(!resolve({candidate()}, QStringLiteral("missing")));
    }

    void partialNamesAndCaseChangesRejected() {
        const QVector<InterfaceCandidate> interfaces{candidate()};
        QVERIFY(!resolve(interfaces, QStringLiteral("Mayak")));
        QVERIFY(!resolve(interfaces, QStringLiteral("prefix-MayakVPN")));
        QVERIFY(!resolve(interfaces, QStringLiteral("MayakVPN-suffix")));
        QVERIFY(!resolve(interfaces, QStringLiteral("mayakvpn")));
    }

    void duplicateFriendlyAliasRejected() {
        QVERIFY(!resolve({candidate(), candidate(QStringLiteral("iftype53_43"), QStringLiteral("MayakVPN"), 43)},
                         QStringLiteral("MayakVPN")));
        // Ambiguity is resolved before address or index filtering: the second
        // candidate cannot be ignored to make the first one look unique.
        QVERIFY(!resolve({candidate(), candidate(QStringLiteral("iftype53_43"), QStringLiteral("MayakVPN"), 0,
                                                  {QHostAddress(QStringLiteral("10.20.30.41"))})},
                         QStringLiteral("MayakVPN")));
    }

    void crossNamespaceCollisionRejected() {
        // The reported token is an internal name on one adapter and an alias on another.
        QVERIFY(!resolve({candidate(QStringLiteral("MayakVPN"), QStringLiteral("Adapter A"), 42),
                          candidate(QStringLiteral("iftype53_43"), QStringLiteral("MayakVPN"), 43)},
                         QStringLiteral("MayakVPN")));
        QVERIFY(!resolve({candidate(QStringLiteral("MayakVPN"), QStringLiteral("Adapter A"), 42),
                          candidate(QStringLiteral("iftype53_43"), QStringLiteral("MayakVPN"), 42)},
                         QStringLiteral("MayakVPN")));
    }

    void expectedAddressMismatchRejected() {
        QVERIFY(!resolve({candidate(QStringLiteral("iftype53_42"), QStringLiteral("MayakVPN"), 42,
                                     {QHostAddress(QStringLiteral("10.20.30.41"))})},
                         QStringLiteral("MayakVPN")));
    }

    void invalidIndexRejected() {
        QVERIFY(!resolve({candidate(QStringLiteral("iftype53_42"), QStringLiteral("MayakVPN"), 0)},
                         QStringLiteral("MayakVPN")));
        QVERIFY(!resolve({candidate(QStringLiteral("iftype53_42"), QStringLiteral("MayakVPN"), -1)},
                         QStringLiteral("MayakVPN")));
    }

    void nonIpv4OrMissingSourceAddressRejected() {
        QVERIFY(!resolve({candidate()}, QStringLiteral("MayakVPN"), nullptr,
                         QHostAddress(QStringLiteral("2001:db8::40"))));
        QVERIFY(!resolve({candidate()}, QStringLiteral("MayakVPN"), nullptr, QHostAddress()));
    }

    void disappearanceRejectedAtRevalidation() {
        InterfaceIdentity bound;
        QVERIFY(resolve({candidate()}, QStringLiteral("MayakVPN"), &bound));
        InterfaceIdentity current;
        QVERIFY(!resolve({}, QStringLiteral("MayakVPN"), &current));
        QVERIFY(!resolve({candidate(), candidate(QStringLiteral("iftype53_43"), QStringLiteral("MayakVPN"), 43)},
                         QStringLiteral("MayakVPN"), &current));
    }

    void indexOrAddressChangeRejectedAtRevalidation() {
        InterfaceIdentity bound;
        QVERIFY(resolve({candidate()}, QStringLiteral("MayakVPN"), &bound));
        InterfaceIdentity changedIndex;
        QVERIFY(resolve({candidate(QStringLiteral("iftype53_42"), QStringLiteral("MayakVPN"), 43)},
                        QStringLiteral("MayakVPN"), &changedIndex));
        QVERIFY(changedIndex != bound);

        InterfaceIdentity changedAddress;
        QVERIFY(!resolve({candidate(QStringLiteral("iftype53_42"), QStringLiteral("MayakVPN"), 42,
                                     {QHostAddress(QStringLiteral("10.20.30.41"))})},
                         QStringLiteral("MayakVPN"), &changedAddress));
    }

    void identityNameOrAliasDriftRejectedAtRevalidation() {
        InterfaceIdentity bound;
        QVERIFY(resolve({candidate()}, QStringLiteral("MayakVPN"), &bound));
        InterfaceIdentity changedName;
        QVERIFY(resolve({candidate(QStringLiteral("iftype53_99"), QStringLiteral("MayakVPN"), 42)},
                        QStringLiteral("MayakVPN"), &changedName));
        QVERIFY(changedName != bound);
        InterfaceIdentity changedAlias;
        QVERIFY(resolve({candidate(QStringLiteral("iftype53_42"), QStringLiteral("Renamed"), 42)},
                        QStringLiteral("iftype53_42"), &changedAlias));
        QVERIFY(changedAlias != bound);
        QVERIFY(!resolve({candidate(QStringLiteral("iftype53_42"), QStringLiteral("Renamed"), 42)},
                         QStringLiteral("MayakVPN"), &changedAlias));
    }
};

QTEST_GUILESS_MAIN(MayakTunnelInterfaceResolverTests)
#include "testMayakTunnelInterfaceResolver.moc"
