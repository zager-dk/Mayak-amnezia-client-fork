#pragma once

#include <QObject>

class SecureAppSettingsRepository;

// Mayak «Россия напрямую» for QML (home screen switch, one-time notice).
class MayakRoutingUiController : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool russiaDirect READ russiaDirect WRITE setRussiaDirect NOTIFY russiaDirectChanged)
    Q_PROPERTY(bool noticePending READ noticePending NOTIFY noticePendingChanged)
    // «Способ подключения»: "auto" (AWG, then Xray paths), "awg", "xray". Used from the next connect.
    Q_PROPERTY(QString connectionMethod READ connectionMethod WRITE setConnectionMethod NOTIFY connectionMethodChanged)

public:
    explicit MayakRoutingUiController(SecureAppSettingsRepository *settings, QObject *parent = nullptr);

    bool russiaDirect() const;
    void setRussiaDirect(bool enabled);
    bool noticePending() const;
    QString connectionMethod() const;
    void setConnectionMethod(const QString &method);

public slots:
    void markNoticeShown();

signals:
    void russiaDirectChanged();
    void noticePendingChanged();
    void connectionMethodChanged();

private:
    SecureAppSettingsRepository *m_settings;
};
