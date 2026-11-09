#pragma once

#include <QObject>

class SecureAppSettingsRepository;

// Mayak «Россия напрямую» for QML (home screen switch, one-time notice).
class MayakRoutingUiController : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool russiaDirect READ russiaDirect WRITE setRussiaDirect NOTIFY russiaDirectChanged)
    Q_PROPERTY(bool noticePending READ noticePending NOTIFY noticePendingChanged)

public:
    explicit MayakRoutingUiController(SecureAppSettingsRepository *settings, QObject *parent = nullptr);

    bool russiaDirect() const;
    void setRussiaDirect(bool enabled);
    bool noticePending() const;

public slots:
    void markNoticeShown();

signals:
    void russiaDirectChanged();
    void noticePendingChanged();

private:
    SecureAppSettingsRepository *m_settings;
};
