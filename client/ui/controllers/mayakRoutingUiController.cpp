#include "mayakRoutingUiController.h"

#include "core/repositories/secureAppSettingsRepository.h"

MayakRoutingUiController::MayakRoutingUiController(SecureAppSettingsRepository *settings, QObject *parent)
    : QObject(parent), m_settings(settings)
{
    if (m_settings)
        connect(m_settings, &SecureAppSettingsRepository::mayakRussiaDirectEnabledChanged, this,
                &MayakRoutingUiController::russiaDirectChanged);
}

bool MayakRoutingUiController::russiaDirect() const
{
    return m_settings && m_settings->isMayakRussiaDirectEnabled();
}

void MayakRoutingUiController::setRussiaDirect(bool enabled)
{
    if (!m_settings || m_settings->isMayakRussiaDirectEnabled() == enabled) return;
    m_settings->setMayakRussiaDirectEnabled(enabled); // stored: the choice survives updates
    markNoticeShown(); // a user who chose needs no "now on by default" notice
}

bool MayakRoutingUiController::noticePending() const
{
    return m_settings && m_settings->isMayakRussiaDirectEnabled() && !m_settings->isMayakRussiaDirectNoticeShown();
}

void MayakRoutingUiController::markNoticeShown()
{
    if (!m_settings || m_settings->isMayakRussiaDirectNoticeShown()) return;
    m_settings->setMayakRussiaDirectNoticeShown(true);
    emit noticePendingChanged();
}
