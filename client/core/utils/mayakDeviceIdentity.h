#pragma once

#include <QString>

namespace mayak::device {

// Хеш постоянного ID устройства для сервера: переустановка приложения не занимает новое место в лимите.
// Сам ID (ANDROID_ID, MachineGuid) не покидает устройство. Пустая строка — ID недоступен.
QString stableDeviceHash();

// SHA-256("mayak-device-v1:" + id) в нижнем регистре; пусто для пустого или известного недействительного ID.
QString hashDeviceId(const QString &rawId);

// "android 14", "windows 11" — тип системы для имени устройства на сервере.
QString osDescription();

} // namespace mayak::device
