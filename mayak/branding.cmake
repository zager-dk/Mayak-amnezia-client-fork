# Маяк: имена приложения. Подключается из client/cmake/clientBrandingDefaults.cmake раньше значений Amnezia.
# Пока меняем только то, что нужно, чтобы приложение ставилось рядом с AmneziaVPN на Android.
# Имена для Windows/macOS (служба, папки, установщик) меняются следующим шагом.
set(CLIENT_ANDROID_APP_NAME "Маяк VPN" CACHE STRING "Android launcher label")
set(CLIENT_ANDROID_PACKAGE "ru.mayaklight.vpn" CACHE STRING "Android package name")
