# Маяк VPN — приложение

Форк [AmneziaVPN](https://github.com/amnezia-vpn/amnezia-client). Изменения Маяка собраны в ветке `mayak`
и помечены комментариями «Маяк:»; ветка `dev` повторяет оригинал, чтобы подтягивать обновления Amnezia.

## Что изменено

| Где | Что |
|---|---|
| `mayak/mayak.cmake` | адрес шлюза (`https://mayaklight.ru/gw/`) и открытый ключ → `mayak_build.h` |
| `mayak/gateway_public.pem` | открытый ключ шлюза; если файла нет, сборка берёт его с `https://mayaklight.ru/gw/public-key` |
| `mayak/branding.cmake` | имя приложения на Android |
| `client/core/controllers/gatewayController.cpp` | ключ шлюза из `mayak_build.h` |
| `client/core/repositories/secureAppSettingsRepository.cpp` | адрес шлюза по умолчанию |
| `client/android/…` | пакет `ru.mayaklight.vpn` — ставится рядом с AmneziaVPN |
| `mayak/lighthouse.svg` | исходник значка; из него сделаны значки Android и логотип в приложении (`client/images/amneziaLogo.svg`) |
| `mayak/rebrand_strings.py` | замена названия в строках интерфейса: код и `<source>` во всех `.ts` меняются одинаково, русский перевод — свой |
| `client/android/res/…` | значки, фон значка, силуэт для уведомлений, названия в системных строках |
| `.github/workflows/mayak.yml` | сборка APK; исходная сборка Amnezia (`deploy.yml`) запускается только вручную |

## Как работает подключение

1. Человек входит в кабинет `https://mayaklight.ru/my/` и берёт «ключ подписки» (`vpn://…`).
2. В приложении: «Добавить» → вставить ключ. Приложение создаёт свой ключ устройства и через шлюз
   (`/gw/v1/config`) получает настройки — так же, как Amnezia Premium.
3. Лимит устройств, срок доступа и отключение — из админки Маяка.

## Сборка

GitHub → Actions → «Маяк: сборка приложения» → Run workflow. Готовый APK — в артефакте `mayak-android`.

Постоянная подпись APK (чтобы обновления ставились поверх): секреты репозитория
`MAYAK_ANDROID_KEYSTORE_BASE64` (keystore в base64, псевдоним ключа `mayak`) и `MAYAK_ANDROID_KEYSTORE_PASS`.
