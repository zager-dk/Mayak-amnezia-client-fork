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
| `client/core/controllers/updateController.*` | проверка собственного подписанного HTTPS feed для Windows x64 и Android arm64 |
| `mayak/update_signing_public.pem` | открытый Ed25519 ключ для проверки манифестов обновлений; приватный ключ хранится вне репозитория |

## Как работает подключение

1. Пользователь выбирает «У меня есть приглашение Маяка» и вводит одноразовый код.
2. Клиент получает сеанс через `/api/auth/invite`, сохраняет его в защищённых настройках и запрашивает
   `/api/app-key`. Ключ передаётся существующему импортёру Amnezia; вручную копировать его не нужно.
3. Если загрузка подписки прервалась после входа, действие «Продолжить настройку доступа» повторяет
   только получение ключа и импорт. Если ответ самого одноразового входа потерян, потребуется новый код.
4. Импортированная подписка становится сервером по умолчанию, подключение выполняется штатной кнопкой.
   Лимит устройств, срок доступа и отключение управляются из админки Маяка.

Для безопасного локального просмотра экрана и сценария повтора см. [mock invite preview](preview/README.md).

Формат и локальная подпись feed обновлений описаны в [UPDATES.md](../docs/UPDATES.md). Пока production feed не опубликован,
клиент закрывает обновление при сетевой ошибке; вход и штатное подключение VPN от этого не зависят.

## Сборка

GitHub → Actions → «Маяк: сборка приложения» → Run workflow. Готовый APK — в артефакте `mayak-android`.

Постоянная подпись APK (чтобы обновления ставились поверх): секреты репозитория
`MAYAK_ANDROID_KEYSTORE_BASE64` (keystore в base64, псевдоним ключа `mayak`) и `MAYAK_ANDROID_KEYSTORE_PASS`.
