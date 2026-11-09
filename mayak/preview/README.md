# Mock invite and update screens

Harness загружает настоящий `client/ui/qml/Pages2/PageMayakInvite.qml` с mock контроллером. Он не обращается к сети, не читает реальные секреты и не включает VPN.

Соберите и запустите из корня репозитория:

```powershell
cmake -S mayak/preview -B out/mayak-preview -G Ninja `
  -DCMAKE_MAKE_PROGRAM=C:/Qt/Tools/Ninja/ninja.exe `
  -DCMAKE_PREFIX_PATH=C:/Qt/6.11.0/mingw_64 `
  -DCMAKE_C_COMPILER=C:/Qt/Tools/mingw1310_64/bin/gcc.exe `
  -DCMAKE_CXX_COMPILER=C:/Qt/Tools/mingw1310_64/bin/g++.exe
cmake --build out/mayak-preview
./out/mayak-preview/MayakInvitePreview.exe
```

Непустой код симулирует сбой после полученного сеанса; затем «Повторить настройку» симулирует успешный retry и переход к mock главному экрану. Это полностью локальный mock.

Для просмотра настоящего `PageUpdate.qml` с mock controller запустите из корня репозитория:

```powershell
./out/mayak-preview/MayakInvitePreview.exe --updates
./out/mayak-preview/MayakInvitePreview.exe --updates --phone
./out/mayak-preview/MayakInvitePreview.exe --updates --download-error
./out/mayak-preview/MayakInvitePreview.exe --updates --phone --download-error
```

Mock симулирует доступную версию, прогресс, отмену и завершённую проверку файла. Он не делает сетевых запросов,
не запускает installer, не читает VPN-конфигурацию или пользовательские секреты. `--phone` задаёт окно 360×720;
обычный режим — 1280×850. `--download-error` показывает начальное состояние ошибки с русским текстом и кнопкой повтора.
Все режимы открывают тот же экран и компоненты, что и приложение, и используют встроенный русский перевод.
