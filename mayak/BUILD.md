# Mayak build notes

## Windows smoke build

The Windows build uses Qt 6.10.3/MSVC 2022 and Ninja. It has a separate executable,
service, IPC endpoint, WireGuard tunnel service and named pipe, interface/config
paths, settings organization, installer directory and stable installer upgrade
GUID. Its install/uninstall scripts address Mayak process and service names only.
Android continues to use package `ru.mayaklight.vpn` and its existing Android
settings identity.

On a fresh Windows configure, the default CMake and CPack install prefix is
`Program Files (x86)/MayakVPN`, and the CPack package name is `MayakVPN`. An
explicit `CMAKE_INSTALL_PREFIX` supplied by the user or packager is preserved.
Windows builds include the signed Mayak updater. The static update feeds must be
published separately; until they are available, update checks fail closed and
cannot provide a package.

The gateway public key is required at configure time. A local smoke build may use
a throwaway fixture key only; it does not produce a user-installable build. Create
one outside the repository and pass only the public PEM through the environment:

```powershell
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $env:TEMP\mayak-smoke-private.pem
openssl pkey -in $env:TEMP\mayak-smoke-private.pem -pubout -out $env:TEMP\mayak-smoke-public.pem
$env:PROD_AGW_PUBLIC_KEY = Get-Content -Raw $env:TEMP\mayak-smoke-public.pem
```

Configure and build from a UTF-8 Visual Studio developer shell. Apply UTF-8 before
and after `VsDevCmd` so Ninja recognizes MSVC `showIncludes` dependency output:

```cmd
chcp 65001
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
chcp 65001
set CONAN_HOME=%CD%\..\toolchains\conan
set PATH=%CD%\..\toolchains\build-python\Scripts;C:\Qt\Tools\Ninja;C:\Qt\Tools\CMake_64\bin;%PATH%
cmake -S . -B out\windows-mayak -G Ninja -DCMAKE_MAKE_PROGRAM=C:/Qt/Tools/Ninja/ninja.exe -DCMAKE_BUILD_TYPE=Release -DCMAKE_TRY_COMPILE_CONFIGURATION=Release -DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF -DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF -DCMAKE_PREFIX_PATH=..\toolchains\Qt\6.10.3\msvc2022_64 -DAMNEZIA_BUILD_TESTS=ON
cmake --build out\windows-mayak --config Release --parallel 6
cmake --build out\windows-mayak --config Release --target test_gateway_service_import --parallel 6
ctest --test-dir out\windows-mayak\client\tests -R GatewayServiceImportTest --output-on-failure
ninja -C out\windows-mayak -t deps > out\windows-mayak\ninja-deps.txt
cmake --install out\windows-mayak --prefix "%CD%\out\mayak-stage" --component AmneziaVPN
```

Check that `ninja-deps.txt` is non-empty and inspect it for the client and service
targets. Run the file-only staging command in the same Visual Studio developer
shell so the runtime dependency scanner can find `dumpbin`; use an absolute staging
prefix. Keep compiler output in a file when diagnosing build failures; MSVC include
traces are large.

## Release gates

- Release configuration must fetch the real public key from
  `https://mayaklight.ru/gw/public-key`; failure or malformed PEM stops the build.
- Android release signing requires `MAYAK_ANDROID_KEYSTORE_BASE64` and
  `MAYAK_ANDROID_KEYSTORE_PASS`. No temporary signing key is generated for release.
- CI smoke artifacts use a throwaway public key and are explicitly unsigned/not for
  installation. The manual workflow release mode is the only path that exports the
  signed Android artifact. No workflow publishes or installs an artifact.
- Installer execution, upgrade/uninstall behavior, coexistence with a separately
  installed AmneziaVPN, and Android device installation have not been observed in
  a VM/device and remain **NOT VERIFIED**.
- Windows QtKeychain backend in the pinned dependency ignores its service argument
  and addresses credentials by `job.key`. Mayak now uses the stable targets
  `MayakVPN-Client/settingsKeyTag` and `MayakVPN-Client/settingsIvTag`; it does not
  probe or migrate Amnezia's legacy targets. Android, macOS and Linux retain the
  original `settingsKeyTag` and `settingsIvTag` names. This storage change has
  passed the isolated Windows Gateway suite, but installer/upgrade coexistence
  and Android device behavior remain **NOT VERIFIED**; no product installation
  or VPN run has been performed.
