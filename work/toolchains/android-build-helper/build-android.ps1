param(
    [switch]$Build,
    [switch]$SourceStableConfirmed
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$jdk = Join-Path $repoRoot 'work\toolchains\android-jdk\jdk-17.0.20.1+1'
$sdk = Join-Path $repoRoot 'work\toolchains\android-sdk'
$ndk = Join-Path $sdk 'ndk\27.0.11718014'
$qtAndroid = Join-Path $repoRoot 'work\toolchains\android-qt\6.10.3\android_arm64_v8a'
$qtHost = Join-Path $repoRoot 'work\toolchains\Qt\6.10.3\msvc2022_64'
$cmakeBin = Join-Path $repoRoot 'work\toolchains\android-build-helper\cmake\cmake-3.31.8-windows-x86_64\bin'
$ninjaBin = Join-Path $repoRoot 'work\toolchains\android-build-helper\ninja'
$conanBin = Join-Path $repoRoot 'work\toolchains\build-python\Scripts'
$conanHome = Join-Path $repoRoot 'work\toolchains\android-conan-home'
$gradleHome = Join-Path $repoRoot 'work\toolchains\android-gradle-home'
$goHome = Join-Path $repoRoot 'work\toolchains\android-go-home'
$goPath = $goHome
$gatewayPublicKey = Join-Path $repoRoot 'work\toolchains\mayak-gateway-public.pem'
$conanLock = Join-Path $repoRoot 'work\toolchains\android-deps-source.lock'
$providerInclude = Join-Path $PSScriptRoot 'conan-provider-lock.cmake'
$androidHostProfile = Join-Path $PSScriptRoot 'android-host.profile'
$androidBuildProfile = Join-Path $PSScriptRoot 'android-build.profile'
$gatewaySpkiSha256 = '06537531B7171787CA75D9F94B3EDC49E55FEB0DBB8FF7DAE5559C23C00C1DA2'

$cmakeNdkPath = $ndk.Replace('\', '/')
$hostProfileText = @"
[settings]
os=Android
os.api_level=28
arch=armv8
compiler=clang
compiler.version=18
compiler.libcxx=c++_shared
build_type=Release

[options]
openssl/*:shared=True

[conf]
tools.android:ndk_path=$cmakeNdkPath
tools.android:cmake_legacy_toolchain=false
tools.cmake.cmaketoolchain:generator=Ninja
tools.build:sharedlinkflags=['-Wl,-z,max-page-size=16384']
tools.build:exelinkflags=['-Wl,-z,max-page-size=16384']
"@
$buildProfileText = @"
[settings]
os=Windows
arch=x86_64
build_type=Release
"@
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText($androidHostProfile, $hostProfileText.Trim() + "`n", $utf8NoBom)
[IO.File]::WriteAllText($androidBuildProfile, $buildProfileText.Trim() + "`n", $utf8NoBom)

$required = @(
    (Join-Path $jdk 'bin\java.exe'),
    (Join-Path $jdk 'bin\javac.exe'),
    (Join-Path $sdk 'cmdline-tools\latest\bin\sdkmanager.bat'),
    (Join-Path $sdk 'platform-tools\adb.exe'),
    (Join-Path $sdk 'platforms\android-28\android.jar'),
    (Join-Path $sdk 'build-tools\36.0.0\aapt.exe'),
    (Join-Path $ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe'),
    (Join-Path $qtAndroid 'lib\cmake\Qt6\qt.toolchain.cmake'),
    (Join-Path $qtHost 'bin\androiddeployqt.exe'),
    (Join-Path $cmakeBin 'cmake.exe'),
    (Join-Path $ninjaBin 'ninja.exe'),
    (Join-Path $conanBin 'conan.exe'),
    $gatewayPublicKey,
    $conanLock,
    $providerInclude,
    $androidHostProfile,
    $androidBuildProfile
)
foreach ($path in $required) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required Android build tool is missing: $path" }
}

$env:JAVA_HOME = $jdk
$env:ANDROID_SDK_ROOT = $sdk
$env:ANDROID_HOME = $sdk
$env:ANDROID_USER_HOME = Join-Path $sdk 'android-user-home'
$env:ANDROID_NDK_ROOT = $ndk
$env:CONAN_HOME = $conanHome
$env:GRADLE_USER_HOME = $gradleHome
$env:GOPATH = $goPath
$env:GOBIN = Join-Path $goPath 'bin'
$env:GOMODCACHE = Join-Path $goPath 'pkg\mod'
$env:GOCACHE = Join-Path $goHome 'go-build-cache'
$env:GOENV = 'off'
$env:GIT_CONFIG_COUNT = '1'
$env:GIT_CONFIG_KEY_0 = 'core.autocrlf'
$env:GIT_CONFIG_VALUE_0 = 'false'
$env:TMPDIR = Join-Path $goHome 'tmp'
$env:MAYAK_GATEWAY_ENDPOINT = 'https://mayaklight.ru/gw/'
$env:PROD_AGW_PUBLIC_KEY = Get-Content -LiteralPath $gatewayPublicKey -Raw
$pemMatch = [regex]::Match($env:PROD_AGW_PUBLIC_KEY, '(?s)^\s*-----BEGIN PUBLIC KEY-----\s*(?<body>[A-Za-z0-9+/=\r\n]+)\s*-----END PUBLIC KEY-----\s*$')
if (-not $pemMatch.Success) { throw 'Canonical gateway key must be a SubjectPublicKeyInfo PUBLIC KEY PEM.' }
$der = [Convert]::FromBase64String(($pemMatch.Groups['body'].Value -replace '\s', ''))
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $actualSpkiSha256 = [BitConverter]::ToString($sha256.ComputeHash($der)).Replace('-', '')
}
finally {
    $sha256.Dispose()
}
if ($actualSpkiSha256 -ne $gatewaySpkiSha256) {
    throw "Canonical gateway PEM fingerprint mismatch (SPKI SHA-256=$actualSpkiSha256)."
}
$env:TEMP = Join-Path $goHome 'tmp'
$env:TMP = $env:TEMP
$env:PATH = "$cmakeBin;$ninjaBin;$jdk\bin;$sdk\cmdline-tools\latest\bin;$conanBin;$env:GOBIN;$env:PATH"
New-Item -ItemType Directory -Force $env:GOBIN,$env:GOMODCACHE,$env:GOCACHE,$env:TMP,$env:GRADLE_USER_HOME,$env:ANDROID_USER_HOME | Out-Null

Write-Output 'Portable Android toolchain paths are present.'
& (Join-Path $jdk 'bin\java.exe') -version
if ($LASTEXITCODE -ne 0) { throw 'java -version failed' }
& (Join-Path $jdk 'bin\javac.exe') -version
if ($LASTEXITCODE -ne 0) { throw 'javac -version failed' }
& (Join-Path $ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe') --version
if ($LASTEXITCODE -ne 0) { throw 'NDK clang --version failed' }
& (Join-Path $cmakeBin 'cmake.exe') --version
if ($LASTEXITCODE -ne 0) { throw 'cmake --version failed' }
& (Join-Path $ninjaBin 'ninja.exe') --version
if ($LASTEXITCODE -ne 0) { throw 'ninja --version failed' }
& (Join-Path $qtHost 'bin\qt-cmake.bat') --version
if ($LASTEXITCODE -ne 0) { throw 'Qt host qt-cmake --version failed' }

if (-not $Build) {
    Write-Output "Canonical gateway PEM verified (pinned RSA-2048 SPKI SHA-256 $gatewaySpkiSha256). No product source was configured or compiled."
    return
}
if (-not $SourceStableConfirmed) {
    throw 'Build is deferred until the director confirms UPDATE-01 source-stable handoff. Re-run with -Build -SourceStableConfirmed after that handoff.'
}

$source = Join-Path $repoRoot 'work\mayak-client'
$buildDir = Join-Path $repoRoot 'work\android-a4'
$qtToolchain = Join-Path $qtAndroid 'lib\cmake\Qt6\qt.toolchain.cmake'
$cmakeQtHost = $qtHost.Replace('\', '/')
$cmakeLock = $conanLock.Replace('\', '/')
$cmakeProviderInclude = $providerInclude.Replace('\', '/')
$cmakeHostProfile = $androidHostProfile.Replace('\', '/')
$cmakeBuildProfile = $androidBuildProfile.Replace('\', '/')
$configureArgs = @(
    '-S', $source,
    '-B', $buildDir,
    '-G', 'Ninja',
    '-DCMAKE_BUILD_TYPE=Release',
    "-DCMAKE_PREFIX_PATH=$qtToolchain",
    "-DCMAKE_TOOLCHAIN_FILE=$qtToolchain",
    "-DQT_HOST_PATH=$cmakeQtHost",
    "-DANDROID_SDK_ROOT=$sdk",
    "-DANDROID_NDK_ROOT=$ndk",
    "-DCONAN_HOST_PROFILE=$cmakeHostProfile",
    "-DCONAN_BUILD_PROFILE=$cmakeBuildProfile",
    "-DCMAKE_PROJECT_INCLUDE=$cmakeProviderInclude",
    "-DMAYAK_ANDROID_HOST_PROFILE=$cmakeHostProfile",
    "-DMAYAK_ANDROID_BUILD_PROFILE=$cmakeBuildProfile",
    "-DMAYAK_ANDROID_CONAN_LOCK=$cmakeLock",
    "-DMAYAK_ANDROID_NDK_ROOT=$cmakeNdkPath",
    '-DMAYAK_GATEWAY_ENDPOINT=https://mayaklight.ru/gw/',
    '-DANDROID_PLATFORM=android-28',
    '-DANDROID_ABI=arm64-v8a',
    '-DAPP_ANDROID_MIN_SDK=28',
    '-DQT_ANDROID_SIGN_APK=FALSE',
    '-DQT_ANDROID_SIGN_AAB=FALSE'
)
& (Join-Path $cmakeBin 'cmake.exe') @configureArgs
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed with exit code $LASTEXITCODE" }
& (Join-Path $cmakeBin 'cmake.exe') --build $buildDir --config Release --parallel 4
if ($LASTEXITCODE -ne 0) { throw "CMake build failed with exit code $LASTEXITCODE" }
