# Windows and Android source build notes for 5.1.0.13

The root CMake file's default release version remains unchanged. Build this candidate with `-DAMNEZIAVPN_VERSION:STRING=5.1.0.13`; the accepted Windows build procedure uses the prewarmed Qt 6.10.3/MSVC toolchain and existing Conan dependencies.

For Android, preserve the CMake base `APP_ANDROID_VERSION_CODE=2191` and pass `-DAPP_ANDROID_VERSION_CODE_OFFSET=2`; the resulting version code is 2193. Do not set `APP_ANDROID_VERSION_CODE` directly. Use the existing Qt Android, NDK, SDK, Gradle, Conan lock/provider and offline package procedures.

These notes specify build inputs only. This source preparation does not claim a build, test, signature, install, or device validation.
