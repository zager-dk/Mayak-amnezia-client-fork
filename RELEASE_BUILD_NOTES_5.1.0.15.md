# Windows and Android source build notes for 5.1.0.15

The root CMake file's default release version remains unchanged. Build this candidate with `-DAMNEZIAVPN_VERSION:STRING=5.1.0.15`; use the existing prewarmed Qt 6.10.3/MSVC toolchain and Conan dependencies.

For Android, preserve CMake base `APP_ANDROID_VERSION_CODE=2191` and pass `-DAPP_ANDROID_VERSION_CODE_OFFSET=4`; the resulting version code is 2195. Do not set `APP_ANDROID_VERSION_CODE` directly. Use the existing Qt Android, NDK, SDK, Gradle, Conan lock/provider and offline package procedures.

These notes specify build inputs only. The source candidate is BUILD_ONLY and does not claim a build, test, signature, installation, release, or device validation. Runtime and isolated crypto execution remain NOT VERIFIED; physical device checks remain NOT VERIFIED.
