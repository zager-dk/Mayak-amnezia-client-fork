# Build notes for 5.1.0.16

Set `-DAMNEZIAVPN_VERSION:STRING=5.1.0.16` and use the existing prewarmed Qt/MSVC and Android toolchains.

For Android preserve base `APP_ANDROID_VERSION_CODE=2191` and pass `-DAPP_ANDROID_VERSION_CODE_OFFSET=5`, yielding code 2196; do not override the base code.

These notes describe build inputs only. No build, test, signature, installation, release, or device validation is claimed. Runtime, crypto, and physical-device observations remain NOT VERIFIED.
