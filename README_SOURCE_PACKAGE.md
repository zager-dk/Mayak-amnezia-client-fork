# MayakVPN 5.1.0.8 source package

This archive contains source files only, including the explicitly reviewed product-source additions, license notices, and the accepted public Android build references. It contains no EXE/APK outputs, build caches, toolchain binaries, credentials, or private keys.

## Build notes

Start with `mayak/BUILD.md`, `README.md`, and `README_RU.md`. The Android helper/profile references are not a self-contained toolchain. The host profile replaces the workstation NDK path with `<ANDROID_NDK_ROOT>`. The standard Gradle wrapper JAR is omitted because it is a tool binary.

This is not a fully reproducible build environment. SDK/NDK, Qt/MSVC, Conan packages, IFW, environment variables, signing configuration, and host tools remain external. Runtime, installer, device, updater, and VPN behavior require separate verification.

The exact public gateway build input is archived as `mayak/gateway_public.pem` with SHA-256 `93ecc3f27a887103aa1bc8072b5db9b32fae8920de5a89e03a7f63bf9717082d`. It matches the explicit workstation/toolchain source file and is separate from `mayak/update_signing_public.pem`, which pins the update-feed signer. Neither is private-key material.

`SOURCE_MANIFEST.sha256` hashes each payload other than itself. `SOURCE_PROVENANCE.txt` records source revision, public gateway input identity, and submodule state. The archive is built only from the supplied FROZEN source manifest.
