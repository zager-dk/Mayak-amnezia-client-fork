# Android release packaging gate

After building the native target and running its `prepare_apk_dir` target, run
androiddeployqt in auxiliary mode to resolve native dependencies. Then restore
the product manifest with `tools/stage_android_manifest.py --source client/android
--destination <android-build> --deployment <deployment-settings.json>`. This
renders source placeholders using the exact deployment version and SDK values.
Aux mode copies the Qt default template but skips copyAndroidSources. Preserve the
custom Gradle/Kotlin sources and resource overlay; do not replace generated Qt
`res/values/libs.xml` with its source template. Build the OSS F-Droid APK.

The compiled APK must pass `tools/verify_android_apk.py --apk <apk> --apkanalyzer
<sdk>/cmdline-tools/latest/bin/apkanalyzer.bat --version <version> --version-code
<code> --report <report.json>` before release publication. Set JAVA_HOME to JDK17.
This checks the actual binary manifest, package identity, product Activity and
Application, AWG service, permissions, matching DEX classes, version and ELF
alignment. A generic Qt template APK is rejected even if compilation, login and
the main screen work. Signature/pin checks and real-device tests remain separate.

5.1.0.7 is a known failing fixture for this gate: its compiled manifest launches
QtActivity and omits the VPN service. Do not distribute it for Android. Windows
5.1.0.7 is independent and is not changed by the Android5.1.0.8 repair.
