# Windows source build notes for 5.1.0.12

The source tree records the 5.1.0.9 baseline default. For a Windows source build of this candidate, configure with `-DAMNEZIAVPN_VERSION:STRING=5.1.0.12`; the CMake project passes this value to client, service, and IFW package version metadata. Use the accepted `mayak/BUILD.md` Windows Qt 6.10.3/MSVC 2022/Ninja recipe, with its required external Conan/Qt/IFW dependencies.

The Windows update-feed `versionCode` is 2191 (positive and accepted by the Windows client); Android remains at its existing 5.1.0.9 / 2191 release. The Android monotonic-code rule does not apply to Windows, whose updater compares the four-part version. This metadata states the intended version override only: no build or signature is claimed by this archive preparation.
