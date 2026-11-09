# Mayak signed updates

Windows x64 and Android arm64 clients check the static stable feeds over HTTPS:

- `https://mayaklight.ru/updates/stable/windows-x64.json`
- `https://mayaklight.ru/updates/stable/android-arm64.json`

The feed is a schema 1 envelope with `alg: "Ed25519"`, base64 UTF-8 JSON in
`payload`, and a base64 Ed25519 signature over the exact decoded payload bytes.
The client pins the update signing public key at build time. Its SPKI SHA-256
fingerprint is `98951331395b223d3039043b3f0dcaa15e177eedc459cd84fbab27d2eaaa3584`.
The key is separate from the gateway RSA key and Android APK signing identity.

The signed payload contains `product` (`mayak-vpn`), `channel` (`stable`),
`platform` (`windows-x64` or `android-arm64`), four-part numeric `version`,
positive integer `versionCode`, same-origin HTTPS package `url`, exact byte
`size`, lowercase SHA-256, and UTC `publishedAt` / `expiresAt`. Optional
`releaseNotes` is plain text. Packages are limited to 512 MiB. The client
rejects invalid signatures, stale versions, expired metadata, redirects,
unexpected URLs, partial files and hash mismatches. It streams into a private
per-user cache and rechecks the file immediately before opening the OS
installer.

## Creating a feed envelope

Keep the durable Ed25519 private key outside the repository and build artifacts.
Maintain a separate encrypted, access-controlled backup. The release helper
takes an explicit artifact and key path; it does not print or embed private key
material. Install an OpenSSL command line tool
and Python 3 on the release host, then run for example:

```powershell
python mayak/tools/sign_update_manifest.py `
  --artifact .\MayakVPN_5.1.0.5_windows_x64.exe `
  --platform windows-x64 `
  --version 5.1.0.5 `
  --version-code 2187 `
  --expires-at 2026-11-07T00:00:00Z `
  --url https://mayaklight.ru/updates/packages/MayakVPN_5.1.0.5_windows_x64.exe `
  --private-key C:\secure-release\mayak-update-ed25519-private.pem `
  --output .\windows-x64.json `
  --release-notes "Stability improvements"
```

Use the same form with `--platform android-arm64`, an `.apk` artifact, and the
version code compiled into that APK. Publish the artifact below
`/updates/packages/` and its envelope at the exact stable feed path. The client
ships fail-closed until those files are hosted. This repository change does not
publish feed files or verify server deployment.

Downloading requires the user to press the update action. Installing requires
a second explicit action and is refused while the VPN tunnel is connecting,
connected or disconnecting. Windows starts the verified Mayak installer for
the user to confirm. Android uses FileProvider and the system package installer;
the user may first need to allow installs from Mayak in Android settings. APK
updates still require the permanent Android signing identity to match. No
Windows Authenticode signature is claimed by the manifest signature.

The application checks on startup and every six hours by default, honors the
saved automatic-check opt-out, and always allows a manual About-page check.
