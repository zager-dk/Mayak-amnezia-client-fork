# Windows installer lifecycle

Windows releases use the full Mayak installer EXE. The supported UI is the
standard Qt IFW wizard: welcome, ready, installation, and finished pages.
Windows runs lifecycle preflight when installation starts, after the user
chooses Install. Qt MaintenanceTool updater and package-manager modes are
refused. The app offers the full installer instead.

Preflight obtains administrator rights through Qt IFW, resolves the selected
target path, checks the existing `MayakVPN-service` image path and ownership
record, and records whether the service and same-path app were running. It
closes only a running `MayakVPN.exe` from that exact target when the full
installer allows it to close the app. Other processes and VPN services are
not selected by executable name alone.

For an existing service, preflight records its startup mode, including delayed
automatic start, then temporarily sets startup to disabled before requesting
stop. This prevents SCM recovery actions from restarting the old executable
during file replacement. Older clients may close their service control pipe
while stopping; only native stop results 109 and 1062 are tolerated, and the
subsequent SCM status query must positively report Stopped. A failed or empty
status query aborts installation. Recovery policy, service account,
dependencies, and image path are not rewritten.

On successful installation, the original startup mode is restored. The
service is started and checked only when its original mode was not disabled.
For a fresh install the helper creates and configures the Mayak service and its
recovery policy. An existing service registration is retained.

On failed or cancelled installation, Qt IFW rolls back installed files first.
The lifecycle rollback restores the original service startup mode and running
state from the per-run snapshot; it also requests relaunch of the app only in
the original user session. Recovery errors are reported explicitly. The
helper uses Windows PowerShell 5.1 with its OS module path isolated from a
possibly incompatible parent PowerShell environment.

Uninstall is separate. Preflight validates service ownership and hashes the
installed runtime files before file removal. The service is removed only after
successful file removal and only when the ownership record matches. On a
partial uninstall, service registration is retained and the user is told to
repair with the full installer. Installer transaction and ownership records
are stored under the administrator/SYSTEM-owned
`%ProgramData%\\MayakVPN-InstallerState`; they contain paths, tokens, startup
mode, and hashes, not account credentials.

Automated QIF lifecycle mocks and PowerShell boundary tests do not exercise
Windows SCM, ACLs, UAC, Qt IFW callback dispatch, or a real upgrade/rollback.
Those checks remain unverified until run against an installed package in a
disposable Windows environment.
