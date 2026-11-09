# Isolated Windows UAPI/transaction regression checks

Build this directory as a standalone CMake project using MSVC, Qt 6 Core/Network/Test/Widgets and Ninja, or use the registered targets in the normal Windows test project. The director's dedicated runner is `work/windows-connection-5108/build-tests.cmd` (outside this repository).

Set `PATH` to include the matching Qt `bin`, and `MAYAK_TEST_TUNNEL_DLL` to the exact staged or packaged `tunnel.dll`; run `ctest --test-dir <dedicated-build> --output-on-failure`. The ABI case explicitly skips when that artifact path is unavailable. QtTest result files are written inside the build directory; CTest enforces a 30-second harness timeout.

The transaction target compiles actual Daemon, WindowsTunnelService, WireguardUtilsWindows and WindowsRouteMonitor. Only OS calls and collaborators are deterministic test substitutes; no host SCM, named-pipe, routing or WFP state is changed. The WFP cleanup target compiles actual WindowsFirewall methods and replaces WFP transaction/deletion calls. Private test access seeds/inspects recorded route/filter teardown inputs and does not substitute cleanup implementations. An object-only target also compiles changed native paths against real Windows SDK declarations without OS-call replacement.

These checks do not execute the DLL, load the real driver, establish a VPN, validate native DLL IO timing/cancellation, or prove interface-bound TLS/egress. Those remain director-owned installed-runtime checks. TLS, ownership IPC and proof deadlines are outside this fixture's scope.

N1 regression: CMake extracts the current `WindowsDaemon::run` and `WindowsSplitTunnel::stop` method bodies verbatim, changing only the class qualifier to attach deterministic start/driver collaborators. Both production files are configure dependencies. The fixture runs actual Daemon ownership/cleanup logic through those generated bodies with a fake failing/succeeding DeviceIoControl; no handwritten cleanup mirror or real driver call is used. The real-SDK object target additionally compiles the complete WindowsDaemon and WindowsSplitTunnel source files.
