# Also usable as an isolated build; never links the GUI/test_common or invokes SCM.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    cmake_minimum_required(VERSION 3.24)
    project(MayakWindowsUapiChecks LANGUAGES CXX)
    enable_testing()
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_AUTOMOC ON)
    find_package(Qt6 REQUIRED COMPONENTS Core Network Test Widgets Core5Compat)
endif()
if(NOT WIN32)
    return()
endif()
get_filename_component(_root "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
set(_native "${_root}/client/platforms/windows/daemon")
# Compile the production Down/stop method bodies verbatim. Only the class
# qualification changes to attach deterministic start/driver collaborators;
# configure dependencies prevent a stale handwritten mirror from passing.
function(mayak_cleanup_method source start_marker end_marker old_name new_name output)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${source}")
    file(READ "${source}" _text)
    string(FIND "${_text}" "${start_marker}" _start)
    string(FIND "${_text}" "${end_marker}" _end)
    if(_start LESS 0 OR _end LESS _start)
        message(FATAL_ERROR "Production cleanup method boundary changed: ${source}")
    endif()
    math(EXPR _length "${_end} - ${_start}")
    string(SUBSTRING "${_text}" ${_start} ${_length} _method)
    string(REPLACE "${old_name}" "${new_name}" _method "${_method}")
    set(${output} "${_method}" PARENT_SCOPE)
endfunction()
mayak_cleanup_method("${_native}/windowsdaemon.cpp"
    "bool WindowsDaemon::run(" "void WindowsDaemon::monitorBackendFailure("
    "WindowsDaemon::run" "ProductionRunDaemon::run" _production_run)
mayak_cleanup_method("${_native}/windowssplittunnel.cpp"
    "bool WindowsSplitTunnel::stop()" "bool WindowsSplitTunnel::resetDriver("
    "WindowsSplitTunnel::stop" "SplitProbe::stop" _production_stop)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/productionCleanupBodies.inc" "${_production_stop}\n${_production_run}")

add_executable(test_windows_uapi_transaction
    testWindowsUapiTransaction.cpp nativeSupport.cpp
    ${_root}/client/daemon/daemon.cpp ${_root}/client/daemon/daemon.h
    ${_root}/client/daemon/wireguardutils.h ${_root}/client/daemon/dnsutils.h
    ${_root}/client/daemon/interfaceconfig.cpp ${_root}/client/daemon/interfaceconfig.h
    ${_root}/client/mozilla/shared/ipaddress.cpp
    ${_native}/windowstunnelservice.cpp ${_native}/windowstunnelservice.h
    ${_native}/wireguardutilswindows.cpp ${_native}/wireguardutilswindows.h
    ${_native}/windowsroutemonitor.cpp ${_native}/windowsroutemonitor.h
    ${_native}/windowstunnellogger.h)
target_include_directories(test_windows_uapi_transaction PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/stubs ${_root}/client ${_root}/client/mozilla/shared
    ${_native} ${CMAKE_CURRENT_BINARY_DIR})
target_compile_definitions(test_windows_uapi_transaction PRIVATE UNICODE _UNICODE _WINSOCKAPI_ WINVER=0x0A00 _WIN32_WINNT=0x0A00)
target_compile_options(test_windows_uapi_transaction PRIVATE "/FI${CMAKE_CURRENT_SOURCE_DIR}/nativeApiFakes.h")
target_link_libraries(test_windows_uapi_transaction PRIVATE Qt6::Core Qt6::Network Qt6::Test iphlpapi ws2_32)
add_test(NAME WindowsUapiTransactionTest COMMAND test_windows_uapi_transaction -o windows-uapi-results.txt,txt)
set_tests_properties(WindowsUapiTransactionTest PROPERTIES TIMEOUT 30)

add_executable(test_windows_firewall_cleanup
    testWindowsFirewallCleanup.cpp firewallSupport.cpp
    ${_native}/windowsfirewall.cpp ${_native}/windowsfirewall.h
    ${_root}/client/mozilla/shared/ipaddress.cpp)
target_include_directories(test_windows_firewall_cleanup PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/stubs ${_root}/client ${_root}/client/mozilla/shared ${_native})
target_compile_definitions(test_windows_firewall_cleanup PRIVATE
    UNICODE _UNICODE WINVER=0x0A00 _WIN32_WINNT=0x0A00 TEST_NATIVE_FIREWALL)
target_compile_options(test_windows_firewall_cleanup PRIVATE "/FI${CMAKE_CURRENT_SOURCE_DIR}/nativeApiFakes.h")
target_link_libraries(test_windows_firewall_cleanup PRIVATE
    Qt6::Core Qt6::Network Qt6::Test Qt6::Widgets Fwpuclnt ws2_32 iphlpapi)
add_test(NAME WindowsFirewallCleanupTest COMMAND test_windows_firewall_cleanup -o windows-firewall-results.txt,txt)
set_tests_properties(WindowsFirewallCleanupTest PROPERTIES TIMEOUT 30)

# Compile changed native paths against real Windows SDK declarations too: this
# object-only target is never linked/run and has no forced API replacements.
add_library(windows_uapi_sdk_compile OBJECT
    ${_root}/client/daemon/daemon.cpp
    ${_native}/windowstunnelservice.cpp ${_native}/wireguardutilswindows.cpp
    ${_native}/windowsroutemonitor.cpp ${_native}/windowsfirewall.cpp
    ${_native}/windowsdaemon.cpp ${_native}/windowssplittunnel.cpp)
set_target_properties(windows_uapi_sdk_compile PROPERTIES AUTOMOC OFF)
target_include_directories(windows_uapi_sdk_compile PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/stubs ${_root}/client ${_root}/client/mozilla/shared ${_native})
target_compile_definitions(windows_uapi_sdk_compile PRIVATE UNICODE _UNICODE _WINSOCKAPI_ WINVER=0x0A00 _WIN32_WINNT=0x0A00)
find_package(Qt6 REQUIRED COMPONENTS Core5Compat)
target_link_libraries(windows_uapi_sdk_compile PRIVATE Qt6::Core Qt6::Network Qt6::Widgets Qt6::Core5Compat)
