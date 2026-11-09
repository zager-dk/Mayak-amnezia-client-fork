# Mayak platform branding. Android's package and settings identity remain stable.
set(CLIENT_ANDROID_APP_NAME "Маяк VPN" CACHE STRING "Android launcher label")
set(CLIENT_ANDROID_PACKAGE "ru.mayaklight.vpn" CACHE STRING "Android package name")

# Windows is a separate product installation. Android keeps its existing package
# and settings identity above; these defaults are consumed only by Windows.
if(WIN32)
    # Keep CMake's generated default install root separate from the upstream
    # project. Respect any prefix supplied explicitly by the packager/user.
    if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
        get_filename_component(_mayak_install_parent "${CMAKE_INSTALL_PREFIX}" DIRECTORY)
        set(_mayak_install_prefix "${_mayak_install_parent}/MayakVPN")
        unset(CMAKE_INSTALL_PREFIX)
        unset(CMAKE_INSTALL_PREFIX CACHE)
        set(CMAKE_INSTALL_PREFIX "${_mayak_install_prefix}" CACHE PATH "Install path prefix, prepended onto install directories")
        unset(_mayak_install_parent)
        unset(_mayak_install_prefix)
    endif()

    set(CLIENT_TARGET_NAME "MayakVPN" CACHE STRING "Windows client executable target")
    set(CLIENT_APPLICATION_NAME "MayakVPN" CACHE STRING "Windows application and executable name")
    set(CLIENT_SERVICE_NAME "MayakVPN-service" CACHE STRING "Windows service executable name")
    set(CLIENT_ORGANIZATION_NAME "MayakVPN.ORG" CACHE STRING "Windows settings organization")
    set(CLIENT_APP_INSTANCE_NAME "MayakVPNInstance" CACHE STRING "Windows single-instance IPC name")
    set(CLIENT_KEYCHAIN_NAME "MayakVPN-Keychain" CACHE STRING "Windows encrypted-settings keychain service")
    # Windows uses the Mayak signed feed; it never falls through to the
    # upstream gateway's app_update endpoint.
    set(CLIENT_ENABLE_APP_UPDATES 1)
endif()
