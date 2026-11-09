# Inject the exact, previously verified Conan dependency graph into the
# project's supported CMAKE_PROJECT_INCLUDE hook. This file is helper-owned;
# product CMake sources remain unchanged.
foreach(_required_var MAYAK_ANDROID_HOST_PROFILE MAYAK_ANDROID_BUILD_PROFILE MAYAK_ANDROID_CONAN_LOCK MAYAK_ANDROID_NDK_ROOT)
    if(NOT DEFINED ${_required_var} OR "${${_required_var}}" STREQUAL "")
        message(FATAL_ERROR "Missing required Android Conan helper setting: ${_required_var}")
    endif()
endforeach()

if(NOT EXISTS "${MAYAK_ANDROID_HOST_PROFILE}" OR NOT EXISTS "${MAYAK_ANDROID_BUILD_PROFILE}" OR NOT EXISTS "${MAYAK_ANDROID_CONAN_LOCK}")
    message(FATAL_ERROR "Android Conan helper profile or lockfile does not exist")
endif()

if(NOT CMAKE_GENERATOR STREQUAL "Ninja")
    message(FATAL_ERROR "Android Conan graph requires the Ninja generator")
endif()

file(READ "${MAYAK_ANDROID_HOST_PROFILE}" _android_host_profile)
foreach(_profile_requirement
        "os=Android"
        "os.api_level=28"
        "arch=armv8"
        "compiler=clang"
        "compiler.version=18"
        "compiler.libcxx=c++_shared"
        "build_type=Release"
        "openssl/*:shared=True"
        "tools.android:cmake_legacy_toolchain=false"
        "tools.cmake.cmaketoolchain:generator=Ninja"
        "-Wl,-z,max-page-size=16384")
    string(FIND "${_android_host_profile}" "${_profile_requirement}" _profile_requirement_index)
    if(_profile_requirement_index EQUAL -1)
        message(FATAL_ERROR "Android host profile is missing required setting: ${_profile_requirement}")
    endif()
endforeach()

set(_android_conan_args
    "--no-remote"
    "--lockfile=${MAYAK_ANDROID_CONAN_LOCK}"
    "-o=openssl/*:shared=True"
    "-o:b=msys2/*:packages=base-devel,binutils,gcc,mingw-w64-cross-mingwarm64-gcc"
    "-c=tools.android:cmake_legacy_toolchain=false"
    "-c=tools.android:ndk_path=${MAYAK_ANDROID_NDK_ROOT}"
    "-c=tools.cmake.cmaketoolchain:generator=Ninja"
    "-c=tools.build:sharedlinkflags=['-Wl,-z,max-page-size=16384']"
    "-c=tools.build:exelinkflags=['-Wl,-z,max-page-size=16384']")
foreach(_arg IN LISTS _android_conan_args)
    list(FIND CONAN_INSTALL_ARGS "${_arg}" _arg_index)
    if(_arg_index EQUAL -1)
        list(APPEND CONAN_INSTALL_ARGS "${_arg}")
    endif()
endforeach()
set(CONAN_INSTALL_ARGS "${CONAN_INSTALL_ARGS}" CACHE STRING "Command line arguments for conan install" FORCE)
message(STATUS "Mayak Android Conan provider pinned to source lock and Android API 28/arm64 clang 18 profile")
