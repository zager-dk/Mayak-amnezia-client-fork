[settings]
os=Android
os.api_level=28
arch=armv8
compiler=clang
compiler.version=18
compiler.libcxx=c++_shared
build_type=Release

[options]
openssl/*:shared=True

[conf]
tools.android:ndk_path=<ANDROID_NDK_ROOT>
tools.android:cmake_legacy_toolchain=false
tools.cmake.cmaketoolchain:generator=Ninja
tools.build:sharedlinkflags=['-Wl,-z,max-page-size=16384']
tools.build:exelinkflags=['-Wl,-z,max-page-size=16384']
