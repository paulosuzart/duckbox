# Overlay of vcpkg 2025.09.17 triplets/arm64-osx.cmake.
# SDK 27 headers mark pipe2 as macOS 27.0+; curl's check_function_exists finds it
# and then compiles socketpair.c with -Werror (unguarded-availability-new).
# Do not raise VCPKG_OSX_DEPLOYMENT_TARGET / MACOSX_DEPLOYMENT_TARGET to 27 —
# binaries would not run on 26.x. curl's own Apple prefill is HAVE_PIPE2=0;
# vcpkg does not use that cache, so force the CMake check off and keep the
# warning from becoming a hard error.
set(VCPKG_TARGET_ARCHITECTURE arm64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

set(VCPKG_CMAKE_SYSTEM_NAME Darwin)
set(VCPKG_OSX_ARCHITECTURES arm64)

set(VCPKG_C_FLAGS "${VCPKG_C_FLAGS} -Wno-error=unguarded-availability-new")
set(VCPKG_CXX_FLAGS "${VCPKG_CXX_FLAGS} -Wno-error=unguarded-availability-new")
list(APPEND VCPKG_CMAKE_CONFIGURE_OPTIONS "-DHAVE_PIPE2=OFF")
