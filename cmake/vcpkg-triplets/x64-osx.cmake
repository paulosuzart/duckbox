# Overlay of vcpkg 2025.09.17 triplets/x64-osx.cmake.
# SDK 27 headers mark pipe2 as macOS 27.0+; curl builds with -Werror and fails on
# macOS 26.x (SDK 27) via -Wunguarded-availability-new. Do not raise
# VCPKG_OSX_DEPLOYMENT_TARGET / MACOSX_DEPLOYMENT_TARGET to 27 — binaries would
# not run on 26.x. Downgrade that warning so first-time aws-sdk-cpp (curl) builds.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

set(VCPKG_CMAKE_SYSTEM_NAME Darwin)
set(VCPKG_OSX_ARCHITECTURES x86_64)

set(VCPKG_C_FLAGS "${VCPKG_C_FLAGS} -Wno-error=unguarded-availability-new")
set(VCPKG_CXX_FLAGS "${VCPKG_CXX_FLAGS} -Wno-error=unguarded-availability-new")
