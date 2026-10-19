#!/usr/bin/env bash
# AWS SDK for C++ — S3 component only, via vcpkg (manifest: vcpkg.json).
# Arrow S3FileSystem has no If-Match / If-None-Match; registry/leases need those.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPS="${DUCKBOX_DEPS:-$ROOT/.deps}"
VCPKG_ROOT="${VCPKG_ROOT:-$DEPS/vcpkg}"
INSTALL_ROOT="${DUCKBOX_VCPKG_INSTALLED:-$DEPS/vcpkg_installed}"
# Pin for CI cache stability. Newer tags are fine if this clone fails.
VCPKG_TAG="${VCPKG_TAG:-2025.09.17}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$os-$arch" in
  linux-x86_64|linux-amd64) TRIPLET="${VCPKG_DEFAULT_TRIPLET:-x64-linux}" ;;
  linux-aarch64|linux-arm64) TRIPLET="${VCPKG_DEFAULT_TRIPLET:-arm64-linux}" ;;
  darwin-arm64) TRIPLET="${VCPKG_DEFAULT_TRIPLET:-arm64-osx}" ;;
  darwin-x86_64) TRIPLET="${VCPKG_DEFAULT_TRIPLET:-x64-osx}" ;;
  *)
    echo "No vcpkg triplet for $os-$arch" >&2
    exit 1
    ;;
esac
export VCPKG_DEFAULT_TRIPLET="$TRIPLET"

aws_config() {
  local root="$1"
  [[ -f "$root/$TRIPLET/share/aws-cpp-sdk-s3/aws-cpp-sdk-s3-config.cmake" ]] ||
    [[ -f "$root/$TRIPLET/share/awssdk/AWSSDKConfig.cmake" ]] ||
    [[ -f "$root/$TRIPLET/share/aws-sdk-cpp/AWSSDKConfig.cmake" ]] ||
    [[ -f "$root/$TRIPLET/share/AWSSDK/AWSSDKConfig.cmake" ]]
}

if aws_config "$INSTALL_ROOT" || aws_config "$VCPKG_ROOT/installed"; then
  echo "aws-sdk-cpp[s3] already installed ($TRIPLET)"
  exit 0
fi

if [[ "$os" == "linux" ]]; then
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    SUDO="sudo"
  else
    SUDO=""
  fi
  $SUDO apt-get update -qq
  $SUDO apt-get install -y --no-install-recommends \
    git curl zip unzip tar pkg-config ninja-build ca-certificates \
    libssl-dev libcurl4-openssl-dev zlib1g-dev
fi

mkdir -p "$DEPS/vcpkg-bincache" "$INSTALL_ROOT"
export VCPKG_BINARY_SOURCES="${VCPKG_BINARY_SOURCES:-clear;files,$DEPS/vcpkg-bincache,readwrite}"

if [[ ! -x "$VCPKG_ROOT/vcpkg" ]]; then
  rm -rf "$VCPKG_ROOT"
  echo "Cloning vcpkg ${VCPKG_TAG}"
  if ! git clone --depth 1 --branch "$VCPKG_TAG" https://github.com/microsoft/vcpkg.git "$VCPKG_ROOT"; then
    echo "Tag ${VCPKG_TAG} missing; cloning vcpkg HEAD"
    git clone --depth 1 https://github.com/microsoft/vcpkg.git "$VCPKG_ROOT"
  fi
  "$VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics
fi

# Linux: vcpkg's compiler probe uses `c++`, which may be Clang without libstdc++.
# Pin GNU so the S3 SDK matches duckbox's g++ link. macOS uses AppleClang.
if [[ "$os" == "linux" ]]; then
  export CC="${CC:-gcc}"
  export CXX="${CXX:-g++}"
fi

echo "Installing aws-sdk-cpp[s3] from vcpkg.json ($TRIPLET) CC=$CC CXX=$CXX"
"$VCPKG_ROOT/vcpkg" install --vcpkg-root="$VCPKG_ROOT" --triplet="$TRIPLET" \
  --x-install-root="$INSTALL_ROOT" --x-manifest-root="$ROOT" \
  --clean-after-build

echo "AWS SDK C++ S3 ready in $INSTALL_ROOT/$TRIPLET"
