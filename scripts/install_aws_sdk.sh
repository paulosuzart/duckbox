#!/usr/bin/env bash
# AWS SDK for C++ — S3 + STS + identity-management via vcpkg (vcpkg.json).
# Linux only. macOS uses Homebrew aws-sdk-cpp + openssl@4 (Arrow/gRPC already
# load openssl@4; a second vcpkg OpenSSL 3.5 in the same binary aborts).
# Lease assume-role needs STSAssumeRoleCredentialsProvider (identity-management)
# and STSClient (sts). Arrow S3FileSystem has no If-Match / If-None-Match.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPS="${DUCKBOX_DEPS:-$ROOT/.deps}"
VCPKG_ROOT="${VCPKG_ROOT:-$DEPS/vcpkg}"
INSTALL_ROOT="${DUCKBOX_VCPKG_INSTALLED:-$DEPS/vcpkg_installed}"
# Pin for CI cache stability. Newer tags are fine if this clone fails.
VCPKG_TAG="${VCPKG_TAG:-2025.09.17}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [[ "$os" == "darwin" ]]; then
  echo "macOS uses Homebrew aws-sdk-cpp, not vcpkg:" >&2
  echo "  brew install aws-sdk-cpp openssl@4" >&2
  exit 1
fi

arch="$(uname -m)"
case "$os-$arch" in
  linux-x86_64|linux-amd64) TRIPLET="${VCPKG_DEFAULT_TRIPLET:-x64-linux}" ;;
  linux-aarch64|linux-arm64) TRIPLET="${VCPKG_DEFAULT_TRIPLET:-arm64-linux}" ;;
  *)
    echo "No vcpkg triplet for $os-$arch (Linux only)" >&2
    exit 1
    ;;
esac
export VCPKG_DEFAULT_TRIPLET="$TRIPLET"

aws_config() {
  local root="$1"
  local prefix="$root/$TRIPLET/share"
  # S3 alone is not enough — assume-role needs STS + identity-management.
  [[ -f "$prefix/aws-cpp-sdk-s3/aws-cpp-sdk-s3-config.cmake" &&
     -f "$prefix/aws-cpp-sdk-sts/aws-cpp-sdk-sts-config.cmake" &&
     -f "$prefix/aws-cpp-sdk-identity-management/aws-cpp-sdk-identity-management-config.cmake" ]]
}

if aws_config "$INSTALL_ROOT" || aws_config "$VCPKG_ROOT/installed"; then
  echo "aws-sdk-cpp[s3,sts,identity-management] already installed ($TRIPLET)"
  exit 0
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi
$SUDO apt-get update -qq
$SUDO apt-get install -y --no-install-recommends \
  git curl zip unzip tar pkg-config ninja-build ca-certificates \
  libssl-dev libcurl4-openssl-dev zlib1g-dev

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

# vcpkg's compiler probe uses `c++`, which may be Clang without libstdc++.
# Pin GNU so the S3 SDK matches duckbox's g++ link.
export CC="${CC:-gcc}"
export CXX="${CXX:-g++}"

echo "Installing aws-sdk-cpp[s3,sts,identity-management] from vcpkg.json ($TRIPLET) CC=${CC:-} CXX=${CXX:-}"
"$VCPKG_ROOT/vcpkg" install --vcpkg-root="$VCPKG_ROOT" --triplet="$TRIPLET" \
  --x-install-root="$INSTALL_ROOT" --x-manifest-root="$ROOT" \
  --clean-after-build

echo "AWS SDK C++ S3+STS ready in $INSTALL_ROOT/$TRIPLET"
