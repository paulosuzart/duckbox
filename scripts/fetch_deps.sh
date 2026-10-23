#!/usr/bin/env bash
# Download DuckDB 1.5.6 headers + static libs, cpp-httplib, yaml-cpp,
# nlohmann/json, jwt-cpp, CLI11, and cppcodec.
# AWS SDK C++ (S3+STS): Linux scripts/install_aws_sdk.sh (vcpkg); macOS brew aws-sdk-cpp openssl@4.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPS="${DUCKBOX_DEPS:-$ROOT/.deps}"
DUCKDB_VERSION="${DUCKDB_VERSION:-v1.5.6}"
HTTP_LIB_VERSION="${HTTP_LIB_VERSION:-v0.18.1}"

mkdir -p "$DEPS/duckdb/include" "$DEPS/duckdb/lib" "$DEPS/httplib"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$os-$arch" in
  linux-x86_64|linux-amd64) lib_zip="static-libs-linux-amd64.zip" ;;
  linux-aarch64|linux-arm64) lib_zip="static-libs-linux-arm64.zip" ;;
  darwin-arm64) lib_zip="static-libs-osx-arm64.zip" ;;
  darwin-x86_64) lib_zip="static-libs-osx-amd64.zip" ;;
  *)
    echo "No prebuilt DuckDB static libs for $os-$arch." >&2
    echo "Set DUCKBOX_DEPS to a directory with duckdb/include and duckdb/lib." >&2
    exit 1
    ;;
esac

base="https://github.com/duckdb/duckdb/releases/download/${DUCKDB_VERSION}"
src_tar="$DEPS/cache/duckdb-src.tar.gz"
lib_zip_path="$DEPS/cache/$lib_zip"
mkdir -p "$DEPS/cache"

download() {
  local url="$1" dest="$2"
  if [[ -f "$dest" && -s "$dest" ]]; then
    return 0
  fi
  echo "Downloading $url"
  curl -fsSL -o "$dest.partial" "$url"
  mv "$dest.partial" "$dest"
}

# Reuse already-downloaded artifacts in /tmp when present (dev machines / this agent).
if [[ -f /tmp/duckdb-src.tar.gz && ! -f "$src_tar" ]]; then
  cp /tmp/duckdb-src.tar.gz "$src_tar"
fi
if [[ -f /tmp/duckdb-dl/static-libs-linux-amd64.zip && "$lib_zip" == "static-libs-linux-amd64.zip" && ! -f "$lib_zip_path" ]]; then
  cp /tmp/duckdb-dl/static-libs-linux-amd64.zip "$lib_zip_path"
fi

# 0.9.0 is cmake_minimum_required 3.5...3.30 (CMake 4 rejects 0.8.0's 3.4).
YAML_CPP_VERSION="${YAML_CPP_VERSION:-0.9.0}"
YAML_CPP_TAG="${YAML_CPP_TAG:-yaml-cpp-${YAML_CPP_VERSION}}"
NLOHMANN_JSON_VERSION="${NLOHMANN_JSON_VERSION:-v3.11.3}"
JWT_CPP_VERSION="${JWT_CPP_VERSION:-v0.7.0}"
CLI11_VERSION="${CLI11_VERSION:-v2.4.2}"
CPPCODEC_VERSION="${CPPCODEC_VERSION:-v0.2}"
yaml_tar="$DEPS/cache/yaml-cpp-${YAML_CPP_TAG}.tar.gz"
json_hdr="$DEPS/cache/nlohmann-json-${NLOHMANN_JSON_VERSION}.hpp"
jwt_tar="$DEPS/cache/jwt-cpp-${JWT_CPP_VERSION}.tar.gz"
cli11_hdr="$DEPS/cache/CLI11-${CLI11_VERSION}.hpp"
codec_tar="$DEPS/cache/cppcodec-${CPPCODEC_VERSION}.tar.gz"
download "https://github.com/duckdb/duckdb/archive/refs/tags/${DUCKDB_VERSION}.tar.gz" "$src_tar"
download "$base/$lib_zip" "$lib_zip_path"
download "https://raw.githubusercontent.com/yhirose/cpp-httplib/${HTTP_LIB_VERSION}/httplib.h" "$DEPS/httplib/httplib.h"
download "https://github.com/jbeder/yaml-cpp/archive/refs/tags/${YAML_CPP_TAG}.tar.gz" "$yaml_tar"
download "https://github.com/nlohmann/json/releases/download/${NLOHMANN_JSON_VERSION}/json.hpp" "$json_hdr"
download "https://github.com/Thalhammer/jwt-cpp/archive/refs/tags/${JWT_CPP_VERSION}.tar.gz" "$jwt_tar"
download "https://github.com/CLIUtils/CLI11/releases/download/${CLI11_VERSION}/CLI11.hpp" "$cli11_hdr"
download "https://github.com/tplgy/cppcodec/archive/refs/tags/${CPPCODEC_VERSION}.tar.gz" "$codec_tar"
mkdir -p "$DEPS/nlohmann/nlohmann"
cp -f "$json_hdr" "$DEPS/nlohmann/nlohmann/json.hpp"
mkdir -p "$DEPS/cli11/CLI"
cp -f "$cli11_hdr" "$DEPS/cli11/CLI/CLI.hpp"
if [[ ! -f "$DEPS/yaml-cpp/CMakeLists.txt" ]]; then
  echo "Extracting yaml-cpp ${YAML_CPP_TAG}"
  tmp="$(mktemp -d)"
  tar -xzf "$yaml_tar" -C "$tmp"
  src_root="$(find "$tmp" -maxdepth 1 -type d -name 'yaml-cpp-*' | head -1)"
  rm -rf "$DEPS/yaml-cpp"
  mv "$src_root" "$DEPS/yaml-cpp"
  rm -rf "$tmp"
fi
if [[ ! -f "$DEPS/jwt-cpp/include/jwt-cpp/jwt.h" ]]; then
  echo "Extracting jwt-cpp ${JWT_CPP_VERSION}"
  tmp="$(mktemp -d)"
  tar -xzf "$jwt_tar" -C "$tmp"
  src_root="$(find "$tmp" -maxdepth 1 -type d -name 'jwt-cpp-*' | head -1)"
  rm -rf "$DEPS/jwt-cpp"
  mkdir -p "$DEPS/jwt-cpp"
  cp -a "$src_root/include" "$DEPS/jwt-cpp/include"
  rm -rf "$tmp"
fi
if [[ ! -f "$DEPS/cppcodec/cppcodec/base64_url_unpadded.hpp" ]]; then
  echo "Extracting cppcodec ${CPPCODEC_VERSION}"
  tmp="$(mktemp -d)"
  tar -xzf "$codec_tar" -C "$tmp"
  src_root="$(find "$tmp" -maxdepth 1 -type d -name 'cppcodec-*' | head -1)"
  rm -rf "$DEPS/cppcodec"
  mkdir -p "$DEPS/cppcodec"
  cp -a "$src_root/cppcodec" "$DEPS/cppcodec/cppcodec"
  rm -rf "$tmp"
fi

if [[ ! -f "$DEPS/duckdb/include/duckdb/parser/parser.hpp" ]]; then
  echo "Extracting DuckDB headers"
  tmp="$(mktemp -d)"
  tar -xzf "$src_tar" -C "$tmp"
  src_root="$(find "$tmp" -maxdepth 1 -type d -name 'duckdb-*' | head -1)"
  rm -rf "$DEPS/duckdb/include"
  mkdir -p "$DEPS/duckdb"
  cp -a "$src_root/src/include" "$DEPS/duckdb/include"
  rm -rf "$tmp"
fi

if [[ ! -f "$DEPS/duckdb/lib/libduckdb_static.a" ]]; then
  echo "Extracting DuckDB static libraries"
  unzip -o -q "$lib_zip_path" -d "$DEPS/duckdb/lib"
fi

echo "DuckDB ${DUCKDB_VERSION} deps ready in $DEPS"
