#!/usr/bin/env bash
# Download DuckDB 1.5.6 headers + static libs, cpp-httplib, yaml-cpp,
# and nlohmann/json. AWS SDK C++ (S3) is scripts/install_aws_sdk.sh (vcpkg).
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

YAML_CPP_VERSION="${YAML_CPP_VERSION:-0.8.0}"
NLOHMANN_JSON_VERSION="${NLOHMANN_JSON_VERSION:-v3.11.3}"
yaml_tar="$DEPS/cache/yaml-cpp-${YAML_CPP_VERSION}.tar.gz"
json_hdr="$DEPS/cache/nlohmann-json-${NLOHMANN_JSON_VERSION}.hpp"
download "https://github.com/duckdb/duckdb/archive/refs/tags/${DUCKDB_VERSION}.tar.gz" "$src_tar"
download "$base/$lib_zip" "$lib_zip_path"
download "https://raw.githubusercontent.com/yhirose/cpp-httplib/${HTTP_LIB_VERSION}/httplib.h" "$DEPS/httplib/httplib.h"
download "https://github.com/jbeder/yaml-cpp/archive/refs/tags/${YAML_CPP_VERSION}.tar.gz" "$yaml_tar"
download "https://github.com/nlohmann/json/releases/download/${NLOHMANN_JSON_VERSION}/json.hpp" "$json_hdr"
mkdir -p "$DEPS/nlohmann/nlohmann"
cp -f "$json_hdr" "$DEPS/nlohmann/nlohmann/json.hpp"
if [[ ! -f "$DEPS/yaml-cpp-${YAML_CPP_VERSION}/CMakeLists.txt" ]]; then
  echo "Extracting yaml-cpp ${YAML_CPP_VERSION}"
  tar -xzf "$yaml_tar" -C "$DEPS"
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
