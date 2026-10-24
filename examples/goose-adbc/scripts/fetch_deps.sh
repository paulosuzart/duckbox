#!/usr/bin/env bash
# Fetch pinned goose + ADBC (headers, driver manager, Flight SQL .so)
# into examples/goose-adbc/.deps. Not used by the default duckbox build.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPS="${DBX_GOOSE_ADBC_DEPS:-$ROOT/.deps}"
GOOSE_VERSION="${DUCKBOX_GOOSE_VERSION:-v2026.3}"
ADBC_TAG="${DBX_ADBC_TAG:-apache-arrow-adbc-18}"
FLIGHTSQL_VERSION="${DBX_FLIGHTSQL_VERSION:-1.12.0}"

mkdir -p "${DEPS}"

need_sha() {
  local file="$1" want="$2"
  local got
  if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "${file}" | awk '{print $1}')"
  else
    got="$(shasum -a 256 "${file}" | awk '{print $1}')"
  fi
  if [[ "${got}" != "${want}" ]]; then
    echo "fetch_deps.sh: sha256 mismatch for $(basename "${file}")" >&2
    echo "  expected ${want}" >&2
    echo "  got      ${got}" >&2
    rm -f "${file}"
    exit 1
  fi
}

fetch_goose() {
  local dest="${DEPS}/goose-${GOOSE_VERSION}"
  if [[ -x "${dest}/goose" ]]; then
    echo "goose ${GOOSE_VERSION} already at ${dest}"
    return 0
  fi
  local os arch asset sha
  os="$(uname -s)"
  arch="$(uname -m)"
  case "${os}-${arch}" in
    Linux-x86_64)
      asset="goose-${GOOSE_VERSION}-linux-x64.tar.gz"
      sha="06ac30284338269d3996d457412bf4f2b47c1f9a5601de65b6317187fe78d5c9"
      ;;
    Darwin-arm64)
      asset="goose-${GOOSE_VERSION}-macos-arm64.tar.gz"
      sha="2ffaaf46b3edde27aed03fcd9ebe73e9b6639cac30d8a6915f7dc00795b7aedf"
      ;;
    Darwin-x86_64)
      asset="goose-${GOOSE_VERSION}-macos-x64.tar.gz"
      sha="3c7f2895f3dcab5f39ee52808446b00688b975620d1d27e23694dd22b82abfe7"
      ;;
    *)
      echo "fetch_deps.sh: no prebuilt goose ${GOOSE_VERSION} for ${os} ${arch}" >&2
      exit 1
      ;;
  esac
  local url="https://github.com/aardappel/goose/releases/download/${GOOSE_VERSION}/${asset}"
  local tmp="${DEPS}/${asset}"
  echo "Fetching ${url}"
  curl -fsSL -o "${tmp}" "${url}"
  need_sha "${tmp}" "${sha}"
  mkdir -p "${dest}"
  tar -xzf "${tmp}" -C "${dest}" --strip-components=1
  rm -f "${tmp}"
  chmod +x "${dest}/goose"
  echo "goose ${GOOSE_VERSION} ready at ${dest}/goose"
}

fetch_adbc_source() {
  local dest="${DEPS}/adbc"
  if [[ -f "${dest}/include/arrow-adbc/adbc.h" && -f "${dest}/src/adbc_driver_manager.cc" ]]; then
    echo "ADBC ${ADBC_TAG} headers/manager already at ${dest}"
    return 0
  fi
  local url="https://github.com/apache/arrow-adbc/archive/refs/tags/${ADBC_TAG}.tar.gz"
  local tmp="${DEPS}/${ADBC_TAG}.tar.gz"
  echo "Fetching ${url}"
  curl -fsSL -L -o "${tmp}" "${url}"
  if [[ "${ADBC_TAG}" == "apache-arrow-adbc-18" ]]; then
    need_sha "${tmp}" "12b2ef9484856d0b5592d14c27c48c15eeae01f7c8101f4ff1606bed67b11a62"
  fi
  local extract="${DEPS}/src-${ADBC_TAG}"
  rm -rf "${extract}"
  mkdir -p "${extract}"
  tar -xzf "${tmp}" -C "${extract}" --strip-components=1
  mkdir -p "${dest}/include" "${dest}/src"
  cp -a "${extract}/c/include/." "${dest}/include/"
  cp -a "${extract}/c/driver_manager/adbc_driver_manager.cc" "${dest}/src/"
  if [[ -f "${extract}/c/driver_manager/adbc_version_100.c" ]]; then
    cp -a "${extract}/c/driver_manager/adbc_version_100.c" "${dest}/src/"
    cp -a "${extract}/c/driver_manager/adbc_version_100.h" "${dest}/src/" 2>/dev/null || true
  fi
  rm -rf "${extract}" "${tmp}"
  echo "ADBC ${ADBC_TAG} headers/manager ready at ${dest}"
}

fetch_flightsql() {
  local dest="${DEPS}/adbc/lib"
  local so="${dest}/libadbc_driver_flightsql.so"
  if [[ -f "${so}" || -f "${dest}/libadbc_driver_flightsql.dylib" ]]; then
    echo "Flight SQL driver already under ${dest}"
    return 0
  fi
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  if [[ "${os}" != "Linux" || "${arch}" != "x86_64" ]]; then
    echo "fetch_deps.sh: pinned Flight SQL wheel is Linux x86_64." >&2
    echo "Install adbc-driver-flightsql and copy libadbc_driver_flightsql.* into ${dest}" >&2
    exit 1
  fi
  local filename="adbc_driver_flightsql-${FLIGHTSQL_VERSION}-py3-none-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl"
  local url="https://files.pythonhosted.org/packages/2b/5b/f8566aa6d05eb40225f5874f8f5f5e8b8b4a4ce866d817a5ff352f326302/${filename}"
  local sha="69742e4f8fcc254490aa7f8e254a3b704c24bde9d5d827a0926ea90a6b4c3a6d"
  local tmp="${DEPS}/${filename}"
  echo "Fetching ${url}"
  curl -fsSL -o "${tmp}" "${url}"
  need_sha "${tmp}" "${sha}"
  local unpack="${DEPS}/whl-flightsql"
  rm -rf "${unpack}"
  mkdir -p "${unpack}" "${dest}"
  python3 - "${tmp}" "${unpack}" <<'PY'
import sys, zipfile
zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])
PY
  local found
  found="$(find "${unpack}" -name 'libadbc_driver_flightsql.so*' | head -n 1)"
  if [[ -z "${found}" ]]; then
    echo "fetch_deps.sh: wheel has no libadbc_driver_flightsql.so" >&2
    exit 1
  fi
  cp -a "${found}" "${so}"
  rm -rf "${unpack}" "${tmp}"
  echo "Flight SQL driver ready at ${so}"
}

fetch_goose
fetch_adbc_source
fetch_flightsql
echo "deps ready under ${DEPS}"
