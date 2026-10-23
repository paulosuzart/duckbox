#!/usr/bin/env bash
# Arrow C++ with Flight SQL. Linux: Apache APT. macOS: Homebrew.
# Pin Arrow 26.0.0 (the version CI installs today) so the APT cache key is stable.
set -euo pipefail

ARROW_VERSION="${ARROW_VERSION:-26.0.0}"
ARROW_APT_VERSION="${ARROW_APT_VERSION:-${ARROW_VERSION}-1}"
ARROW_APT_CACHE="${ARROW_APT_CACHE:-${HOME}/.cache/duckbox-apt}"

os="$(uname -s)"
if [[ "$os" == "Linux" ]]; then
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    SUDO="sudo"
  else
    SUDO=""
  fi

  # GitHub-hosted runners sometimes see 15 kB/s Azure Ubuntu mirrors; retry.
  echo 'Acquire::Retries "5";' | $SUDO tee /etc/apt/apt.conf.d/80-duckbox-retries >/dev/null

  seed_apt_archives() {
    mkdir -p "${ARROW_APT_CACHE}"
    local n
    n="$(find "${ARROW_APT_CACHE}" -maxdepth 1 -name '*.deb' | wc -l)"
    if [[ "${n}" -gt 0 ]]; then
      $SUDO mkdir -p /var/cache/apt/archives/partial
      $SUDO cp -n "${ARROW_APT_CACHE}"/*.deb /var/cache/apt/archives/ || true
      echo "Seeded apt archives from ${ARROW_APT_CACHE} (${n} debs, $(du -sh "${ARROW_APT_CACHE}" | awk '{print $1}'))"
    else
      echo "Arrow APT cache empty (cold download)"
    fi
  }

  save_apt_archives() {
    local src="${1:-}"
    mkdir -p "${ARROW_APT_CACHE}"
    find /var/cache/apt/archives -maxdepth 1 -name '*.deb' -exec cp -n {} "${ARROW_APT_CACHE}/" \; || true
    if [[ -n "${src}" && -f "${src}" ]]; then
      cp -n "${src}" "${ARROW_APT_CACHE}/" || true
    fi
    echo "Saved apt archives to ${ARROW_APT_CACHE} ($(find "${ARROW_APT_CACHE}" -maxdepth 1 -name '*.deb' | wc -l) debs, $(du -sh "${ARROW_APT_CACHE}" | awk '{print $1}'))"
  }

  seed_apt_archives

  $SUDO apt-get update -qq
  $SUDO apt-get install -y --no-install-recommends ca-certificates lsb-release wget g++ cmake unzip curl zip tar \
    pkg-config ninja-build git libssl-dev libcurl4-openssl-dev zlib1g-dev
  codename="$(lsb_release --codename --short)"
  deb="apache-arrow-apt-source-latest-${codename}.deb"
  if [[ -f "${ARROW_APT_CACHE}/${deb}" ]]; then
    cp -f "${ARROW_APT_CACHE}/${deb}" "/tmp/${deb}"
    echo "Using cached Apache apt source ${deb}"
  else
    wget -q "https://packages.apache.org/artifactory/arrow/ubuntu/${deb}" -O "/tmp/${deb}"
  fi
  $SUDO apt-get install -y "/tmp/${deb}"
  $SUDO apt-get update -qq
  $SUDO apt-get install -y \
    "libarrow-dev=${ARROW_APT_VERSION}" \
    "libarrow-flight-dev=${ARROW_APT_VERSION}" \
    "libarrow-flight-sql-dev=${ARROW_APT_VERSION}"
  installed="$(pkg-config --modversion arrow)"
  if [[ "${installed}" != "${ARROW_VERSION}" ]]; then
    echo "Pinned Arrow ${ARROW_VERSION} but pkg-config reports ${installed}" >&2
    exit 1
  fi
  echo "Arrow ${installed} with Flight SQL (pinned ${ARROW_APT_VERSION})"
  save_apt_archives "/tmp/${deb}"
elif [[ "$os" == "Darwin" ]]; then
  brew install apache-arrow aws-sdk-cpp openssl@4 cmake ninja
  echo "Arrow + aws-sdk-cpp via Homebrew (openssl@4; Flight SQL enabled in recent formulae)"
else
  echo "Install Apache Arrow C++ with ARROW_FLIGHT=ON ARROW_FLIGHT_SQL=ON" >&2
  exit 1
fi
