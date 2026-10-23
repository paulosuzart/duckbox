#!/usr/bin/env bash
# Arrow C++ with Flight SQL. Linux: Apache APT. macOS: Homebrew.
# Pin Arrow 26.0.0 (the version CI installs today) so the APT cache key is stable.
#
# Linux CI downloads every .deb (Arrow and transitive Ubuntu deps) into
# ARROW_APT_CACHE via Dir::Cache::Archives, then installs from that directory.
# The workflow caches the directory so warm jobs skip the Ubuntu mirror.
set -euo pipefail

ARROW_VERSION="${ARROW_VERSION:-26.0.0}"
ARROW_APT_VERSION="${ARROW_APT_VERSION:-${ARROW_VERSION}-1}"
ARROW_APT_CACHE="${ARROW_APT_CACHE:-${HOME}/.cache/duckbox-apt}"

# Package list is part of the CI cache key (hash of this file).
ARROW_BUILD_PACKAGES=(
  ca-certificates lsb-release wget g++ cmake unzip curl zip tar
  pkg-config ninja-build git libssl-dev libcurl4-openssl-dev zlib1g-dev
)
ARROW_DEV_PACKAGES=(
  "libarrow-dev=${ARROW_APT_VERSION}"
  "libarrow-flight-dev=${ARROW_APT_VERSION}"
  "libarrow-flight-sql-dev=${ARROW_APT_VERSION}"
)

os="$(uname -s)"
if [[ "$os" == "Linux" ]]; then
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    SUDO="sudo"
  else
    SUDO=""
  fi

  # GitHub-hosted runners use azure.archive.ubuntu.com. When that mirror
  # stalls at 15-100 kB/s (run 40016321532), cmake / libgrpc / protobuf take
  # 13-15 minutes. Prefer archive.ubuntu.com via mirror+file: and fail over
  # with Acquire::Retries + Acquire::http::Timeout instead of crawling Azure.
  configure_apt_mirrors() {
    $SUDO tee /etc/apt/apt.conf.d/80-duckbox-acquire >/dev/null <<'EOF'
Acquire::Retries "5";
Acquire::http::Timeout "20";
Acquire::https::Timeout "20";
EOF

    $SUDO mkdir -p /etc/apt/mirrors
    local list
    list="$(mktemp)"
    cat >"${list}" <<'EOF'
http://archive.ubuntu.com/ubuntu/
http://security.ubuntu.com/ubuntu/
http://azure.archive.ubuntu.com/ubuntu/
EOF
    $SUDO cp "${list}" /etc/apt/mirrors/ubuntu.list
    # ubuntu-latest already reads this mirror list; put the public archive first.
    if [[ -f /etc/apt/apt-mirrors.txt ]]; then
      $SUDO cp "${list}" /etc/apt/apt-mirrors.txt
    fi
    rm -f "${list}"

    local src
    for src in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
      [[ -f "${src}" ]] || continue
      if grep -q 'azure.archive.ubuntu.com' "${src}"; then
        $SUDO sed -i \
          -e 's|https\?://azure.archive.ubuntu.com/ubuntu/|mirror+file:/etc/apt/mirrors/ubuntu.list|g' \
          -e 's|https\?://azure.archive.ubuntu.com/ubuntu|mirror+file:/etc/apt/mirrors/ubuntu.list|g' \
          "${src}"
      fi
    done
  }

  prepare_apt_cache() {
    mkdir -p "${ARROW_APT_CACHE}/partial"
    chmod -R a+rwX "${ARROW_APT_CACHE}"
    $SUDO rm -f "${ARROW_APT_CACHE}/lock" "${ARROW_APT_CACHE}/partial/lock"
    local n
    n="$(find "${ARROW_APT_CACHE}" -maxdepth 1 -name '*.deb' | wc -l)"
    if [[ "${n}" -gt 0 ]]; then
      echo "Arrow APT cache warm (${n} debs, $(du -sh "${ARROW_APT_CACHE}" | awk '{print $1}')) at ${ARROW_APT_CACHE}"
    else
      echo "Arrow APT cache empty (cold download into ${ARROW_APT_CACHE})"
    fi
  }

  finish_apt_cache() {
    $SUDO rm -f "${ARROW_APT_CACHE}/lock" "${ARROW_APT_CACHE}/partial/lock"
    $SUDO chmod -R a+rX "${ARROW_APT_CACHE}"
    $SUDO chown -R "$(id -u):$(id -g)" "${ARROW_APT_CACHE}" || true
    echo "Arrow APT archives in ${ARROW_APT_CACHE} ($(find "${ARROW_APT_CACHE}" -maxdepth 1 -name '*.deb' | wc -l) debs, $(du -sh "${ARROW_APT_CACHE}" | awk '{print $1}'))"
  }

  # Every apt-get that fetches packages writes .debs here, including transitive deps.
  apt_get() {
    $SUDO apt-get \
      -o "Dir::Cache::Archives=${ARROW_APT_CACHE}" \
      -o "APT::Keep-Downloaded-Packages=true" \
      "$@"
  }

  # Download-only first so the cached directory holds the full closure, then install.
  apt_download_and_install() {
    apt_get install -y -d "$@"
    apt_get install -y "$@"
  }

  configure_apt_mirrors
  prepare_apt_cache

  apt_get update -qq
  apt_download_and_install --no-install-recommends "${ARROW_BUILD_PACKAGES[@]}"

  codename="$(lsb_release --codename --short)"
  deb="apache-arrow-apt-source-latest-${codename}.deb"
  if [[ -f "${ARROW_APT_CACHE}/${deb}" ]]; then
    echo "Using cached Apache apt source ${deb}"
  else
    wget -q "https://packages.apache.org/artifactory/arrow/ubuntu/${deb}" -O "${ARROW_APT_CACHE}/${deb}"
  fi
  apt_get install -y "${ARROW_APT_CACHE}/${deb}"
  apt_get update -qq
  apt_download_and_install "${ARROW_DEV_PACKAGES[@]}"

  installed="$(pkg-config --modversion arrow)"
  if [[ "${installed}" != "${ARROW_VERSION}" ]]; then
    echo "Pinned Arrow ${ARROW_VERSION} but pkg-config reports ${installed}" >&2
    exit 1
  fi
  echo "Arrow ${installed} with Flight SQL (pinned ${ARROW_APT_VERSION})"
  finish_apt_cache
elif [[ "$os" == "Darwin" ]]; then
  brew install apache-arrow aws-sdk-cpp openssl@4 cmake ninja
  echo "Arrow + aws-sdk-cpp via Homebrew (openssl@4; Flight SQL enabled in recent formulae)"
else
  echo "Install Apache Arrow C++ with ARROW_FLIGHT=ON ARROW_FLIGHT_SQL=ON" >&2
  exit 1
fi
