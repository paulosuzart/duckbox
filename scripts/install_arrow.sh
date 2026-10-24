#!/usr/bin/env bash
# Arrow C++ with Flight SQL. Linux: Apache APT. macOS: Homebrew.
# Pin Arrow 26.0.0 (the version CI installs today). DuckDB stays 2.0.0.
set -euo pipefail

ARROW_VERSION="${ARROW_VERSION:-26.0.0}"
ARROW_APT_VERSION="${ARROW_APT_VERSION:-${ARROW_VERSION}-1}"

ARROW_BUILD_PACKAGES=(
  ca-certificates lsb-release wget g++ cmake unzip curl zip tar
  pkg-config ninja-build git libssl-dev libcurl4-openssl-dev zlib1g-dev
)
ARROW_DEV_PACKAGES=(
  "libarrow-dev=${ARROW_APT_VERSION}"
  "libarrow-flight-dev=${ARROW_APT_VERSION}"
  "libarrow-flight-sql-dev=${ARROW_APT_VERSION}"
)

# SHA256 of the versioned apache-arrow-apt-source_${ARROW_APT_VERSION} package
# (keyring + sources). Update these pins together with ARROW_VERSION.
arrow_apt_source_sha256() {
  case "$1" in
    noble) echo "89ff33c409ef0e5f0ed7ba117fb1bd5db7c5cc937f46f0baae482a30acb4972d" ;;
    jammy) echo "382b9c75f18e5870f2d706c9790f81f550bcdad08817da2eb0951da15a8ebfc1" ;;
    *) return 1 ;;
  esac
}

os="$(uname -s)"
if [[ "$os" == "Linux" ]]; then
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    SUDO="sudo"
  else
    SUDO=""
  fi

  # GitHub-hosted runners use azure.archive.ubuntu.com. When that mirror
  # stalls at 15-100 kB/s (run 40016321532), cmake / libgrpc / protobuf take
  # 13-15 minutes. apt's mirror+file: picks a URI at random unless each line
  # has a TAB + priority:N (lower wins). Prefer archive/security at priority 1;
  # Azure is priority 9 and is used only when a preferred mirror errors.
  # Acquire::http::Timeout does not catch a slow-but-working transfer.
  # Local machines are left alone unless DUCKBOX_APT_MIRRORS=1.
  configure_apt_mirrors() {
    $SUDO tee /etc/apt/apt.conf.d/80-duckbox-acquire >/dev/null <<'EOF'
Acquire::Retries "5";
Acquire::http::Timeout "20";
Acquire::https::Timeout "20";
EOF

    $SUDO mkdir -p /etc/apt/mirrors
    local list
    list="$(mktemp)"
    {
      printf '%s\t%s\n' 'http://archive.ubuntu.com/ubuntu/' 'priority:1'
      printf '%s\t%s\n' 'http://security.ubuntu.com/ubuntu/' 'priority:1'
      printf '%s\t%s\n' 'http://azure.archive.ubuntu.com/ubuntu/' 'priority:9'
    } >"${list}"
    $SUDO cp "${list}" /etc/apt/mirrors/ubuntu.list
    # ubuntu-24.04 runners already read this mirror list.
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

  if [[ "${GITHUB_ACTIONS:-}" == "true" || "${DUCKBOX_APT_MIRRORS:-}" == "1" ]]; then
    configure_apt_mirrors
  fi

  $SUDO apt-get update -qq
  $SUDO apt-get install -y --no-install-recommends "${ARROW_BUILD_PACKAGES[@]}"

  codename="$(lsb_release --codename --short)"
  expected="$(arrow_apt_source_sha256 "${codename}")" || {
    echo "No pinned SHA256 for apache-arrow-apt-source on ${codename} (supported: noble, jammy). Update the pin together with ARROW_VERSION." >&2
    exit 1
  }
  url="https://packages.apache.org/artifactory/arrow/ubuntu/pool/${codename}/main/a/apache-arrow-apt-source/apache-arrow-apt-source_${ARROW_APT_VERSION}_all.deb"
  # apt-get install requires a .deb suffix; a bare mktemp path is "Unsupported file".
  tmp="$(mktemp --suffix=.deb)"
  trap 'rm -f "${tmp}"' EXIT
  wget -q "${url}" -O "${tmp}"
  got="$(sha256sum "${tmp}" | awk '{print $1}')"
  if [[ "${got}" != "${expected}" ]]; then
    echo "SHA256 mismatch for ${url}: got ${got} want ${expected}. Update the pin together with ARROW_VERSION." >&2
    exit 1
  fi
  # Readable by apt's _apt sandbox user so install is not "unsandboxed as root".
  chmod 644 "${tmp}"
  $SUDO apt-get install -y "${tmp}"
  $SUDO apt-get update -qq
  $SUDO apt-get install -y "${ARROW_DEV_PACKAGES[@]}"

  installed="$(pkg-config --modversion arrow)"
  if [[ "${installed}" != "${ARROW_VERSION}" ]]; then
    echo "Pinned Arrow ${ARROW_VERSION} but pkg-config reports ${installed}" >&2
    exit 1
  fi
  echo "Arrow ${installed} with Flight SQL (pinned ${ARROW_APT_VERSION})"
elif [[ "$os" == "Darwin" ]]; then
  brew install apache-arrow aws-sdk-cpp openssl@4 cmake ninja
  echo "Arrow + aws-sdk-cpp via Homebrew (openssl@4; Flight SQL enabled in recent formulae)"
else
  echo "Install Apache Arrow C++ with ARROW_FLIGHT=ON ARROW_FLIGHT_SQL=ON" >&2
  exit 1
fi
