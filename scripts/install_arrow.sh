#!/usr/bin/env bash
# Arrow C++ with Flight SQL. Linux: Apache APT. macOS: Homebrew.
set -euo pipefail

os="$(uname -s)"
if [[ "$os" == "Linux" ]]; then
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    SUDO="sudo"
  else
    SUDO=""
  fi
  $SUDO apt-get update -qq
  $SUDO apt-get install -y --no-install-recommends ca-certificates lsb-release wget g++ cmake unzip curl zip tar \
    pkg-config ninja-build git libssl-dev libcurl4-openssl-dev zlib1g-dev
  codename="$(lsb_release --codename --short)"
  deb="apache-arrow-apt-source-latest-${codename}.deb"
  wget -q "https://packages.apache.org/artifactory/arrow/ubuntu/${deb}" -O "/tmp/${deb}"
  $SUDO apt-get install -y "/tmp/${deb}"
  $SUDO apt-get update -qq
  $SUDO apt-get install -y libarrow-dev libarrow-flight-dev libarrow-flight-sql-dev
  echo "Arrow $(pkg-config --modversion arrow) with Flight SQL"
elif [[ "$os" == "Darwin" ]]; then
  brew install apache-arrow openssl cmake
  echo "Arrow via Homebrew (Flight SQL enabled in recent formulae)"
else
  echo "Install Apache Arrow C++ with ARROW_FLIGHT=ON ARROW_FLIGHT_SQL=ON" >&2
  exit 1
fi
