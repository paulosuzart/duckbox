#!/usr/bin/env bash
# Fetch a pinned goose compiler release into .deps. Used only when CMake is
# configured with -DDUCKBOX_EXPERIMENTAL_GOOSE=ON. Not part of the default build.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPS="${DUCKBOX_DEPS:-$ROOT/.deps}"
VERSION="${DUCKBOX_GOOSE_VERSION:-v2026.3}"
DEST="${DEPS}/goose-${VERSION}"

os="$(uname -s)"
arch="$(uname -m)"
case "${os}-${arch}" in
  Linux-x86_64)
    asset="goose-${VERSION}-linux-x64.tar.gz"
    sha="06ac30284338269d3996d457412bf4f2b47c1f9a5601de65b6317187fe78d5c9"
    ;;
  Darwin-arm64)
    asset="goose-${VERSION}-macos-arm64.tar.gz"
    sha="2ffaaf46b3edde27aed03fcd9ebe73e9b6639cac30d8a6915f7dc00795b7aedf"
    ;;
  Darwin-x86_64)
    asset="goose-${VERSION}-macos-x64.tar.gz"
    sha="3c7f2895f3dcab5f39ee52808446b00688b975620d1d27e23694dd22b82abfe7"
    ;;
  *)
    echo "fetch_goose.sh: no prebuilt goose ${VERSION} for ${os} ${arch}" >&2
    exit 1
    ;;
esac

if [[ -x "${DEST}/goose" ]]; then
  echo "goose ${VERSION} already at ${DEST}"
  exit 0
fi

url="https://github.com/aardappel/goose/releases/download/${VERSION}/${asset}"
mkdir -p "${DEPS}"
tmp="${DEPS}/${asset}"
echo "Fetching ${url}"
curl -fsSL -o "${tmp}" "${url}"
if command -v sha256sum >/dev/null 2>&1; then
  got="$(sha256sum "${tmp}" | awk '{print $1}')"
else
  got="$(shasum -a 256 "${tmp}" | awk '{print $1}')"
fi
if [[ "${got}" != "${sha}" ]]; then
  echo "fetch_goose.sh: sha256 mismatch for ${asset}" >&2
  echo "  expected ${sha}" >&2
  echo "  got      ${got}" >&2
  rm -f "${tmp}"
  exit 1
fi
mkdir -p "${DEST}"
tar -xzf "${tmp}" -C "${DEST}" --strip-components=1
rm -f "${tmp}"
if [[ ! -x "${DEST}/goose" ]]; then
  found="$(find "${DEST}" -maxdepth 2 -type f -name goose | head -n 1)"
  if [[ -n "${found}" ]]; then
    chmod +x "${found}"
    ln -sfn "${found}" "${DEST}/goose"
  fi
fi
if [[ ! -x "${DEST}/goose" ]]; then
  echo "fetch_goose.sh: unpacked archive has no goose binary" >&2
  exit 1
fi
echo "goose ${VERSION} ready at ${DEST}/goose"
