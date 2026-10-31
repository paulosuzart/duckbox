#!/usr/bin/env bash
# Fetch the pinned ADBC Flight SQL driver library into examples/c3-adbc/.deps.
# Isolated from the default duckbox build (does not touch repo-root .deps).
# The C3 bindings are in src/adbc.c3, so no ADBC headers are needed.
# This script only downloads and extracts; it never removes files.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPS="${DBX_C3_ADBC_DEPS:-$ROOT/.deps}"
FLIGHTSQL_VERSION="1.12.0"
PYPI="https://files.pythonhosted.org/packages"
DEST="${DEPS}/adbc/lib"

os="$(uname -s)"
arch="$(uname -m)"
case "${os}/${arch}" in
  Darwin/arm64)
    path="61/36/49267a4fc8c07c066dd8c36b9c3d27265a4dc0fc478cb5acb7bd6a551d80"
    file="adbc_driver_flightsql-${FLIGHTSQL_VERSION}-py3-none-macosx_11_0_arm64.whl"
    sha="fb37efefceb7ceca64840c76c55e6280f3811b54dca305ec1781f9cc1a6da21e"
    lib="libadbc_driver_flightsql.dylib"
    ;;
  Darwin/x86_64)
    path="7a/a4/5ad52abf0c4830585b86d68cff8ce07779cdee9b8cf390dff0ee21a29fa7"
    file="adbc_driver_flightsql-${FLIGHTSQL_VERSION}-py3-none-macosx_10_15_x86_64.whl"
    sha="c2c7209407c180d9d0dd94846203f184ab91e116782585bf29cb968c2686ba75"
    lib="libadbc_driver_flightsql.dylib"
    ;;
  Linux/x86_64)
    path="2b/5b/f8566aa6d05eb40225f5874f8f5f5e8b8b4a4ce866d817a5ff352f326302"
    file="adbc_driver_flightsql-${FLIGHTSQL_VERSION}-py3-none-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl"
    sha="69742e4f8fcc254490aa7f8e254a3b704c24bde9d5d827a0926ea90a6b4c3a6d"
    lib="libadbc_driver_flightsql.so"
    ;;
  Linux/aarch64)
    path="57/45/6468fb425f3c0ae868c1ca9ab8e15cba76b59e941edd7e80e892e5476728"
    file="adbc_driver_flightsql-${FLIGHTSQL_VERSION}-py3-none-manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64.whl"
    sha="9adfb5e46abc77347476d09ee76dfc835fef2b4dcb0c76d08d6d35aa3a4cce17"
    lib="libadbc_driver_flightsql.so"
    ;;
  *)
    echo "fetch_deps.sh: no pinned Flight SQL wheel for ${os}/${arch}." >&2
    echo "Copy libadbc_driver_flightsql.{so,dylib} into ${DEST}" >&2
    exit 1
    ;;
esac

if [[ -f "${DEST}/${lib}" ]]; then
  echo "Flight SQL driver already at ${DEST}/${lib}"
  exit 0
fi

mkdir -p "${DEST}"
whl="${DEPS}/${file}"
if [[ ! -f "${whl}" ]]; then
  echo "Fetching ${PYPI}/${path}/${file}"
  curl -fsSL -o "${whl}" "${PYPI}/${path}/${file}"
fi
if command -v sha256sum >/dev/null 2>&1; then
  got="$(sha256sum "${whl}" | awk '{print $1}')"
else
  got="$(shasum -a 256 "${whl}" | awk '{print $1}')"
fi
if [[ "${got}" != "${sha}" ]]; then
  echo "fetch_deps.sh: sha256 mismatch for ${whl}" >&2
  echo "  expected ${sha}" >&2
  echo "  got      ${got}" >&2
  echo "Remove that file and run again." >&2
  exit 1
fi

# Extract only the driver library from the wheel (a zip).
python3 - "${whl}" "${DEST}/${lib}" <<'PY'
import sys, zipfile
whl, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(whl) as z:
    names = [n for n in z.namelist() if n.rsplit("/", 1)[-1].startswith("libadbc_driver_flightsql")]
    if not names:
        sys.exit("wheel has no libadbc_driver_flightsql library")
    with z.open(names[0]) as src, open(out, "wb") as dst:
        dst.write(src.read())
PY
if [[ "${os}" == "Linux" && ! -e "${DEST}/${lib}.112" ]]; then
  # The wheel's SONAME is libadbc_driver_flightsql.so.112.
  ln -s "${lib}" "${DEST}/${lib}.112"
fi
echo "Flight SQL driver ready at ${DEST}/${lib}"
