#!/usr/bin/env bash
# Line coverage of server/src (duckbox_core). CI-reported number: gcovr. Target: >= 75%.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${COVERAGE_BUILD_DIR:-$ROOT/build-cov}"
export DUCKBOX_HANDLE_SECRET="${DUCKBOX_HANDLE_SECRET:-duckbox-dev-secret}"
export PATH="${HOME}/.local/bin:${PATH}"

cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Debug -DDUCKBOX_COVERAGE=ON -DCMAKE_CXX_COMPILER="${CXX:-g++}"
# Unbounded --parallel OOMs/cancels the coverage runner while compiling the
# instrumented integration suite. Two jobs is enough and stays under RAM.
cmake --build "$BUILD" --parallel "${COVERAGE_JOBS:-2}" --target duckbox duckbox_unit_tests duckbox_guardrail_tests duckbox_integration_tests duckbox_schema_tests duckbox_s3_credentials_tests duckbox_s3_secret_guardrail_tests duckbox_s3_sts_tests
export DUCKBOX_BIN="$BUILD/duckbox"
if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
  python3 -m venv "$ROOT/.venv"
  "$ROOT/.venv/bin/pip" install -q -r "$ROOT/examples/python/requirements.txt"
  export DUCKBOX_PYTHON="$ROOT/.venv/bin/python"
fi
ctest --test-dir "$BUILD" --output-on-failure

python3 -m pip install --user -q 'gcovr>=7.2'

# Filter to server/src/*.cpp — this is the number CI reports (not a homemade gcov parser).
python3 -m gcovr --root "$ROOT" \
  --filter 'server/src/' \
  --exclude '\.deps/' \
  --exclude 'test/' \
  --gcov-ignore-errors=no_working_dir_found \
  --gcov-ignore-parse-errors=negative_hits.warn_once_per_file \
  "$BUILD" \
  --txt \
  --print-summary \
  --fail-under-line 75
