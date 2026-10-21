#!/usr/bin/env bash
# Line coverage of server/src (duckbox_core). CI-reported number: gcovr. Target: >= 75%.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${COVERAGE_BUILD_DIR:-$ROOT/build-cov}"
export DUCKBOX_HANDLE_SECRET="${DUCKBOX_HANDLE_SECRET:-duckbox-dev-secret}"
export PATH="${HOME}/.local/bin:${PATH}"

cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Debug -DDUCKBOX_COVERAGE=ON -DCMAKE_CXX_COMPILER="${CXX:-g++}"
cmake --build "$BUILD" --parallel --target duckbox duckbox_unit_tests duckbox_guardrail_tests duckbox_integration_tests duckbox_schema_tests
export DUCKBOX_BIN="$BUILD/duckbox"
ctest --test-dir "$BUILD" --output-on-failure

python3 -m pip install --user -q 'gcovr>=7.2'

# Filter to server/src/*.cpp — this is the number CI reports (not a homemade gcov parser).
python3 -m gcovr --root "$ROOT" \
  --filter 'server/src/' \
  --exclude '\.deps/' \
  --exclude 'test/' \
  "$BUILD" \
  --txt \
  --print-summary \
  --fail-under-line 75

# plan_check.cpp is the last-line-of-defense; keep it well above the repo floor.
python3 -m gcovr --root "$ROOT" \
  --filter 'server/src/plan_check.cpp' \
  --exclude '\.deps/' \
  --exclude 'test/' \
  "$BUILD" \
  --txt \
  --print-summary \
  --fail-under-line 85
