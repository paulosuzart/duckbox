#!/usr/bin/env bash
# Line coverage of server/ (duckbox_core). Target: >= 75%.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${COVERAGE_BUILD_DIR:-$ROOT/build-cov}"
export DUCKBOX_HANDLE_SECRET="${DUCKBOX_HANDLE_SECRET:-duckbox-dev-secret}"

cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Debug -DDUCKBOX_COVERAGE=ON -DCMAKE_CXX_COMPILER="${CXX:-g++}"
cmake --build "$BUILD" --parallel --target duckbox_unit_tests duckbox_guardrail_tests duckbox_integration_tests
ctest --test-dir "$BUILD" --output-on-failure

python3 - "$BUILD" "$ROOT" <<'PY'
import os, sys, glob, subprocess, pathlib

build, root = sys.argv[1], sys.argv[2]
gcda = glob.glob(os.path.join(build, "**", "duckbox_core.dir", "server", "src", "*.gcda"), recursive=True)
if not gcda:
    sys.exit("no .gcda files under duckbox_core.dir/server/src")

# gcov writes .gcov next to cwd; keep a temp dir
out = os.path.join(build, "gcov-out")
os.makedirs(out, exist_ok=True)
objdir = os.path.dirname(gcda[0])
cmd = ["gcov", "-p", "-o", objdir] + sorted({os.path.splitext(p)[0] + ".gcno" for p in gcda})
subprocess.check_call(cmd, cwd=out, stdout=subprocess.DEVNULL)

executed = 0
instrumented = 0
per_file = []
for gcov in glob.glob(os.path.join(out, "*.gcov")):
    name = os.path.basename(gcov)
    decoded = name.replace("#", "/")
    if "/server/src/" not in decoded or not decoded.endswith(".cpp.gcov"):
        continue
    lines_ok = 0
    lines_all = 0
    with open(gcov) as f:
        for line in f:
            if ":" not in line:
                continue
            count = line.split(":", 1)[0].strip()
            if count in ("-", "====="):
                continue
            lines_all += 1
            if count.startswith("#####"):
                continue
            try:
                int(count.rstrip("*"))
                lines_ok += 1
            except ValueError:
                pass
    if lines_all == 0:
        continue
    src = "server/src/" + os.path.basename(decoded[: -len(".gcov")])
    executed += lines_ok
    instrumented += lines_all
    per_file.append((100.0 * lines_ok / lines_all, src, lines_ok, lines_all))

if instrumented == 0:
    sys.exit("gcov produced no instrumented lines for server/src")
pct = 100.0 * executed / instrumented
print(f"server/ line coverage: {executed}/{instrumented} = {pct:.1f}%")
per_file.sort()
for p, src, ok, all_ in per_file[:8]:
    print(f"  {p:5.1f}%  {src} ({ok}/{all_})")
if pct + 1e-9 < 75.0:
    sys.exit(f"coverage {pct:.1f}% is below 75%")
print("coverage target met (>= 75%)")
PY
