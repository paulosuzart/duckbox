#!/usr/bin/env bash
# Run duckbox_schema_tests under lldb --batch so a SIGSEGV prints a backtrace.
# Usage: ci_macos_schema_loop.sh [repeats] [binary] [logdir]
set -u
repeats="${1:-1}"
bin="${2:-./build/duckbox_schema_tests}"
outdir="${3:-schema-lldb-logs}"
mkdir -p "$outdir"

if [[ ! -x "$bin" ]]; then
    echo "missing schema test binary: $bin" >&2
    exit 2
fi

lldb_bin="lldb"
if ! command -v lldb >/dev/null 2>&1; then
    lldb_bin="xcrun lldb"
fi

ok=0
crash=0
fail=0

for i in $(seq 1 "$repeats"); do
    log="$outdir/run-$i.log"
    echo "=== schema lldb run $i/$repeats ==="
    set +e
    $lldb_bin --batch \
        -o "settings set target.process.stop-on-exec false" \
        -o run \
        -o bt \
        -k bt \
        -k quit \
        -- "$bin" >"$log" 2>&1
    ec=$?
    set -e
    if grep -Eqi 'SIGSEGV|EXC_BAD_ACCESS|stop reason =|Process [0-9]+ crashed|thread #[0-9]+ crashed' "$log"; then
        echo "CRASH run=$i exit=$ec"
        crash=$((crash + 1))
        tail -n 120 "$log"
    elif grep -q 'schema passed=' "$log" && grep -q 'failed=0' "$log"; then
        echo "OK run=$i"
        ok=$((ok + 1))
    else
        echo "FAIL run=$i exit=$ec"
        fail=$((fail + 1))
        tail -n 60 "$log"
    fi
done

summary="SCHEMA_LOOP_SUMMARY repeats=$repeats ok=$ok crash=$crash fail=$fail"
echo "$summary"
echo "$summary" >"$outdir/summary.txt"

if [[ "$repeats" -eq 1 ]]; then
    [[ "$ok" -eq 1 ]]
    exit $?
fi
exit 0
