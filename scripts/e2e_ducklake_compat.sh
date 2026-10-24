#!/usr/bin/env bash
# DuckLake compatibility e2e: read a pre-existing Postgres+S3 lake with duckbox 2.0.
# Prefer creating the lake with DuckDB 1.5.6 + its ducklake extension (the last
# 1.5.x engine). Local runs may fall back to 2.0 and print why. CI sets
# DUCKBOX_REQUIRE_LAKE_ENGINE=1.5.6 so a failed 1.5.6 seed exits instead of
# falling back. duckbox ATTACH never sets AUTOMATIC_MIGRATION — either the
# read works as-is or this script prints the exact migration ATTACH.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export ROOT
export PYTHONPATH="$ROOT/examples/python${PYTHONPATH:+:$PYTHONPATH}"
export DUCKBOX_HANDLE_SECRET="${DUCKBOX_HANDLE_SECRET:-duckbox-dev-secret}"
export DUCKBOX_S3_KEY="${DUCKBOX_S3_KEY:-rustfsadmin}"
export DUCKBOX_S3_SECRET="${DUCKBOX_S3_SECRET:-rustfsadmin}"
export DUCKBOX_S3_ENDPOINT="${DUCKBOX_S3_ENDPOINT:-http://127.0.0.1:9000}"
export DUCKBOX_LAKE_CATALOG="${DUCKBOX_LAKE_CATALOG:-ducklake:postgres:dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox}"
BIN="${DUCKBOX_BIN:-$ROOT/build/duckbox}"
PY="${DUCKBOX_PYTHON:-python3}"
LISTEN="${DUCKBOX_COMPAT_LISTEN:-127.0.0.1:4757}"
METRICS="${DUCKBOX_COMPAT_METRICS:-127.0.0.1:9487}"
PORT="${LISTEN##*:}"
LEGACY_VENV="${DUCKBOX_LEGACY_VENV:-$ROOT/.venv-ducklake-1.5.6}"
RESULT_FILE="${DUCKBOX_COMPAT_RESULT:-$ROOT/ducklake-compat-result.txt}"

if [[ ! -x "$BIN" ]]; then
	echo "missing $BIN" >&2
	exit 1
fi

wait_port() {
	local port="$1"
	local i
	for i in $(seq 1 40); do
		if "$PY" -c "import socket; s=socket.create_connection(('127.0.0.1',$port),1)" 2>/dev/null; then
			return 0
		fi
		sleep 0.25
	done
	echo "timeout waiting for 127.0.0.1:$port" >&2
	return 1
}

CREATED_WITH=""
CREATED_WHY=""

seed_with() {
	local python_bin="$1"
	local label="$2"
	echo "seeding DuckLake with $label ($python_bin)"
	DUCKBOX_S3_KEY="$DUCKBOX_S3_KEY" DUCKBOX_S3_SECRET="$DUCKBOX_S3_SECRET" \
		"$python_bin" "$ROOT/scripts/seed_ducklake.py" \
		--s3-endpoint "$DUCKBOX_S3_ENDPOINT" \
		--s3-key "$DUCKBOX_S3_KEY" \
		--s3-secret "$DUCKBOX_S3_SECRET"
}

if [[ -n "${DUCKBOX_REQUIRE_LAKE_ENGINE:-}" && "${DUCKBOX_REQUIRE_LAKE_ENGINE}" != "1.5.6" ]]; then
	echo "DUCKBOX_REQUIRE_LAKE_ENGINE must be exactly 1.5.6 (got '${DUCKBOX_REQUIRE_LAKE_ENGINE}')" >&2
	exit 1
fi

require_legacy_engine() {
	[[ "${DUCKBOX_REQUIRE_LAKE_ENGINE:-}" == "1.5.6" ]]
}

fallback_or_die() {
	local why="$1"
	if require_legacy_engine; then
		echo "DUCKBOX_REQUIRE_LAKE_ENGINE=1.5.6: refusing 2.0 fallback ($why)" >&2
		exit 1
	fi
	CREATED_WITH="2.0.0"
	CREATED_WHY="$why"
	seed_with "$PY" "DuckDB 2.0 (fallback)"
}

# Ideal: DuckDB 1.5.6 CLI/python + matching ducklake extension, then duckbox 2.0 reads.
if [[ "${DUCKBOX_FORCE_LAKE_ENGINE:-}" == "2.0" ]]; then
	if require_legacy_engine; then
		echo "DUCKBOX_REQUIRE_LAKE_ENGINE=1.5.6 conflicts with DUCKBOX_FORCE_LAKE_ENGINE=2.0" >&2
		exit 1
	fi
	CREATED_WITH="2.0.0"
	CREATED_WHY="DUCKBOX_FORCE_LAKE_ENGINE=2.0"
	seed_with "$PY" "DuckDB 2.0 (forced)"
elif "$PY" -c "import duckdb; raise SystemExit(0 if duckdb.__version__.startswith('1.5.6') else 1)" 2>/dev/null; then
	CREATED_WITH="1.5.6"
	CREATED_WHY="active DUCKBOX_PYTHON is already duckdb 1.5.6"
	seed_with "$PY" "DuckDB 1.5.6 (current interpreter)"
else
	if [[ ! -x "$LEGACY_VENV/bin/python" ]]; then
		echo "creating $LEGACY_VENV with duckdb==1.5.6"
		if python3 -m venv "$LEGACY_VENV" &&
			"$LEGACY_VENV/bin/pip" install -q 'duckdb==1.5.6' boto3 pytz 'urllib3>=2'; then
			true
		else
			fallback_or_die "could not create a duckdb==1.5.6 venv (pip/venv failed)"
		fi
	fi
	if [[ -z "$CREATED_WITH" ]]; then
		if "$LEGACY_VENV/bin/python" -c "import duckdb; assert duckdb.__version__.startswith('1.5.6')" &&
			seed_with "$LEGACY_VENV/bin/python" "DuckDB 1.5.6 (legacy venv)"; then
			CREATED_WITH="1.5.6"
			CREATED_WHY="seeded with pip duckdb==1.5.6 and its ducklake extension"
		else
			fallback_or_die "duckdb==1.5.6 installed but INSTALL/LOAD ducklake or seed failed; 1.5.6 extensions are not usable in this environment"
		fi
	fi
fi

echo "lake created with DuckDB $CREATED_WITH ($CREATED_WHY)"

DAEMON_TMP="$(mktemp)"
sed -e "s/127.0.0.1:4747/${LISTEN}/" -e "s/127.0.0.1:9477/${METRICS}/" \
	"$ROOT/daemons/ducklake.yaml" >"$DAEMON_TMP"

"$BIN" serve --daemon "$DAEMON_TMP" --listen "$LISTEN" --metrics "$METRICS" &
PID=$!
cleanup() {
	kill "$PID" 2>/dev/null || true
	sleep 1
	if kill -0 "$PID" 2>/dev/null; then
		kill -9 "$PID" 2>/dev/null || true
	fi
	rm -f "$DAEMON_TMP"
}
trap cleanup EXIT

wait_port "$PORT"

"$BIN" sandbox create --url "grpc://${LISTEN}" \
	--spec "$ROOT/policies/ducklake/analyst.yaml" \
	--id compat-analyst --key tenant_21:user_sergio
"$BIN" sandbox create --url "grpc://${LISTEN}" \
	--spec "$ROOT/policies/ducklake/analyst.yaml" \
	--id compat-kim --key tenant_22:user_kim

MIGRATION="none"
QUERY_OUT="$("$PY" - <<PY
import os, sys
os.environ.pop("DUCKBOX_SANDBOX", None)
sys.path.insert(0, os.environ["ROOT"] + "/examples/python")
from duckbox_client import connect, format_error

url = "grpc://${LISTEN}"
sql = "SELECT id, title, amount FROM deals ORDER BY id"
cross = "SELECT id, title FROM deals WHERE tenant_id = 22 ORDER BY id"

try:
    with connect(url=url, sandbox="compat-analyst", key="tenant_21:user_sergio") as a, \\
         connect(url=url, sandbox="compat-kim", key="tenant_22:user_kim") as b:
        deals_a = a.query(sql)
        deals_b = b.query(sql)
        ids_a = [int(v) for v in deals_a["id"].tolist()]
        ids_b = [int(v) for v in deals_b["id"].tolist()]
        print("compat-analyst ids:", ids_a)
        print("compat-kim ids:", ids_b)
        if ids_a != [1] or sorted(ids_b) != [3, 4] or set(ids_a) & set(ids_b):
            print("FAIL: tenant isolation on lake tables", file=sys.stderr)
            sys.exit(2)
        if "bravo" in deals_a.to_string() or "alpha deal" in deals_b.to_string():
            print("FAIL: cross-tenant title leaked", file=sys.stderr)
            sys.exit(2)
        cross_a = a.query(cross)
        cross_ids = [int(v) for v in cross_a["id"].tolist()]
        print("compat-analyst WHERE tenant_id=22 ids:", cross_ids)
        if cross_ids:
            print("FAIL: rewriter allowed a cross-tenant read", file=sys.stderr)
            sys.exit(2)
        print("tenant isolation ok (rewriter-only; cross-tenant WHERE is empty)")
except Exception as exc:
    msg = format_error(exc)
    print(msg, file=sys.stderr)
    low = msg.lower()
    if "automatic_migration" in low or "catalog version" in low or "ducklake catalog" in low:
        print("MIGRATION_REQUIRED", file=sys.stderr)
        sys.exit(3)
    raise
PY
)" || status=$?
status="${status:-0}"

if [[ "$status" -eq 3 ]]; then
	MIGRATION="required"
	echo "duckbox 2.0 could not attach the existing lake without migration."
	echo "Exact ATTACH (operator-run, not duckbox):"
	echo "  ATTACH 'ducklake:postgres:…' AS lake (DATA_PATH 's3://duckbox-lake/data/', AUTOMATIC_MIGRATION true);"
	echo "duckbox itself does not pass AUTOMATIC_MIGRATION (see BuildDuckLakeAttachSql)."
	echo "$QUERY_OUT"
	exit 1
fi
if [[ "$status" -ne 0 ]]; then
	echo "$QUERY_OUT"
	exit "$status"
fi

echo "$QUERY_OUT"

{
	echo "created_with=${CREATED_WITH}"
	echo "created_why=${CREATED_WHY}"
	echo "migration=${MIGRATION}"
	echo "attach=DATA_PATH+READ_ONLY (no AUTOMATIC_MIGRATION, no DUCKLAKE_VERSION, no STORAGE_VERSION)"
	echo "tenant_isolation=rewriter-only"
} | tee "$RESULT_FILE"

echo "DuckLake compatibility: created with DuckDB ${CREATED_WITH}; migration=${MIGRATION}"
