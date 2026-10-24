#!/usr/bin/env bash
# Warm a DuckLake sandbox, stop the catalog Postgres, and check that the
# client sees only the generic catalog-unavailable message (no DSN / password)
# while operator logs keep a redacted detail.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT/examples/python${PYTHONPATH:+:$PYTHONPATH}"
BIN="${DUCKBOX_BIN:-$ROOT/build/duckbox}"
PY="${DUCKBOX_PYTHON:-python3}"
URL="${DUCKBOX_URL:-grpc://127.0.0.1:4747}"
SANDBOX="${DUCKBOX_SANDBOX:-acme-analyst}"
KEY="${DUCKBOX_KEY:-tenant_21:user_sergio}"
PW="${DUCKBOX_CATALOG_PASSWORD:-duckbox}"
BARE_DSN="dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=${PW}"
LOG="${DUCKBOX_SERVE_LOG:-/tmp/duckbox-serve.log}"

if [[ ! -x "$BIN" ]]; then
	echo "missing $BIN" >&2
	exit 1
fi

query_err() {
	local sql="$1"
	"$PY" - "$URL" "$SANDBOX" "$KEY" "$sql" <<'PY'
import sys
from duckbox_client import connect, format_error
url, sandbox, key, sql = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
try:
    with connect(url=url, sandbox=sandbox, key=key) as db:
        db.query(sql)
    print("UNEXPECTED_OK")
except Exception as exc:  # noqa: BLE001
    print(format_error(exc))
PY
}

echo "e2e catalog-down: warm $SANDBOX"
"$PY" - "$URL" "$SANDBOX" "$KEY" <<'PY'
import sys
from duckbox_client import connect
url, sandbox, key = sys.argv[1], sys.argv[2], sys.argv[3]
with connect(url=url, sandbox=sandbox, key=key) as db:
    df = db.query("SELECT count(*) FROM deals")
    print("warm rows", int(df.iloc[0, 0]))
PY

if docker compose ps postgres >/dev/null 2>&1; then
	echo "e2e catalog-down: docker compose stop postgres"
	docker compose stop postgres
elif command -v pg_ctl >/dev/null 2>&1 && [[ -n "${PGDATA:-}" ]]; then
	echo "e2e catalog-down: pg_ctl stop"
	pg_ctl stop -D "$PGDATA" -m fast
else
	echo "e2e catalog-down: no postgres service or pg_ctl+PGDATA" >&2
	exit 1
fi

sleep 1
: >"${LOG}.after"
if [[ -f "$LOG" ]]; then
	cp "$LOG" "${LOG}.before"
fi

err="$(query_err "SELECT count(*) FROM deals")"
at_err="$(query_err "SELECT count(*) FROM deals AT (VERSION => 2)")"

assert_clean() {
	local label="$1"
	local msg="$2"
	if [[ "$msg" == "UNEXPECTED_OK" ]]; then
		echo "FAIL: $label succeeded after catalog stop" >&2
		exit 1
	fi
	if [[ "$msg" != *"lake catalog unavailable; see operator logs"* ]]; then
		echo "FAIL: $label expected generic catalog message, got: $msg" >&2
		exit 1
	fi
	if [[ "$msg" == *"$PW"* || "$msg" == *"$BARE_DSN"* || "$msg" == *"password="* ]]; then
		echo "FAIL: $label leaked password or DSN: $msg" >&2
		exit 1
	fi
}

assert_clean "SELECT count(*)" "$err"
assert_clean "AT VERSION => 2" "$at_err"

if [[ -f "$LOG" ]]; then
	if [[ -f "${LOG}.before" ]]; then
		comm -13 <(sort "${LOG}.before") <(sort "$LOG") >"${LOG}.after" || true
		# Fallback: tail new bytes
		if [[ ! -s "${LOG}.after" ]]; then
			tail -n 50 "$LOG" >"${LOG}.after"
		fi
	else
		tail -n 50 "$LOG" >"${LOG}.after"
	fi
	if grep -F "$PW" "${LOG}.after" | grep -v '<redacted>' >/dev/null; then
		# password string may appear in unrelated lines; require password= form
		if grep -F "password=${PW}" "${LOG}.after"; then
			echo "FAIL: operator log contains password=${PW}" >&2
			exit 1
		fi
	fi
	if grep -F "password=${PW}" "$LOG"; then
		echo "FAIL: serve log contains password=${PW}" >&2
		exit 1
	fi
	if ! grep -E 'lake catalog unavailable|Unable to connect to Postgres|Failed to query most recent snapshot' "$LOG" >/dev/null; then
		echo "FAIL: operator log missing catalog-down detail" >&2
		tail -n 80 "$LOG" >&2
		exit 1
	fi
	if grep -E 'flight: lake catalog unavailable:|sandbox: lake catalog unavailable:' "$LOG" >/dev/null; then
		if grep -E 'flight: lake catalog unavailable:.*password=' "$LOG" | grep -v '<redacted>'; then
			echo "FAIL: flight catalog log still has password=" >&2
			exit 1
		fi
	fi
	echo "e2e catalog-down: operator log is redacted"
else
	echo "WARN: no serve log at $LOG (client assertions still passed)"
fi

echo "e2e catalog-down: ok"
