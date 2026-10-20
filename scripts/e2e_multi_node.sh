#!/usr/bin/env bash
# Multi-node e2e: 3 daemons, RustFS leases, kill owner, query still served.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export ROOT
export PYTHONPATH="$ROOT/examples/python${PYTHONPATH:+:$PYTHONPATH}"
export DUCKBOX_HANDLE_SECRET="${DUCKBOX_HANDLE_SECRET:-duckbox-dev-secret}"
export DUCKBOX_PEER_SECRET="${DUCKBOX_PEER_SECRET:-duckbox-peer-dev}"
export DUCKBOX_S3_KEY="${DUCKBOX_S3_KEY:-rustfsadmin}"
export DUCKBOX_S3_SECRET="${DUCKBOX_S3_SECRET:-rustfsadmin}"
BIN="${DUCKBOX_BIN:-$ROOT/build/duckbox}"
PY="${DUCKBOX_PYTHON:-python3}"

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

"$PY" - <<'PY'
import os, boto3
from botocore.config import Config
from botocore.exceptions import ClientError
ep = os.environ.get("DUCKBOX_S3_ENDPOINT", "http://127.0.0.1:9000")
c = boto3.client(
    "s3",
    endpoint_url=ep,
    aws_access_key_id=os.environ["DUCKBOX_S3_KEY"],
    aws_secret_access_key=os.environ["DUCKBOX_S3_SECRET"],
    region_name="us-east-1",
    config=Config(s3={"addressing_style": "path"}),
)
try:
    c.create_bucket(Bucket="duckbox-control")
except ClientError as e:
    code = e.response.get("Error", {}).get("Code", "")
    if code not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
        raise
print("control bucket ready")
PY

"$BIN" serve --daemon "$ROOT/daemons/cluster-node-a.yaml" --no-metrics &
PID_A=$!
"$BIN" serve --daemon "$ROOT/daemons/cluster-node-b.yaml" --no-metrics &
PID_B=$!
"$BIN" serve --daemon "$ROOT/daemons/cluster-node-c.yaml" --no-metrics &
PID_C=$!
cleanup() {
	for p in ${PID_A:-} ${PID_B:-} ${PID_C:-}; do
		kill "$p" 2>/dev/null || true
	done
	wait 2>/dev/null || true
}
trap cleanup EXIT

wait_port 4747
wait_port 4748
wait_port 4749
wait_port 5747
wait_port 5748
wait_port 5749

"$BIN" sandbox create --url grpc://127.0.0.1:4747 \
	--spec "$ROOT/policies/memory/analyst.yaml" \
	--id cluster-analyst --key tenant_21:user_sergio

LIST="$("$BIN" sandbox list --url grpc://127.0.0.1:4748 --id-prefix cluster-analyst)"
echo "$LIST"
echo "$LIST" | grep -q '"owner":"node-a"'

"$PY" - <<'PY'
from duckbox_client import connect
db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4748", retries=5)
df = db.query("SELECT id, title FROM deals ORDER BY id")
assert len(df) >= 1, df
print("query via node-b ok", list(df["id"]))
db.close()
PY

kill "$PID_A"
wait "$PID_A" 2>/dev/null || true
PID_A=""

"$PY" - <<'PY'
import time
from duckbox_client import connect
deadline = time.time() + 20
last = None
while time.time() < deadline:
    try:
        db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4748", retries=1)
        df = db.query("SELECT id FROM deals ORDER BY id")
        assert len(df) >= 1, df
        print("failover query via node-b ok", list(df["id"]))
        db.close()
        break
    except Exception as e:  # noqa: BLE001
        last = e
        time.sleep(0.5)
else:
    raise SystemExit(f"query after kill did not succeed: {last}")
PY

LIST2="$("$BIN" sandbox list --url grpc://127.0.0.1:4749 --id-prefix cluster-analyst)"
echo "$LIST2"
echo "$LIST2" | grep -E -q '"owner":"node-(b|c)"'

"$BIN" node drain --url grpc://127.0.0.1:5748 --timeout 1000
"$PY" - <<'PY'
import time
from duckbox_client import connect
deadline = time.time() + 20
last = None
while time.time() < deadline:
    try:
        db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4749", retries=1)
        df = db.query("SELECT id FROM deals ORDER BY id")
        assert len(df) >= 1, df
        print("query after drain via node-c ok", list(df["id"]))
        db.close()
        break
    except Exception as e:  # noqa: BLE001
        last = e
        time.sleep(0.5)
else:
    raise SystemExit(f"query after drain did not succeed: {last}")
PY

echo "multi-node e2e ok"
