#!/usr/bin/env bash
# 2-node cluster: SIGINT and SIGTERM must exit 0 and deregister (no SIGKILL).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export ROOT
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

assert_exits() {
	local pid="$1"
	local sig="$2"
	local name="$3"
	kill -"$sig" "$pid"
	local i
	for i in $(seq 1 40); do
		if ! kill -0 "$pid" 2>/dev/null; then
			local rc=0
			wait "$pid" || rc=$?
			if [[ "$rc" -ne 0 ]]; then
				echo "$name exited $rc after $sig (want 0)" >&2
				return 1
			fi
			echo "$name exited 0 after $sig"
			return 0
		fi
		sleep 0.25
	done
	echo "$name still running 10s after $sig; would need SIGKILL" >&2
	kill -9 "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
	return 1
}

node_gone() {
	local node_id="$1"
	"$PY" - <<PY
import os, sys, boto3
from botocore.config import Config
from botocore.exceptions import ClientError
c = boto3.client(
    "s3",
    endpoint_url=os.environ.get("DUCKBOX_S3_ENDPOINT", "http://127.0.0.1:9000"),
    aws_access_key_id=os.environ["DUCKBOX_S3_KEY"],
    aws_secret_access_key=os.environ["DUCKBOX_S3_SECRET"],
    region_name="us-east-1",
    config=Config(s3={"addressing_style": "path"}),
)
try:
    c.head_object(Bucket="duckbox-control", Key="leases/nodes/${node_id}.json")
    print("node record still present: ${node_id}", file=sys.stderr)
    sys.exit(1)
except ClientError as e:
    code = e.response.get("Error", {}).get("Code", "")
    if code in ("404", "NoSuchKey", "NotFound"):
        print("deregistered ${node_id}")
        sys.exit(0)
    raise
PY
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
cleanup() {
	local p
	for p in ${PID_A:-} ${PID_B:-}; do
		kill -9 "$p" 2>/dev/null || true
		wait "$p" 2>/dev/null || true
	done
}
trap cleanup EXIT

wait_port 4747
wait_port 5747
wait_port 4748
wait_port 5748

assert_exits "$PID_A" INT node-a
PID_A=""
node_gone node-a
assert_exits "$PID_B" TERM node-b
PID_B=""
node_gone node-b

echo "signal shutdown e2e ok"
trap - EXIT
