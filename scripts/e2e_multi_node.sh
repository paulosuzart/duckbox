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
	local p
	for p in ${PID_A:-} ${PID_B:-} ${PID_C:-}; do
		kill "$p" 2>/dev/null || true
	done
	sleep 1
	for p in ${PID_A:-} ${PID_B:-} ${PID_C:-}; do
		if kill -0 "$p" 2>/dev/null; then
			kill -9 "$p" 2>/dev/null || true
		fi
	done
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

"$PY" - <<'PY'
from duckbox_client import connect
db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4747", retries=5)
df = db.query("SELECT id, title FROM deals ORDER BY id")
assert len(df) >= 1, df
print("warmup query via node-a ok", list(df["id"]))
db.close()
PY

LIST="$("$BIN" sandbox list --url grpc://127.0.0.1:4748 --id-prefix cluster-analyst)"
echo "$LIST"
echo "$LIST" | grep -q '"id":"cluster-analyst"'
echo "$LIST" | grep -q '"owner":"node-a"'

"$PY" - <<'PY'
from duckbox_client import connect
db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4748", retries=5)
df = db.query("SELECT id, title FROM deals ORDER BY id")
assert len(df) >= 1, df
print("query via non-owner node-b ok", list(df["id"]))
db.close()
PY

# Crash the owner (SIGKILL). SIGTERM can wait on the internal Serve thread.
kill -9 "$PID_A" 2>/dev/null || true
sleep 0.5
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

"$BIN" node drain --url grpc://127.0.0.1:5748 --timeout 1000 --peer-secret env:DUCKBOX_PEER_SECRET
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

# Restart the same node_id after SIGKILL (A was killed above).
"$BIN" serve --daemon "$ROOT/daemons/cluster-node-a.yaml" --no-metrics &
PID_A=$!
wait_port 4747
wait_port 5747
"$PY" - <<'PY'
from duckbox_client import connect
db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4747", retries=8)
df = db.query("SELECT id FROM deals ORDER BY id")
assert len(df) >= 1, df
print("restart same node_id after SIGKILL ok", list(df["id"]))
db.close()
PY

# SIGTERM should drain + deregister (must exit 0; no SIGKILL).
term_t0=$(date +%s.%N)
kill -TERM "$PID_A"
term_ok=0
for _ in $(seq 1 40); do
	if ! kill -0 "$PID_A" 2>/dev/null; then
		rc=0
		wait "$PID_A" || rc=$?
		if [[ "$rc" -ne 0 ]]; then
			echo "node-a exited $rc after SIGTERM (want 0)" >&2
			exit 1
		fi
		term_ok=1
		break
	fi
	sleep 0.25
done
if [[ "$term_ok" -ne 1 ]]; then
	echo "node-a did not exit after SIGTERM" >&2
	kill -9 "$PID_A" 2>/dev/null || true
	wait "$PID_A" 2>/dev/null || true
	exit 1
fi
term_t1=$(date +%s.%N)
python3 - <<PY
t0=float("$term_t0"); t1=float("$term_t1")
print(f"sigterm_idle_exit_s={t1-t0:.3f}")
if t1-t0 > 8:
    raise SystemExit(f"SIGTERM took too long: {t1-t0}")
PY
PID_A=""
"$BIN" serve --daemon "$ROOT/daemons/cluster-node-a.yaml" --no-metrics &
PID_A=$!
wait_port 4747
wait_port 5747
"$PY" - <<'PY'
from duckbox_client import connect
db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4747", retries=8)
df = db.query("SELECT id FROM deals ORDER BY id")
assert len(df) >= 1, df
print("restart same node_id after SIGTERM ok", list(df["id"]))
db.close()
PY

# Flight SQL CommandStatementQuery without pyarrow.flight.sql (not a
# package on the CI pyarrow build). Same encoding as test/schema/flight_metadata_pyarrow.py.
py_flight_sql() {
	cat <<'PY'
import pyarrow.flight as flight

def _varint(n):
    out = bytearray()
    while True:
        bits = n & 0x7F
        n >>= 7
        out.append(bits | (0x80 if n else 0))
        if not n:
            return bytes(out)

def _len_field(field, payload):
    return _varint((field << 3) | 2) + _varint(len(payload)) + payload

def command_statement_query(sql):
    body = _len_field(1, sql.encode())
    return _len_field(1, b"type.googleapis.com/arrow.flight.protocol.sql.CommandStatementQuery") + _len_field(2, body)

def call_opts():
    return flight.FlightCallOptions(headers=[
        (b"x-duckbox-sandbox", b"cluster-analyst"),
        (b"x-duckbox-caller", b"local"),
        (b"x-duckbox-key", b"tenant_21:user_sergio"),
    ])

def statement_info(client, sql="SELECT id FROM deals"):
    options = call_opts()
    info = client.get_flight_info(
        flight.FlightDescriptor.for_command(command_statement_query(sql)), options)
    return info, options
PY
}

# Slow owner: C still holds the lease after drain(B); A/B proxy to C.
# GetFlightInfo while C is live, then SIGSTOP C and DoGet (first-message bound).
export OWNER_PID="$PID_C"
"$PY" - <<PY
$(py_flight_sql)
import os, signal, time

owner = int(os.environ["OWNER_PID"])
client = flight.FlightClient("grpc://127.0.0.1:4747")
info, options = statement_info(client)
print("GetFlightInfo before freeze ok")
os.kill(owner, signal.SIGSTOP)
t0 = time.time()
try:
    list(client.do_get(info.endpoints[0].ticket, options))
    raise SystemExit("DoGet to SIGSTOPped owner should not succeed")
except SystemExit:
    raise
except Exception as e:  # noqa: BLE001
    elapsed = time.time() - t0
    print("slow owner DoGet failed as expected", type(e).__name__, str(e)[:200], "elapsed", round(elapsed, 2))
    if elapsed > 20:
        raise SystemExit(f"proxied DoGet hung too long: {elapsed}")
PY
kill -CONT "$PID_C" 2>/dev/null || true

# Healthy-path proxied DoGet latency (owner C is live; client hits proxy A).
"$PY" - <<PY
$(py_flight_sql)
import time

client = flight.FlightClient("grpc://127.0.0.1:4747")
info, options = statement_info(client)
list(client.do_get(info.endpoints[0].ticket, options))
samples = []
for _ in range(8):
    t0 = time.time()
    info, options = statement_info(client)
    list(client.do_get(info.endpoints[0].ticket, options))
    samples.append((time.time() - t0) * 1000)
print(f"healthy_proxied_doget_mean_ms={sum(samples)/len(samples):.3f}")
print(f"healthy_proxied_doget_pmax_ms={max(samples):.3f}")
PY

# SIGTERM the proxy while N DoGets are hung on a frozen owner. Measure
# proxy-process threads/RSS (not the client) before/during, then exit time.
export OWNER_PID="$PID_C"
export PROXY_PID="$PID_A"
"$PY" - <<PY
$(py_flight_sql)
import os, signal, threading, time

owner = int(os.environ["OWNER_PID"])
proxy = int(os.environ["PROXY_PID"])
N = 150

def snap(pid):
    threads, rss = 0, 0
    with open(f"/proc/{pid}/status", encoding="utf-8") as f:
        for line in f:
            if line.startswith("Threads:"):
                threads = int(line.split()[1])
            elif line.startswith("VmRSS:"):
                rss = int(line.split()[1])
    return threads, rss

client = flight.FlightClient("grpc://127.0.0.1:4747")
info, options = statement_info(client)
before = snap(proxy)
os.kill(owner, signal.SIGSTOP)

def hung_get():
    try:
        list(client.do_get(info.endpoints[0].ticket, options))
    except Exception:
        pass

workers = [threading.Thread(target=hung_get, daemon=True) for _ in range(N)]
for th in workers:
    th.start()
time.sleep(2.0)
during = snap(proxy)
print(
    f"proxy_hung_doget_n={N} threads_before={before[0]} threads_during={during[0]} "
    f"rss_before_kb={before[1]} rss_during_kb={during[1]}"
)
# Incoming public DoGets may use one gRPC handler thread each. A per-stream
# watcher would add a second set of N on top of that.
if during[0] - before[0] >= 2 * N:
    raise SystemExit(
        f"proxy grew {during[0] - before[0]} threads under {N} hung DoGets "
        "(want no per-stream watcher threads)"
    )
t0 = time.time()
os.kill(proxy, signal.SIGTERM)
while time.time() - t0 < 8:
    try:
        os.kill(proxy, 0)
    except OSError:
        print(f"sigterm_hung_doget_exit_s={time.time()-t0:.3f}")
        break
    time.sleep(0.05)
else:
    raise SystemExit("proxy did not exit after SIGTERM with hung DoGet")
os.kill(owner, signal.SIGCONT)
PY
wait "$PID_A" 2>/dev/null || true
PID_A=""
"$BIN" serve --daemon "$ROOT/daemons/cluster-node-a.yaml" --no-metrics &
PID_A=$!
wait_port 4747
wait_port 5747

# S3 outage longer than TTL (5s): nodes self-fence (exit 3), then restart recovers.
docker compose pause rustfs
sleep 8
for p in ${PID_A:-} ${PID_B:-} ${PID_C:-}; do
	if kill -0 "$p" 2>/dev/null; then
		echo "waiting for self-fence of pid $p"
		for _ in $(seq 1 20); do
			if ! kill -0 "$p" 2>/dev/null; then
				break
			fi
			sleep 0.5
		done
	fi
done
docker compose unpause rustfs
sleep 1
# Reap and restart whatever fenced.
for p in ${PID_A:-} ${PID_B:-} ${PID_C:-}; do
	wait "$p" 2>/dev/null || true
done
PID_A=""; PID_B=""; PID_C=""
"$BIN" serve --daemon "$ROOT/daemons/cluster-node-a.yaml" --no-metrics &
PID_A=$!
"$BIN" serve --daemon "$ROOT/daemons/cluster-node-b.yaml" --no-metrics &
PID_B=$!
"$BIN" serve --daemon "$ROOT/daemons/cluster-node-c.yaml" --no-metrics &
PID_C=$!
wait_port 4747
wait_port 4748
wait_port 4749
"$PY" - <<'PY'
from duckbox_client import connect
db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4748", retries=10)
df = db.query("SELECT id FROM deals ORDER BY id")
assert len(df) >= 1, df
print("cluster recovered after S3 outage > TTL", list(df["id"]))
db.close()
PY

echo "multi-node e2e ok"
