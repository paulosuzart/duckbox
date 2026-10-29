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

dump_leases() {
	echo "===== lease records (S3 prefix leases/) =====" >&2
	"$PY" - <<'PY' >&2 || true
import os, json
import boto3
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
    pages = c.get_paginator("list_objects_v2").paginate(Bucket="duckbox-control", Prefix="leases/")
    n = 0
    for page in pages:
        for obj in page.get("Contents") or []:
            n += 1
            key = obj["Key"]
            body = c.get_object(Bucket="duckbox-control", Key=key)["Body"].read().decode("utf-8", "replace")
            print(f"{key}\t{body}")
    if n == 0:
        print("(no objects under leases/)")
except ClientError as e:
    print(f"lease dump failed: {e}")
PY
	echo "===== end lease records =====" >&2
}

# Bounded wait for sandbox-list owner to match a regex. Not a query retry.
wait_owner() {
	local url="$1"
	local want="$2"
	local i list=""
	for i in $(seq 1 40); do
		list="$("$BIN" sandbox list --url "$url" --id-prefix cluster-analyst)" || true
		if echo "$list" | grep -E -q "$want"; then
			echo "$list"
			return 0
		fi
		sleep 0.25
	done
	echo "$list"
	echo "timeout waiting for owner matching $want via $url" >&2
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
E2E_FAILED=0
cleanup() {
	if [[ "${E2E_FAILED}" -ne 0 ]]; then
		dump_leases || true
	fi
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
on_err() {
	E2E_FAILED=1
}
trap on_err ERR
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
db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4747", retries=1)
df = db.query("SELECT id, title FROM deals ORDER BY id")
assert len(df) >= 1, df
print("warmup query via node-a ok", list(df["id"]))
db.close()
PY

# Daemon wiring of the public 4 MiB cap (ApplyPublicListenerMessageCap in
# RunServer). I3b only exercises the helper the test applies itself, so a
# one-frame ~5 MiB DoPut on the real public listener is the required check:
# removing the daemon call must fail this e2e job.
"$PY" - <<'PY'
import pyarrow as pa
import pyarrow.flight as fl


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


def anyp(name, value):
    return _len_field(1, ("type.googleapis.com/arrow.flight.protocol.sql." + name).encode()) + _len_field(
        2, value
    )


def rd(buf):
    i = 0
    out = {}
    while i < len(buf):
        tag = 0
        shift = 0
        while True:
            b = buf[i]
            i += 1
            tag |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        no = tag >> 3
        ln = 0
        shift = 0
        while True:
            b = buf[i]
            i += 1
            ln |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        out.setdefault(no, buf[i : i + ln])
        i += ln
    return out


opts = fl.FlightCallOptions(
    headers=[
        (b"x-duckbox-sandbox", b"cluster-analyst"),
        (b"x-duckbox-caller", b"local"),
        (b"x-duckbox-key", b"tenant_21:user_sergio"),
    ],
    timeout=15,
)
client = fl.FlightClient("grpc://127.0.0.1:4747")
body = anyp("ActionCreatePreparedStatementRequest", _len_field(1, b"SELECT id FROM deals WHERE title <> ?"))
res = list(client.do_action(fl.Action("CreatePreparedStatement", body), opts))
handle = rd(rd(res[0].body.to_pybytes())[2])[1]
desc = fl.FlightDescriptor.for_command(anyp("CommandPreparedStatementQuery", _len_field(1, handle)))
schema = pa.schema([("$1", pa.utf8())])
try:
    writer, reader = client.do_put(desc, schema, opts)
    writer.write_batch(pa.record_batch([pa.array(["Q" * (5 * 1024 * 1024)])], schema=schema))
    writer.done_writing()
    reader.read()
    writer.close()
except Exception as e:  # noqa: BLE001
    msg = str(e)
    if "larger than max" in msg and "4194304" in msg:
        print("public 4 MiB cap:", msg.split(". gRPC client debug")[0][:160], flush=True)
    else:
        raise SystemExit(f"public 4 MiB cap: want 'larger than max (... vs. 4194304)', got {msg[:240]}")
else:
    raise SystemExit("public 4 MiB cap: 5 MiB DoPut accepted (ApplyPublicListenerMessageCap not wired)")
PY

LIST="$("$BIN" sandbox list --url grpc://127.0.0.1:4748 --id-prefix cluster-analyst)"
echo "$LIST"
echo "$LIST" | grep -q '"id":"cluster-analyst"'
echo "$LIST" | grep -q '"owner":"node-a"'

"$PY" - <<'PY'
from duckbox_client import connect
db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4748", retries=1)
df = db.query("SELECT id, title FROM deals ORDER BY id")
assert len(df) >= 1, df
print("query via non-owner node-b ok", list(df["id"]))
db.close()
PY

# Crash the owner (SIGKILL). SIGTERM can wait on the internal Serve thread.
kill -9 "$PID_A" 2>/dev/null || true
sleep 0.5
PID_A=""

# Lease TTL is 5s (+ 1s skew). Wait for expiry so the next Get can take over.
# Do not retry the query — one attempt after the lease is stealable.
sleep 7
"$PY" - <<'PY'
from duckbox_client import connect
db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4748", retries=1)
df = db.query("SELECT id FROM deals ORDER BY id")
assert len(df) >= 1, df
print("failover query via node-b ok", list(df["id"]))
db.close()
PY

LIST2="$("$BIN" sandbox list --url grpc://127.0.0.1:4749 --id-prefix cluster-analyst)"
echo "$LIST2"
echo "$LIST2" | grep -E -q '"owner":"node-(b|c)"'

"$BIN" node drain --url grpc://127.0.0.1:5748 --timeout 1000 --peer-secret env:DUCKBOX_PEER_SECRET
"$PY" - <<'PY'
from duckbox_client import connect
db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4749", retries=1)
df = db.query("SELECT id FROM deals ORDER BY id")
assert len(df) >= 1, df
print("query after drain via node-c ok", list(df["id"]))
db.close()
PY

# Restart the same node_id after SIGKILL (A was killed above).
"$BIN" serve --daemon "$ROOT/daemons/cluster-node-a.yaml" --no-metrics &
PID_A=$!
wait_port 4747
wait_port 5747
"$PY" - <<'PY'
from duckbox_client import connect
db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4747", retries=1)
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
db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4747", retries=1)
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

def call_opts(timeout=None):
    kw = dict(headers=[
        (b"x-duckbox-sandbox", b"cluster-analyst"),
        (b"x-duckbox-caller", b"local"),
        (b"x-duckbox-key", b"tenant_21:user_sergio"),
    ])
    if timeout is not None:
        kw["timeout"] = timeout
    return flight.FlightCallOptions(**kw)

def statement_info(client, sql="SELECT id FROM deals", timeout=None):
    options = call_opts(timeout)
    info = client.get_flight_info(
        flight.FlightDescriptor.for_command(command_statement_query(sql)), options)
    return info, options

def node_status(port=5747):
    import json
    c = flight.FlightClient(f"grpc://127.0.0.1:{port}")
    opts = flight.FlightCallOptions(headers=[(b"x-duckbox-caller", b"local")])
    for rec in c.do_action(flight.Action("NodeStatus", b""), opts):
        return json.loads(rec.body.to_pybytes())
    raise SystemExit("NodeStatus returned no result")
PY
}

# Healthy-path proxied DoGet latency (owner C is live; client hits proxy A).
# Do this — and the 150-stream hang — before any freeze longer than lease TTL
# (5s). A 13s SIGSTOP lets another node steal ownership; later DoGets then
# succeed locally on A and proxy_inflight stays 0.
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

# SIGTERM the proxy while N DoGets are hung on a frozen owner. One FlightClient
# per stream (a shared client serializes DoGet). Caps default 256/256 so N=150
# must be accepted, not "peer proxy busy". Wait on NodeStatus.proxy_inflight.
OWNER_LIST="$("$BIN" sandbox list --url grpc://127.0.0.1:4748 --id-prefix cluster-analyst)"
echo "$OWNER_LIST"
echo "$OWNER_LIST" | grep -q '"owner":"node-c"'
export OWNER_PID="$PID_C"
export PROXY_PID="$PID_A"
"$PY" - <<PY
$(py_flight_sql)
import os, signal, threading, time

signal.signal(signal.SIGPIPE, signal.SIG_IGN)
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

warm = flight.FlightClient("grpc://127.0.0.1:4747")
info, options = statement_info(warm)
ticket = info.endpoints[0].ticket
# Separate channel per stream so HTTP/2 / client locks cannot serialize them.
clients = [flight.FlightClient("grpc://127.0.0.1:4747") for _ in range(N)]
lock = threading.Lock()
state = {"busy": 0, "other": 0, "ok": 0, "other_msgs": []}

def hung_get(i):
    try:
        list(clients[i].do_get(ticket, options))
        with lock:
            state["ok"] += 1
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        with lock:
            if "peer proxy busy" in msg:
                state["busy"] += 1
            else:
                state["other"] += 1
                if len(state["other_msgs"]) < 3:
                    state["other_msgs"].append(msg[:160])

before = snap(proxy)
os.kill(owner, signal.SIGSTOP)
workers = [threading.Thread(target=hung_get, args=(i,), daemon=True) for i in range(N)]
for th in workers:
    th.start()
deadline = time.time() + 8
inflight = 0
while time.time() < deadline:
    try:
        inflight = int(node_status(5747).get("proxy_inflight", 0))
    except Exception:  # noqa: BLE001
        inflight = 0
    if inflight >= N:
        break
    time.sleep(0.05)
during = snap(proxy)
print(
    f"proxy_hung_doget_n={N} in_flight={inflight} rejected_busy={state['busy']} "
    f"other_done={state['other']} ok_done={state['ok']} "
    f"threads_before={before[0]} threads_during={during[0]} "
    f"rss_before_kb={before[1]} rss_during_kb={during[1]}",
    flush=True,
)
if state["other_msgs"]:
    print("proxy_hung_doget_other", state["other_msgs"])
if state["busy"] != 0:
    raise SystemExit(
        f"{state['busy']} of {N} rejected with peer proxy busy "
        "(defaults proxy_max_inflight=256 / per_peer=256; N=150 must be under the cap)"
    )
if inflight < N:
    raise SystemExit(
        f"only {inflight}/{N} proxied DoGets in flight at measurement "
        f"(busy={state['busy']} other={state['other']} ok={state['ok']})"
    )
grown = during[0] - before[0]
# Incoming public DoGets may use one gRPC handler thread each. A per-stream
# watcher would add a second set of N on top of that.
if grown >= 2 * N:
    raise SystemExit(
        f"proxy grew {grown} threads under {N} hung DoGets "
        "(want no per-stream watcher threads)"
    )
t0 = time.time()
os.kill(proxy, signal.SIGTERM)
exited = False
while time.time() - t0 < 8:
    try:
        os.kill(proxy, 0)
    except OSError:
        print(f"sigterm_hung_doget_exit_s={time.time()-t0:.3f}", flush=True)
        exited = True
        break
    time.sleep(0.05)
try:
    os.kill(owner, signal.SIGCONT)
except OSError:
    pass
if not exited:
    raise SystemExit("proxy did not exit after SIGTERM with hung DoGet")
PY
kill -CONT "$PID_C" 2>/dev/null || true
wait "$PID_A" 2>/dev/null || true
PID_A=""

# Over-cap: same node_id, caps 2/2. Extra DoGets must reject immediately.
BUSY_YAML="$(mktemp)"
"$PY" - <<PY
from pathlib import Path
src = Path("$ROOT/daemons/cluster-node-a.yaml").read_text()
if "proxy_max_inflight:" not in src:
    src = src.rstrip() + "\n  proxy_max_inflight: 2\n  proxy_max_inflight_per_peer: 2\n"
Path("$BUSY_YAML").write_text(src)
PY
kill -TERM "$PID_A" 2>/dev/null || true
wait "$PID_A" 2>/dev/null || true
PID_A=""
"$BIN" serve --daemon "$BUSY_YAML" --no-metrics &
PID_A=$!
wait_port 4747
wait_port 5747
export OWNER_PID="$PID_C"
export PROXY_PID="$PID_A"
"$PY" - <<PY
$(py_flight_sql)
import os, signal, threading, time

signal.signal(signal.SIGPIPE, signal.SIG_IGN)
owner = int(os.environ["OWNER_PID"])
N = 8
CAP = 2
warm = flight.FlightClient("grpc://127.0.0.1:4747")
info, options = statement_info(warm)
ticket = info.endpoints[0].ticket
clients = [flight.FlightClient("grpc://127.0.0.1:4747") for _ in range(N)]
lock = threading.Lock()
state = {"busy": 0, "other": 0, "ok": 0, "busy_ms": []}

def one(i):
    t0 = time.time()
    try:
        list(clients[i].do_get(ticket, options))
        with lock:
            state["ok"] += 1
    except Exception as e:  # noqa: BLE001
        ms = (time.time() - t0) * 1000
        msg = str(e)
        with lock:
            if "peer proxy busy" in msg:
                state["busy"] += 1
                state["busy_ms"].append(ms)
            else:
                state["other"] += 1

os.kill(owner, signal.SIGSTOP)
workers = [threading.Thread(target=one, args=(i,), daemon=True) for i in range(N)]
for th in workers:
    th.start()
deadline = time.time() + 5
inflight = 0
while time.time() < deadline:
    try:
        inflight = int(node_status(5747).get("proxy_inflight", 0))
    except Exception:  # noqa: BLE001
        inflight = 0
    if inflight >= CAP and state["busy"] >= N - CAP:
        break
    time.sleep(0.05)
print(
    f"proxy_busy_e2e_n={N} cap={CAP} in_flight={inflight} rejected_busy={state['busy']} "
    f"other_done={state['other']} ok_done={state['ok']}",
    flush=True,
)
if state["busy_ms"]:
    print(f"proxy_busy_e2e_reject_pmax_ms={max(state['busy_ms']):.3f}")
if inflight != CAP:
    raise SystemExit(f"expected {CAP} in flight under the cap, got {inflight}")
if state["busy"] < N - CAP:
    raise SystemExit(
        f"expected at least {N - CAP} immediate peer proxy busy, got {state['busy']}"
    )
if state["busy_ms"] and max(state["busy_ms"]) >= 200:
    raise SystemExit(
        f"busy rejection was queued ({max(state['busy_ms']):.1f}ms; want < 200ms)"
    )
try:
    os.kill(owner, signal.SIGCONT)
except OSError:
    pass
# Skip pyarrow/gRPC atexit: tearing down live DoGet clients against a
# just-continued owner has SIGSEGV'd the interpreter (CI exit 139).
os._exit(0)
PY
# Always continue C in the shell so later steps (S3 pause) are not talking
# to a still-frozen owner. The freeze case below uses a 60s client timeout
# and asserts the proxy itself returned within the documented bound.
kill -CONT "$PID_C" 2>/dev/null || true
kill -TERM "$PID_A" 2>/dev/null || true
wait "$PID_A" 2>/dev/null || true
PID_A=""
rm -f "$BUSY_YAML"
"$BIN" serve --daemon "$ROOT/daemons/cluster-node-a.yaml" --no-metrics &
PID_A=$!
wait_port 4747
wait_port 5747

# Owner freeze longer than lease TTL (5s). The client timeout is 60s — well
# above the documented proxy bounds — so a pass cannot be the client giving
# up first. GetFlightInfo must return within proxy_timeout_ms (5s);
# DoGet within query_timeout_ms + proxy_timeout_ms (8+5=13s). Timeout or
# post-takeover success are both fine; an unbounded proxy wait is not.
export OWNER_PID="$PID_C"
"$PY" - <<PY
$(py_flight_sql)
import os, signal, time

owner = int(os.environ["OWNER_PID"])
# Documented bounds (cluster YAML defaults): proxy_timeout_ms=5000,
# query_timeout_ms=8000, first-message ceiling=60s.
CLIENT_TIMEOUT_S = 60.0
GETINFO_BOUND_S = 5.0
DOGET_BOUND_S = 13.0
ASSERT_SLACK_S = 2.0  # assertion tolerance only; not a client timeout
client = flight.FlightClient("grpc://127.0.0.1:4747")


def is_client_timeout(exc):
    # Only the Flight client deadline. "peer proxy timed out" is an IO error
    # the proxy returned within its own bound.
    timed = getattr(flight, "FlightTimedOutError", ())
    return isinstance(exc, timed) or type(exc).__name__ == "FlightTimedOutError"


def assert_proxy_bound(elapsed, bound, label, client_timeout):
    if client_timeout:
        raise SystemExit(
            f"{label}: client timeout fired after {elapsed:.3f}s; "
            f"proxy did not return within {bound}s"
        )
    if elapsed > bound + ASSERT_SLACK_S:
        raise SystemExit(
            f"{label}: proxy returned in {elapsed:.3f}s; "
            f"want <= {bound}+{ASSERT_SLACK_S}s"
        )


t0 = time.time()
try:
    info, options = statement_info(client, timeout=CLIENT_TIMEOUT_S)
    print("GetFlightInfo before freeze ok elapsed", round(time.time() - t0, 3), flush=True)
except Exception as e:  # noqa: BLE001
    elapsed = time.time() - t0
    print("GetFlightInfo before freeze failed", type(e).__name__, str(e)[:200], "elapsed", round(elapsed, 3), flush=True)
    assert_proxy_bound(elapsed, GETINFO_BOUND_S, "GetFlightInfo before freeze", is_client_timeout(e))
    raise

ticket = info.endpoints[0].ticket
os.kill(owner, signal.SIGSTOP)

t1 = time.time()
try:
    info2, _ = statement_info(client, timeout=CLIENT_TIMEOUT_S)
    elapsed = time.time() - t1
    print("GetFlightInfo during freeze ok (takeover) elapsed", round(elapsed, 3), flush=True)
    assert_proxy_bound(elapsed, GETINFO_BOUND_S, "GetFlightInfo during freeze", False)
except Exception as e:  # noqa: BLE001
    elapsed = time.time() - t1
    print("GetFlightInfo during freeze failed", type(e).__name__, str(e)[:200], "elapsed", round(elapsed, 3), flush=True)
    assert_proxy_bound(elapsed, GETINFO_BOUND_S, "GetFlightInfo during freeze", is_client_timeout(e))

t2 = time.time()
try:
    doget_opts = call_opts(timeout=CLIENT_TIMEOUT_S)
    list(client.do_get(ticket, doget_opts))
    elapsed = time.time() - t2
    print("DoGet during freeze ok elapsed", round(elapsed, 3), flush=True)
    assert_proxy_bound(elapsed, DOGET_BOUND_S, "DoGet during freeze", False)
except Exception as e:  # noqa: BLE001
    elapsed = time.time() - t2
    print("DoGet during freeze failed", type(e).__name__, str(e)[:200], "elapsed", round(elapsed, 3), flush=True)
    assert_proxy_bound(elapsed, DOGET_BOUND_S, "DoGet during freeze", is_client_timeout(e))
PY
kill -CONT "$PID_C" 2>/dev/null || true

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
# Reap and restart whatever fenced. SIGKILL leftovers so `wait` cannot hang
# the step on a wedged (still-alive) process.
for p in ${PID_A:-} ${PID_B:-} ${PID_C:-}; do
	if kill -0 "$p" 2>/dev/null; then
		echo "pid $p still alive after fence wait; SIGKILL"
		kill -9 "$p" 2>/dev/null || true
	fi
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
db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4748", retries=1)
df = db.query("SELECT id FROM deals ORDER BY id")
assert len(df) >= 1, df
print("cluster recovered after S3 outage > TTL", list(df["id"]))
db.close()
PY

echo "multi-node e2e ok"
