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

def location_of(info):
    locs = info.endpoints[0].locations
    return locs[0].uri.decode() if locs else ""

def follow(info, options):
    # Honor FlightEndpoint.locations: DoGet at the owner's advertised address.
    rows = 0
    for ep in info.endpoints:
        target = ep.locations[0].uri.decode() if ep.locations else "grpc://127.0.0.1:4747"
        rows += flight.FlightClient(target).do_get(ep.ticket, options).read_all().num_rows
    return rows

def node_status(port=5747):
    import json
    c = flight.FlightClient(f"grpc://127.0.0.1:{port}")
    opts = flight.FlightCallOptions(headers=[(b"x-duckbox-caller", b"local")])
    for rec in c.do_action(flight.Action("NodeStatus", b""), opts):
        return json.loads(rec.body.to_pybytes())
    raise SystemExit("NodeStatus returned no result")
PY
}

# The client planned a DoGet at the owner (node-a), then the owner crashes
# (SIGKILL; SIGTERM can wait on the internal Serve thread). That DoGet fails
# with a retryable UNAVAILABLE, a live non-owner answers the same ticket with
# owner_moved (no relay, no takeover), and the application retries the query
# from GetFlightInfo after the lease TTL (#100).
FAILOVER_TICKET="$("$PY" - <<PY
$(py_flight_sql)
import base64
client = flight.FlightClient("grpc://127.0.0.1:4748")
info, _ = statement_info(client)
assert location_of(info) == "grpc://127.0.0.1:4747", location_of(info)
print(base64.b64encode(info.endpoints[0].ticket.ticket).decode())
PY
)"
export FAILOVER_TICKET
kill -9 "$PID_A" 2>/dev/null || true
sleep 0.5
PID_A=""
"$PY" - <<PY
$(py_flight_sql)
import base64, os, time
ticket = flight.Ticket(base64.b64decode(os.environ["FAILOVER_TICKET"]))
try:
    list(flight.FlightClient("grpc://127.0.0.1:4747").do_get(ticket, call_opts(timeout=10)))
    raise SystemExit("DoGet at the killed owner succeeded")
except flight.FlightUnavailableError as e:
    print("DoGet at the killed owner: UNAVAILABLE", str(e)[:120], flush=True)
t0 = time.time()
try:
    list(flight.FlightClient("grpc://127.0.0.1:4748").do_get(ticket, call_opts(timeout=10)))
    raise SystemExit("DoGet on non-owner node-b was served")
except flight.FlightUnavailableError as e:
    ms = (time.time() - t0) * 1000
    msg = str(e)
    print(f"failover_non_owner_doget_ms={ms:.3f}", msg[:200], flush=True)
    assert "owner_moved:" in msg and "owner=node-a" in msg, msg
    assert ms < 1000, ms
PY

# Lease TTL is 5s (+ 1s skew). Wait for expiry so the retry's GetFlightInfo
# can take over. One retry attempt after the lease is stealable.
sleep 7
"$PY" - <<'PY'
from duckbox_client import connect
db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4748", retries=1)
df = db.query("SELECT id FROM deals ORDER BY id")
assert len(df) >= 1, df
print("failover retry via node-b ok", list(df["id"]))
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

# Redirect and owner_moved (#100). Owner C is live; the client connects to A.
# The raw pyarrow helper honors FlightEndpoint.locations; a client that
# ignores them gets an immediate owner_moved from A. No node relays DoGet.
OWNER_LIST="$("$BIN" sandbox list --url grpc://127.0.0.1:4748 --id-prefix cluster-analyst)"
echo "$OWNER_LIST"
echo "$OWNER_LIST" | grep -q '"owner":"node-c"'
"$PY" - <<PY
$(py_flight_sql)
import json, time

client = flight.FlightClient("grpc://127.0.0.1:4747")
info, options = statement_info(client)
assert location_of(info) == "grpc://127.0.0.1:4749", location_of(info)
assert follow(info, options) >= 1
samples = []
for _ in range(8):
    t0 = time.time()
    info, options = statement_info(client)
    follow(info, options)
    samples.append((time.time() - t0) * 1000)
print(f"redirect_query_mean_ms={sum(samples)/len(samples):.3f}")
print(f"redirect_query_pmax_ms={max(samples):.3f}")

ticket = info.endpoints[0].ticket
t0 = time.time()
try:
    list(client.do_get(ticket, options))
    raise SystemExit("DoGet on non-owner node-a was served (relayed)")
except flight.FlightUnavailableError as e:
    ms = (time.time() - t0) * 1000
    msg = str(e)
    print(f"non_owner_doget_ms={ms:.3f}", msg[:200], flush=True)
    assert "owner_moved:" in msg and "owner=node-c" in msg, msg
    assert "address=grpc://127.0.0.1:4749" in msg, msg
    assert "5749" not in msg, "internal listener leaked: " + msg
    assert ms < 1000, ms
    # Gherkin 7: pyarrow exposes the JSON extra_info on FlightError.
    extra = getattr(e, "extra_info", b"") or b""
    j = json.loads(extra) if extra else {}
    print("pyarrow_extra_info_visible=" + ("yes " + json.dumps(j, sort_keys=True) if j else "no"), flush=True)
    assert j.get("code") == "owner_moved", ("pyarrow extra_info", extra)
    assert j.get("owner") == "node-c" and j.get("address") == "grpc://127.0.0.1:4749", j
PY

# 150 concurrent DoGets for a sandbox owned by C, sent to A: each fails
# immediately; A adds no threads and holds no peer call (NodeStatus).
export NON_OWNER_PID="$PID_A"
"$PY" - <<PY
$(py_flight_sql)
import os, threading, time
from concurrent.futures import ThreadPoolExecutor

pid = int(os.environ["NON_OWNER_PID"])
N = 150
WORKERS = 16

def threads(p):
    with open(f"/proc/{p}/status", encoding="utf-8") as f:
        for line in f:
            if line.startswith("Threads:"):
                return int(line.split()[1])
    return -1

warm = flight.FlightClient("grpc://127.0.0.1:4747")
info, options = statement_info(warm)
ticket = info.endpoints[0].ticket
clients = [flight.FlightClient("grpc://127.0.0.1:4747") for _ in range(WORKERS)]
for c in clients:
    try:
        list(c.do_get(ticket, options))
    except flight.FlightUnavailableError:
        pass
lock = threading.Lock()
state = {"moved": 0, "other": [], "max_ms": 0.0}

def one(i):
    t0 = time.time()
    try:
        list(clients[i % WORKERS].do_get(ticket, options))
        msg = "served"
    except Exception as e:  # noqa: BLE001
        msg = str(e)
    ms = (time.time() - t0) * 1000
    with lock:
        state["max_ms"] = max(state["max_ms"], ms)
        if "owner_moved:" in msg:
            state["moved"] += 1
        else:
            state["other"].append(msg[:160])

before = threads(pid)
t0 = time.time()
with ThreadPoolExecutor(max_workers=WORKERS) as pool:
    futs = [pool.submit(one, i) for i in range(N)]
    during = threads(pid)
    for f in futs:
        f.result()
total_ms = (time.time() - t0) * 1000
after = threads(pid)
inflight = int(node_status(5747).get("proxy_inflight", 0))
print(
    f"non_owner_doget_n={N} workers={WORKERS} owner_moved={state['moved']} "
    f"threads_before={before} threads_during={during} threads_after={after} "
    f"total_ms={total_ms:.1f} max_call_ms={state['max_ms']:.1f} peer_inflight={inflight}",
    flush=True,
)
if state["other"]:
    print("non_owner_doget_other", state["other"][:5])
assert state["moved"] == N, state
assert state["max_ms"] < 2000, state["max_ms"]
assert inflight == 0, inflight
assert after <= before + WORKERS, (before, after)
PY

# ADBC surfaces owner_moved to Python. Restart node-c with advertised_address
# pointing at node-a (a stale location); C takes the free lease on
# GetFlightInfo and the driver's DoGet lands on A, which does not own it.
kill -TERM "$PID_C" 2>/dev/null || true
wait "$PID_C" 2>/dev/null || true
PID_C=""
STALE_YAML="$(mktemp)"
"$PY" - <<PY
from pathlib import Path
src = Path("$ROOT/daemons/cluster-node-c.yaml").read_text()
src = src.replace("advertised_address: grpc://127.0.0.1:4749", "advertised_address: grpc://127.0.0.1:4747")
assert "advertised_address: grpc://127.0.0.1:4747" in src
Path("$STALE_YAML").write_text(src)
PY
"$BIN" serve --daemon "$STALE_YAML" --no-metrics &
PID_C=$!
wait_port 4749
wait_port 5749
"$PY" - <<'PY'
from duckbox_client import connect
db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4749", retries=1)
try:
    db.query("SELECT id FROM deals ORDER BY id")
    raise SystemExit("ADBC DoGet at a non-owner was served")
except SystemExit:
    raise
except Exception as e:  # noqa: BLE001
    msg = str(e)
    print("adbc_owner_moved_exception", type(e).__name__, msg[:240], flush=True)
    assert "owner_moved" in msg and "node-c" in msg, msg
    # Gherkin 7: is the JSON extra_info among the ADBC error details? Only a
    # detail value that parses as JSON with code=owner_moved counts; the
    # status message header also contains the text "owner_moved".
    import json
    def text(x):
        return x.decode("utf-8", "replace") if isinstance(x, (bytes, bytearray)) else str(x)
    details = getattr(e, "details", None) or []
    keys = [text(k) for k, _ in details]
    found = None
    for k, v in details:
        try:
            j = json.loads(v if isinstance(v, (bytes, bytearray)) else str(v))
        except ValueError:
            continue
        if isinstance(j, dict) and j.get("code") == "owner_moved":
            found = (text(k), j)
            break
    print("adbc_error_detail_keys=" + ",".join(keys), flush=True)
    print("adbc_extra_info_visible=" + ("yes " + found[0] + " " + json.dumps(found[1], sort_keys=True) if found else "no"), flush=True)
    # Recorded result (ADBC Flight SQL driver 1.13): the details carry
    # x-arrow-status, x-arrow-status-detail-bin ("Unavailable") and the
    # message, not the extra_info JSON. ADBC clients read owner= and address=
    # from the message (docs/multi-node.md). Fails if a driver starts
    # exposing it, so the docs get updated.
    assert found is None, ("ADBC now exposes extra_info; update docs/multi-node.md", found)
    assert "owner=node-c" in msg and "address=grpc://127.0.0.1:4747" in msg, msg
finally:
    db.close()
PY
kill -TERM "$PID_C" 2>/dev/null || true
wait "$PID_C" 2>/dev/null || true
"$BIN" serve --daemon "$ROOT/daemons/cluster-node-c.yaml" --no-metrics &
PID_C=$!
wait_port 4749
wait_port 5749

# node-b is still draining from the drain step above and would answer
# no_owner; restart it so it can own the sandbox again.
kill -TERM "$PID_B" 2>/dev/null || true
wait "$PID_B" 2>/dev/null || true
"$BIN" serve --daemon "$ROOT/daemons/cluster-node-b.yaml" --no-metrics &
PID_B=$!
wait_port 4748
wait_port 5748

# ADBC connected only to node-a runs a prepared statement with a bound
# parameter on a sandbox owned by node-b: rows are filtered by the bound value.
"$PY" - <<'PY'
from duckbox_client import connect
db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4748", retries=1)
assert len(db.query("SELECT id FROM deals ORDER BY id")) >= 1
db.close()
PY
OWNER_B="$("$BIN" sandbox list --url grpc://127.0.0.1:4747 --id-prefix cluster-analyst)"
echo "$OWNER_B"
echo "$OWNER_B" | grep -q '"owner":"node-b"'
"$PY" - <<'PY'
from duckbox_client import connect
db = connect(sandbox="cluster-analyst", key="tenant_21:user_sergio", url="grpc://127.0.0.1:4747", retries=1)
all_ids = list(db.query("SELECT id FROM deals ORDER BY id")["id"])
want = all_ids[0]
df = db.query("SELECT id FROM deals WHERE id = ?", [want])
print("adbc_prepared_bound_rows", list(df["id"]), "of", all_ids, flush=True)
assert list(df["id"]) == [want], (list(df["id"]), want)
# The driver's choice of DoPut-returned vs original handle is not visible to
# the client. Both are correct: the owner executes the params sealed in the
# signed ticket that node-a re-signs on GetFlightInfo (#95 C3).
print("adbc_prepared_handle=not observable from the client; params sealed in the signed ticket", flush=True)
db.close()
PY

# Owner freeze longer than lease TTL (5s). The client timeout is 60s, well
# above the documented bounds, so a pass cannot be the client giving up
# first. GetFlightInfo on a non-owner returns within proxy_timeout_ms (5s).
# A DoGet on the non-owner never waits on the owner: it fails immediately
# with UNAVAILABLE (owner_moved or no_owner).
export OWNER_PID="$PID_B"
"$PY" - <<PY
$(py_flight_sql)
import os, signal, time

owner = int(os.environ["OWNER_PID"])
CLIENT_TIMEOUT_S = 60.0
GETINFO_BOUND_S = 5.0
DOGET_BOUND_S = 1.0
ASSERT_SLACK_S = 2.0  # assertion tolerance only; not a client timeout
client = flight.FlightClient("grpc://127.0.0.1:4747")


def is_client_timeout(exc):
    timed = getattr(flight, "FlightTimedOutError", ())
    return isinstance(exc, timed) or type(exc).__name__ == "FlightTimedOutError"


def assert_bound(elapsed, bound, label, client_timeout):
    if client_timeout:
        raise SystemExit(f"{label}: client timeout fired after {elapsed:.3f}s; want <= {bound}s")
    if elapsed > bound + ASSERT_SLACK_S:
        raise SystemExit(f"{label}: returned in {elapsed:.3f}s; want <= {bound}+{ASSERT_SLACK_S}s")


info, options = statement_info(client, timeout=CLIENT_TIMEOUT_S)
assert location_of(info) == "grpc://127.0.0.1:4748", location_of(info)
ticket = info.endpoints[0].ticket
os.kill(owner, signal.SIGSTOP)

t1 = time.time()
try:
    statement_info(client, timeout=CLIENT_TIMEOUT_S)
    elapsed = time.time() - t1
    print("GetFlightInfo during freeze ok (takeover) elapsed", round(elapsed, 3), flush=True)
    assert_bound(elapsed, GETINFO_BOUND_S, "GetFlightInfo during freeze", False)
except flight.FlightUnavailableError as e:
    elapsed = time.time() - t1
    print("GetFlightInfo during freeze UNAVAILABLE", str(e)[:200], "elapsed", round(elapsed, 3), flush=True)
    assert_bound(elapsed, GETINFO_BOUND_S, "GetFlightInfo during freeze", False)
except Exception as e:  # noqa: BLE001
    elapsed = time.time() - t1
    assert_bound(elapsed, GETINFO_BOUND_S, "GetFlightInfo during freeze", is_client_timeout(e))
    raise

t2 = time.time()
try:
    list(client.do_get(ticket, call_opts(timeout=CLIENT_TIMEOUT_S)))
    raise SystemExit("DoGet on non-owner node-a was served during the owner freeze")
except flight.FlightUnavailableError as e:
    elapsed = time.time() - t2
    msg = str(e)
    print("DoGet on non-owner during freeze", msg[:200], "elapsed", round(elapsed, 3), flush=True)
    assert "owner_moved:" in msg or "no_owner:" in msg, msg
    assert_bound(elapsed, DOGET_BOUND_S, "DoGet during freeze", False)
PY
kill -CONT "$PID_B" 2>/dev/null || true

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
