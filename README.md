# duckbox

A **deny-by-default SQL sandbox** for untrusted, often AI-generated, SQL over a shared DuckLake (Parquet on S3, catalog in Postgres or a DuckDB file). In the spirit of smolvm/microVM CLIs: a sandbox sees **nothing** except what its spec hands it.

This is **not** a DuckDB fork. Parser/planner/settings stay behind `server/include/duckbox/duckdb_layer.hpp` for a later DuckDB 2.0 upgrade. Development is DuckDB **1.5.6**.

## Quickstart in 5 minutes

You need Docker (Postgres + an S3 emulator), a built `./build/duckbox`, and Python 3.

```bash
docker compose up -d
python3 -m venv .venv && .venv/bin/pip install -r examples/python/requirements.txt
export DUCKBOX_S3_KEY=rustfsadmin DUCKBOX_S3_SECRET=rustfsadmin
export DUCKBOX_LAKE_CATALOG='ducklake:postgres:dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox'
.venv/bin/python scripts/seed_ducklake.py
./build/duckbox serve --daemon ./daemons/ducklake.yaml
```

In another terminal:

```bash
.venv/bin/python examples/python/quickstart.py
# or open examples/python/quickstart.ipynb  (same steps, pandas DataFrames)
```

The helper is three or four lines in your own code:

```python
import sys
sys.path.append("examples/python")
from duckbox_client import connect, create_sandbox

create_sandbox()  # named sandbox acme-analyst from the bundled spec
db = connect()    # queries send id + SQL
print(db.query("SELECT id, title, amount FROM deals"))
```

`DUCKBOX_URL` / `DUCKBOX_SPEC` / `DUCKBOX_SANDBOX` override the defaults. Memory lake (no Docker): serve `daemons/memory.yaml` and set `DUCKBOX_SPEC=policies/memory/analyst.yaml`. A flag-oriented one-shot lives at `examples/python/query_cli.py`.

## Named sandboxes

A sandbox is a **named resource** with a stable id (`acme-analyst`), like a VM name. That replaces `(key, hash)` identity and the per-key sandbox cap.

The **daemon is a control plane**. It has **no data access**. It owns:

- the Flight SQL listener
- the named-sandbox **registry** (S3 next to leases, or in-memory)
- routing of calls to warm instances
- S3 **ownership leases** (its only credential is the lease/registry prefix)

**Lake attach, attachments, and credentials belong on the sandbox definition** and are used only by that sandbox’s DuckDB instance, at create/warmup (before `lock_configuration`). The registry stores **credential references only** (`env:DUCKBOX_S3_KEY`, `file:/run/secrets/x`) — never values. Values are resolved inside the sandbox at each warmup. Refs are checked syntactically at create; resolvability is checked at warmup. Values are never logged.

A definition is: **id**, **key**, **policy** (with a bounded `policy_class` name), lake, attachments, credential refs, initSQL, limits.

Trusted-caller CRUD (Flight SQL `DoAction`, mirrored as CLI):

```bash
duckbox sandbox create|get|update|delete|list --url grpc://127.0.0.1:4747 --spec FILE [--id ID] [--key KEY]
```

Create on an existing id with different content is rejected (409). `UpdateSandbox` explicitly bumps **version** (hash of policy+initSQL is the content identity; S3 keeps immutable `sandboxes/<id>/v<N>.json` plus `current.json` with If-None-Match / If-Match). Warm instances of versions older than N-1 drain/passivate; N-1 stays warm when `handles.stale_version_grace` is >0. Delete writes a tombstone. Any node can load a definition after failover.

Queries send **id + SQL** (`x-duckbox-sandbox`). The bound key comes from the definition; send `x-duckbox-key` only when the spec’s `auth.key` extractor needs a per-query key. The caller must be authorized for the sandbox’s key (`auth.callers` maps identities to key globs; empty = allow all in local/dev).

Prepared-statement handles carry **id + version**. `handles.stale_version_grace` (default `0s`, cap `1h`) governs a non-current handle: `0s` rejects immediately with `re-prepare`. If >0, a handle for the **immediately previous** version is accepted until `updated_at + grace` and executes against that previous version’s rules. Older versions, and N-1 after the window, always `re-prepare`.

### CLI

```bash
# Control plane (no lake). Definitions live in the registry.
duckbox serve --daemon ./daemons/memory.yaml --listen 127.0.0.1:4747

duckbox sandbox create --spec ./policies/memory/analyst.yaml
duckbox sandbox list

# One-shot throwaway DuckDB (does not persist a named sandbox)
duckbox run --daemon ./daemons/memory.yaml \
  --spec ./policies/memory/analyst.yaml \
  --key tenant_21:user_sergio \
  --sql 'SELECT id, title, amount FROM deals'

# Static + throwaway-sandbox lake check
duckbox validate --daemon ./daemons/memory.yaml --spec ./policies/memory/analyst.yaml
```

`--debug-http HOST:PORT` enables the old `POST /v1/query` **debug** endpoint (off by default). v1 is **Arrow Flight SQL**.

Each node also serves Prometheus **text** on `/metrics` (default `127.0.0.1:9477`, `metrics.listen` in the daemon YAML, `--metrics HOST:PORT` / `--no-metrics`). Separate from debug HTTP. Labels are only `node` plus a bounded `policy` class (`policy_class` on the spec, allowlisted in `metrics.policy_classes`, else `other`). **Never the sandbox id** (id cardinality ≈ tenants), and never tenant/user/key — those go to the structured per-query audit log on stderr.

### Validation

1. **Static** (create/update): schema, types, key extractors, filters, `:vars`, function names, initSQL allowlist, secret-ref syntax, `handles.stale_version_grace` (duration, cap 1h). **All** errors, with field paths (`tables.deals.filters[0]: …`).
2. **Lake** (inside the sandbox on first warmup for that **(id, version)**): whitelisted tables/columns exist. Cached on the registry record so later warmups skip it. `duckbox validate` uses a throwaway sandbox.

Daemon startup validates **only** daemon config (listen, limits, optional lease prefix reachability / If-None-Match probe). Not the lake.

### Sandbox lifecycle

Runtime instances are keyed by **id@version**. Idle instances **passivate** (DuckDB freed); **warmup** recreates the instance, resolves secret refs, attaches the spec’s lake, **reruns initSQL**, then `lock_configuration`. Global `max_sandboxes` still applies; there is no per-key cap.

**initSQL**: SET of permitted names (empty allowlist is deny-all), `CREATE [OR REPLACE] TEMP VIEW|MACRO|TABLE`, `USE`, `LOAD` of spec-listed extensions (exact name). Reject `ATTACH`/`DETACH`, `COPY`/`EXPORT`, `INSTALL`, security settings. VIEW/MACRO bodies are rewritten with the tenant key and AST-checked. Objects it creates are visible to user SQL **only if the spec whitelists them**. After lake attach, `enable_external_access` is false (allowed_directories/paths cover the lake only).

### Metrics

`GET /metrics` (Prometheus text). Query histogram `duckbox_query_duration_seconds{policy,outcome,cold,node}` plus rejections, limits, result rows/bytes, sandbox lifecycle, policy-validation cache, and lease/router stubs (`duckbox_route_decisions_total`, `duckbox_node_lease_*`). Histogram buckets: 5ms … 120s for queries; 10ms … 30s for warmup/initSQL. A self-fence logs `{"event":"self_fence",...}` and exits **3**.

## Arrow Flight SQL

v1 wire protocol. JDBC and ADBC work. Headers:

- `x-duckbox-sandbox` — named sandbox id (required for queries)
- `x-duckbox-key` — optional; definition key is used otherwise
- `x-duckbox-caller` — trusted caller identity; used only when `auth.allow_insecure_dev` is set and no bearer/JWT is configured
- `Authorization: Bearer` — static `auth.bearer_secrets` or HS256 JWT (`auth.jwt_secret`). Unsigned tokens are rejected

CRUD actions: `CreateSandbox`, `GetSandbox`, `UpdateSandbox`, `DeleteSandbox`, `ListSandboxes` (body is spec YAML or id).

`GetCatalogs` / `GetDbSchemas` / `GetTables` / `GetSqlInfo` are answered **by the sandbox** and filtered to spec-whitelisted tables/columns.

Python is Arrow Flight SQL via ADBC. Use `examples/python/quickstart.ipynb` (or `quickstart.py`) after the daemon is up. `create_sandbox()` / `connect(sandbox=...)` send the id header for you.

## Build

Linux (CI): `bash scripts/install_arrow.sh` (Apache Arrow APT, including Flight SQL).  
macOS: `brew install apache-arrow openssl cmake` (recent formulae enable Flight SQL).

```bash
bash scripts/fetch_deps.sh          # DuckDB 1.5.6 headers + static libs + yaml-cpp
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++
cmake --build build --parallel
./build/duckbox_tests
make validate
```

## DuckLake locally (Postgres + RustFS)

The **spec** (not the daemon) carries DuckLake attach info. Credentials are env/secret names (never logged): `DUCKBOX_S3_KEY` / `DUCKBOX_S3_SECRET` / `DUCKBOX_LAKE_CATALOG`.

```bash
docker compose up -d
export DUCKBOX_S3_KEY=rustfsadmin DUCKBOX_S3_SECRET=rustfsadmin
export DUCKBOX_LAKE_CATALOG='ducklake:postgres:dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox'
.venv/bin/python scripts/seed_ducklake.py
./build/duckbox serve --daemon ./daemons/ducklake.yaml
.venv/bin/python examples/python/quickstart.py
```

CI job `ducklake-e2e` runs this on GitHub Actions (Docker available there). This VM has no Docker, so local compose is the laptop/CI path. **RustFS** is the emulator in `docker-compose.yml` to match the product S3 target; if the image is unusable, MinIO is the fallback (same path-style endpoint).

Reads use DuckDB httpfs path-style S3. Conditional S3 (If-Match / If-None-Match) is for **leases and the named-sandbox registry**, not for lake reads. The registry is `SandboxRegistry` (S3 impl against RustFS in CI, in-memory impl for tests). `S3ConditionalLeaseManager` is the v1 lease interface; this draft uses `SingleNodeLeaseManager` and probes the lease endpoint when configured.

## Layout

| Path | What |
| --- | --- |
| `daemons/` | Control-plane YAML (listen, limits, optional lease) |
| `policies/` | Sandbox specs (lake + tables + key + functions) |
| `server/` | C++ daemon + enforcement |
| `examples/python/` | Quickstart notebook/script, `duckbox_client`, CLI utility |
| `test/` | AST, isolation, handles, named-sandbox CRUD, initSQL |

## Stubbed

- mTLS caller certs (bearer secrets and HS256 JWT are implemented)
- Multi-node S3 leases with fencing epoch (`S3ConditionalLeaseManager`)
- Per-process cgroup/seccomp
