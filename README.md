# duckbox

A **deny-by-default SQL sandbox** for untrusted, often AI-generated, SQL over a shared DuckLake (Parquet on S3, catalog in Postgres or a DuckDB file). In the spirit of smolvm/microVM CLIs: a sandbox sees **nothing** except what its spec hands it.

This is **not** a DuckDB fork. Parser/planner/settings stay behind `server/include/duckbox/duckdb_layer.hpp` for a later DuckDB 2.0 upgrade. Development is DuckDB **1.5.6**.

## The sandbox spec is the contract

A duckbox **daemon is a control plane**. It has **no data access**. It owns:

- the Flight SQL listener and instance registry
- routing of calls to sandboxes
- S3 **ownership leases** (its only credential is the lease prefix)

**Lake attach, attachments, and their credentials belong on the per-connection spec** and are used only by that sandbox’s DuckDB instance, at create/warmup (before `lock_configuration`). Credentials are **env/secret names**, never logged.

Each connection (or `duckbox run`) supplies:

| Input | Where |
| --- | --- |
| Tenant **key** | `x-duckbox-key` / handshake username / `--key` |
| **Policy / spec** | `x-duckbox-spec` YAML (trusted) or inside the JWT (token mode) / `--spec` |
| **initSQL** | `x-duckbox-init-sql` / `--init-sql` / spec `init_sql` |

The spec grants, explicitly:

- lake attach (catalog, data path, S3 env names, extensions to LOAD)
- whitelisted tables and columns
- mandatory filters (bound from key variables, never string-interpolated)
- key extraction (`auth.key` pattern / regex / split)
- function allowlist and resource limits

Nothing else is reachable: no implicit catalogs, no extension autoload, no table discovery, no user `ATTACH`/`COPY TO`.

### CLI

```bash
# Control plane (no lake). Specs arrive per connection.
duckbox serve --daemon ./daemons/memory.yaml --listen 127.0.0.1:4747

# One-shot sandbox (throws away the DuckDB instance at exit)
duckbox run --daemon ./daemons/memory.yaml \
  --spec ./policies/memory/analyst.yaml \
  --key tenant_21:user_sergio \
  --sql 'SELECT id, title, amount FROM deals'

# Static + throwaway-sandbox lake check
duckbox validate --daemon ./daemons/memory.yaml --spec ./policies/memory/analyst.yaml
```

`--debug-http HOST:PORT` enables the old `POST /v1/query` **debug** endpoint (off by default). v1 is **Arrow Flight SQL**.

Trusted callers may send inline spec YAML. In `auth.mode: token`, the spec must come from the signed JWT (inline YAML or hash). JWT verify is stubbed in this draft.

### Validation

1. **Static** (every arrival): schema, types, key extractors compile, filters parse with DuckDB, referenced `:vars` exist, function names, initSQL allowlist. **All** errors, with field paths (`tables.deals.filters[0]: …`).
2. **Lake** (inside the sandbox on first warmup for that **policy hash**): whitelisted tables/columns exist, filter columns exist. Cached in the daemon registry by hash so later sandboxes skip it. `duckbox validate` uses a throwaway sandbox.

Daemon startup validates **only** daemon config (listen, limits, optional lease prefix reachability / If-None-Match probe). Not the lake.

### Sandbox lifecycle

Sandboxes are keyed by `(tenant key, hash(policy + initSQL))`. A different policy for the same key is a **different** sandbox. Idle instances **passivate** (DuckDB freed); **warmup** recreates the instance, attaches the spec’s lake, **reruns initSQL**, then `lock_configuration`. Cap live sandboxes per key (default 3).

**initSQL** (header / CLI / spec): SET of permitted names, `CREATE [OR REPLACE] TEMP VIEW|MACRO|TABLE`, `USE`, `LOAD` of spec-listed extensions. Reject `ATTACH`/`DETACH`, `COPY`/`EXPORT`, `INSTALL`, external access, security settings. Objects it creates are visible to user SQL **only if the spec whitelists them**.

Prepared-statement handles are HMAC-signed and include rewritten SQL, tenant key, **policy hash + YAML**, initSQL, expiry, and bound parameter IPC so any node can execute without session state.

## Arrow Flight SQL

v1 wire protocol. JDBC and ADBC work. Headers:

- `x-duckbox-key`
- `x-duckbox-spec` (base64url of the spec YAML — gRPC headers cannot carry newlines)
- `x-duckbox-spec-dir` (optional; resolves spec-relative paths such as `lake.bootstrap_sql`)
- `x-duckbox-init-sql` (optional)
- handshake: username=key (optional; spec still required in trusted mode)

`GetCatalogs` / `GetDbSchemas` / `GetTables` / `GetSqlInfo` are answered **by the sandbox** and filtered to spec-whitelisted tables/columns.

Python (ADBC):

```bash
python3 -m venv .venv
.venv/bin/pip install -r examples/python/requirements.txt
# terminal 1
./build/duckbox serve --daemon ./daemons/memory.yaml
# terminal 2
.venv/bin/python examples/python/query.py \
  --url grpc://127.0.0.1:4747 \
  --spec ./policies/memory/analyst.yaml \
  --key tenant_21:user_sergio
```

Prepared with parameters: `--sql 'SELECT id FROM deals WHERE id = ?' --params 1`.

## Build

Linux (CI): `bash scripts/install_arrow.sh` (Apache Arrow APT, including Flight SQL).  
macOS: `brew install apache-arrow openssl cmake` (recent formulae enable Flight SQL).

```bash
bash scripts/fetch_deps.sh          # DuckDB 1.5.6 headers + static libs
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
.venv/bin/python examples/python/isolation_check.py --spec ./policies/ducklake/analyst.yaml
```

CI job `ducklake-e2e` runs this on GitHub Actions (Docker available there). This VM has no Docker, so local compose is the laptop/CI path. **RustFS** is the emulator in `docker-compose.yml` to match the product S3 target; if the image is unusable, MinIO is the fallback (same path-style endpoint).

Reads use DuckDB httpfs path-style S3. Conditional S3 (If-Match / If-None-Match) is for **leases/writes**, not for these reads. `S3ConditionalLeaseManager` is the v1 interface; this draft uses `SingleNodeLeaseManager` and probes the lease endpoint when configured.

## Layout

| Path | What |
| --- | --- |
| `daemons/` | Control-plane YAML (listen, limits, optional lease) |
| `policies/` | Sandbox specs (lake + tables + key + functions) |
| `server/` | C++ daemon + enforcement |
| `examples/python/` | ADBC Flight SQL client |
| `test/` | AST, isolation, handles, initSQL, policy-hash cache |

## Stubbed

- JWT signature/claims (`token` mode)
- Multi-node S3 leases with fencing epoch (`S3ConditionalLeaseManager`)
- Per-process cgroup/seccomp
