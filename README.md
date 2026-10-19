# duckbox

Draft of a per-tenant sandboxed DuckDB query service over a shared DuckLake (Parquet on S3, catalog in Postgres or a DuckDB file). Incoming SQL is treated as untrusted. A request carries a tenant key (for example `tenant_21:user_sergio`) and a policy name. duckbox validates the SQL, rewrites it so tenant and mandatory filters are applied, runs it in that tenant key's DuckDB instance, and returns Arrow.

This is **not** a DuckDB fork. DuckDB internals (parser, planner, settings) are isolated behind `server/include/duckbox/duckdb_layer.hpp` for a later 2.0 upgrade.

## Protocol

**HTTP POST + Arrow IPC stream**, not Arrow Flight and not a client `ATTACH` extension.

Flight would need Apache Arrow C++ / gRPC on the server. A DuckDB client extension would need the extension build template. DuckDB 1.5.6 already writes Arrow IPC via `COPY … TO 'file.arrows' (FORMAT ARROWS)`, and Python already reads that with `pyarrow.ipc`. That is the cheapest path that still returns Arrow. `proto/` documents the HTTP API. `extension/` is a placeholder for a later `LOAD duckbox` client.

## DuckDB version

**v1.5.6** (requested; the C++ amalgamation, static libs, and `src/include` headers from that tag).

## Layout

| Path | What |
| --- | --- |
| `server/` | C++ binary `duckbox` (parser, rewrite, plan guard, HTTP) |
| `cli/` | notes for the same binary's `serve` / `query` subcommands |
| `proto/` | HTTP request/response |
| `extension/` | future client extension (not in this draft) |
| `policies/` | YAML policies (`memory/` for local tests, `ducklake/` for compose) |
| `examples/python/` | `pyarrow` client |
| `test/` | bypass + tenant-isolation tests |
| `docker-compose.yml` | RustFS (S3) + Postgres (DuckLake catalog) |

## Enforcement

1. **AST (DuckDB parser only, no string rewriting of user SQL)**  
   Single `SELECT`. No table functions / replacement scans (`FROM 's3://…'`). Table allowlist (including qualified names) with CTE names scoped correctly. Function allowlist (including window/aggregate). Mandatory filters are parsed from policy YAML (`:tenant_id` becomes a DuckDB named parameter) and attached by wrapping each allowlisted base table in a subquery.
2. **Logical plan (independent optimizer extension)**  
   After DuckDB's optimizer, refuse any scan of a tenant table that lacks `tenant_id = <this tenant>` and refuse known file-scan table functions.

Each tenant key gets its own in-process DuckDB instance with `memory_limit` / `threads` from the policy, then `lock_configuration=true`. The first query for a key also `INSTALL nanoarrow FROM community` (needs network once) so results can be written as Arrow IPC. Per-process cgroup/seccomp isolation is future work.

Tenant key form: `tenant_<id>:<user>` or `<id>:<user>`. `:tenant_id` binds to the numeric id (never interpolated into user SQL).

## Stubbed / not in this draft

- **Auth `token`**: any non-empty `Authorization: Bearer …` is accepted; JWT signature/claims are not verified. `trusted` accepts `X-Duckbox-Key` directly. mTLS / shared secret: TODO.
- **Lease/router**: `server/include/duckbox/lease.hpp` always grants local ownership. Multi-node S3 conditional writes and fencing epoch are not implemented.
- Client DuckDB extension / Arrow Flight.

## Run locally (memory catalog, no Docker)

Exact commands from the repo root:

```bash
# 1. C++ toolchain: cmake, g++, curl, unzip, python3
bash scripts/fetch_deps.sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++
cmake --build build --parallel
./build/duckbox_tests

# 2. Server
./build/duckbox serve --policies ./policies/memory --listen 127.0.0.1:4747

# 3. In another shell: Python client (tenant 21 must not see tenant 22)
python3 -m venv .venv
.venv/bin/pip install -r examples/python/requirements.txt
.venv/bin/python examples/python/query.py \
  --url http://127.0.0.1:4747 \
  --key tenant_21:user_sergio \
  --policy analyst \
  --sql 'SELECT id, title, amount FROM deals ORDER BY id'
```

Expected ids: `[1]` (`alpha deal` only). Tenant 22:

```bash
.venv/bin/python examples/python/query.py \
  --key tenant_22:user_kim \
  --sql 'SELECT id, title, amount FROM deals ORDER BY id'
```

Expected ids: `[3, 4]`.

CLI equivalent (raw Arrow bytes on stdout):

```bash
./build/duckbox query --url http://127.0.0.1:4747 \
  --key tenant_21:user_sergio --policy analyst \
  --sql 'SELECT id, title, amount FROM deals'
```

Or: `make test` then `make serve`.

## Run locally (DuckLake: Postgres + RustFS)

No cloud CLIs. Compose is local-only:

```bash
docker compose up -d
.venv/bin/pip install -r examples/python/requirements.txt   # includes duckdb 1.5.6 and boto3
.venv/bin/python scripts/seed_ducklake.py
./build/duckbox serve --policies ./policies/ducklake --listen 127.0.0.1:4747
.venv/bin/python examples/python/query.py --key tenant_21:user_sergio --policy analyst
```

`scripts/seed_ducklake.py` creates bucket `duckbox-lake`, attaches DuckLake (`ducklake:postgres:…`, `DATA_PATH 's3://duckbox-lake/data/'`), and inserts four `deals` rows for tenants 21 and 22.

## Policy YAML

See `policies/memory/analyst.yaml` and `policies/ducklake/analyst.yaml`. Fields:

- `resources`: `memory_limit`, `threads`, `query_timeout_ms`, `max_result_rows`
- `auth.mode`: `trusted` | `token`
- `lake`: `kind` (`memory` | `ducklake`), `catalog`, `data_path`, `read_only`, optional `s3`
- `tables.<name>.columns`, `tables.<name>.filters` (bound params, not concatenated into user SQL)
- `functions` allowlist, `deny_table_functions: true`

## Tests / CI

```bash
make test
```

GitHub Actions (`.github/workflows/ci.yml`) fetches DuckDB 1.5.6 static libs, builds, and runs the same enforcement tests (bypass attempts rejected; tenant A never sees tenant B).
