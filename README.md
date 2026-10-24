# duckbox

A **deny-by-default SQL sandbox** for untrusted, often AI-generated, SQL over a shared DuckLake (Parquet on S3, catalog in Postgres or a DuckDB file). In the spirit of smolvm/microVM CLIs: a sandbox sees **nothing** except what its spec hands it.

This is **not** a DuckDB fork. Parser/planner/settings stay behind `server/src/common/duckdb_layer.hpp`. Development is DuckDB **2.0.0**.

## Actors and trust model

1. **AI agent** (untrusted). Generates SQL and runs it via ADBC / Flight SQL on an **existing** sandbox. It cannot create sandboxes and cannot `CREATE VIEW`.
2. **SaaS** (trusted caller). Creates, updates, expires, and deletes sandboxes through its own harness (CRUD is authenticated and scoped by key prefix). It supplies memory-lake `lake.bootstrap_sql` (trusted seed). Duckbox statement-type-checks that SQL (fail closed): `CREATE TABLE` / `SCHEMA` (including `CREATE TABLE AS SELECT`) and `INSERT` only. `CREATE VIEW` / `MACRO` / `FUNCTION` / `TYPE` / `INDEX`, `ATTACH`, and `SET` are rejected so bootstrap cannot expose unwrapped objects tenants can query.
3. **Sandbox**. Exposes spec-allowlisted tables and scalar functions. **Tenant isolation is the SQL rewriter only.** The spec allowlists `catalog.schema.table` (unqualified names default to the lake alias and `main`) and names each relation's tenant column; the rewriter wraps those exact allowlisted appearances so `tenant_col = <tenant from the sandbox key>` is present with the bound key value (never a spec literal). A query that names a different catalog or schema (`staging.deals` when the allowlist is `memory.main.deals`) is rejected — it is not wrapped as if it were the allowlisted table. The wrap applies at the top level, in CTE bodies (including chained and recursive `WITH`), in subqueries, in joins, and in set operations. Agent `SELECT` may use `WITH`. A CTE name is visible to later siblings and the outer query; a non-recursive body does not see its own name (it resolves to the catalog), and a recursive CTE sees it only in the recursive arm. Qualified names (`catalog.schema.table`) never match a CTE. A CTE that reuses an allowlisted or non-allowlisted table name therefore cannot skip the allowlist or the tenant wrap on the real table.

The rewriter does **not** expand macros. Spec validation and warmup reject an allowlisted name when the DuckDB catalog has a hit that is not a window function — `MACRO_ENTRY`, `TABLE_MACRO_ENTRY`, and native aggregates, scalars, and table functions. That is the 1.5.6 contract: names 1.5.6 treated as macros (`string_agg`, `list`, `approx_count_distinct`, `concat`, `regexp_matches`, `read_csv`, `duckdb_tables`, `md5`, `pg_get_viewdef`, …) are still rejected with `macro is not allowlisted: <name>`, even when DuckDB 2.0 types them as native functions. Window functions (`row_number`, `rank`, `dense_rank`, `ntile`, `percent_rank`, `cume_dist`, …) are the exception: DuckDB 2.0 may return them from the same catalog scan as `WINDOW_FUNCTION_ENTRY`, and they may be allowlisted. The only other exceptions are the tested aliases `count`, `count_star`, `sum`, `avg`, `min`, `max`, `lower`, `upper`, `length`, `coalesce`, `round`, `abs`, and only when that catalog entry is `internal` and lives in the `system` catalog. A user, extension, or lake `MACRO_ENTRY` with the same name is rejected. Spec validation uses a throwaway DuckDB catalog scan; warmup looks up each allowlisted name with the DuckDB catalog API (not `FROM duckdb_functions()`, which a temp macro can shadow). Table-function names on the always-denied list (`read_csv`, `duckdb_tables`, `postgres_query`, …) are also rejected at static validation. `AT (VERSION => n)` time travel is wrapped, but it returns that tenant's older versions — including rows since marked `_deleted`. There is no plan guard walking DuckDB's logical plan.

**Lake views** belong in the lake. Define or materialize them with dbt, Bruin, or a similar tool so the view (or table) has a tenant column. Then list that relation in the spec like any other table: columns, `tenant_column`, optional `catalog`/`schema`, and filters such as `tenant_id = :tenant_id`. The rewriter wraps the exact allowlisted `catalog.schema.table`. Duckbox does not create views at warmup. A name that is not allowlisted is rejected by the allowlist. `CreateSandbox` / `UpdateSandbox` return the registry record only (no `warnings` field). Flight SQL `GetTables` lists allowlisted relations as type `TABLE`.

### Migration (breaking): removed spec keys, daemon keys, CLI, and metric

**Spec YAML** — rejected as unknown keys (load / `CreateSandbox` / `UpdateSandbox` error):

- `init_sql` at the spec root. Delete it. Put views in the lake (dbt/Bruin), keep a tenant column, and allowlist the relation like a table.
- `tables.<name>.authorized_view`. Delete it. List the lake relation like any other table (`columns`, `tenant_column`, filters, optional `catalog`/`schema`).

**Daemon YAML** — rejected as unknown keys (daemon load error):

- `limits.init_sql_timeout_ms`. Remove it. There is no init-SQL timeout because spec-level `init_sql` is gone. Memory `lake.bootstrap_sql` runs as part of warmup (`duckbox_sandbox_warmup_seconds`).
- `allowed_init_settings`. This was a C++ default set, not a typical YAML key. If it appears at the daemon root or under `limits`, load fails. Remove it. The setting no longer exists; warmup does not apply a special init-SQL settings allowlist.

**CLI** — parse error (unknown option):

- `--init-sql`. Remove the flag. Seed a memory lake with `lake.bootstrap_sql` (or the `lake.init_sql` alias) in the spec. `duckbox run` takes `--sql` for the one-shot query only.

**Metrics / dashboards** — series no longer exported (scrapers ignore the missing name; dashboards and alerts go stale):

- `duckbox_init_sql_seconds`. Drop it from dashboards and alerts. Use `duckbox_sandbox_warmup_seconds` if you were tracking seed/warmup duration.

`lake.bootstrap_sql` (and the `lake.init_sql` alias) is **memory-lake seed data only**: `CREATE TABLE`, `CREATE SCHEMA`, and `INSERT`, including `CREATE TABLE AS SELECT`. `CREATE VIEW`, `CREATE MACRO`, and other catalog objects tenants can query are rejected at static validation (create/update) so bootstrap cannot expose unwrapped wrappers around base tables. On DuckLake, `lake.bootstrap_sql` is a validation error — the lake already has its catalog; the field is no longer silently ignored.

**Trusted SaaS input.** `lake.bootstrap_sql` is written by the SaaS, not by the agent. It runs during warmup **before** `enable_external_access=false`. `CREATE TABLE AS SELECT` and `INSERT … SELECT` may therefore read files (`read_csv`, `query()`, and similar). That is intentional for seeding. Agent queries are still rewriter-wrapped (`tenant_col =` the bound key) and cannot `COPY` / `read_*` except for prefixes the spec already declared.

Allowed external locations are derived from the spec: `lake.data_path`, each `attachments` entry, and rarely `extra_paths` for a prefix with no attachment. Those prefixes are applied to DuckDB `allowed_paths` / `allowed_directories` **before** external access is disabled. Anything undeclared fails. Agent SQL still cannot `COPY` / `read_*` except for prefixes the spec already declared.

```yaml
attachments:
  extra_prefix:
    location: s3://duckbox-lake/extra/   # optional credential: env:NAME
# extra_paths: [/rarely/needed]         # only when there is no attachment
```

## Run everything locally (macOS and Linux)

Copy-paste from the repo root. CI job `readme-runbook` runs the DuckLake path (compose → seed → serve → CLI create → quickstart). Job `enforcement` runs the test commands. Job `macos-arm64` builds with AppleClang and runs unit + guardrail tests (no Docker).

### Prerequisites

- Docker Engine with Compose v2 (Postgres + RustFS)
- Python 3.10+
- CMake 3.20+ and a C++17 compiler (`g++` on Linux, Apple Clang or `g++` on macOS)
- **Linux:** `sudo` for the Arrow APT source on Ubuntu 24.04 (noble) or 22.04 (jammy). GitHub Actions rewrites the runner's Ubuntu mirrors with `archive.ubuntu.com` / `security.ubuntu.com` at priority 1 and Azure at priority 9. A local run does not, unless you set `DUCKBOX_APT_MIRRORS=1`.
- **macOS:** Homebrew

### 1. C++ dependencies and Arrow

```bash
# Linux — Apache APT Arrow 26.0.0 (noble/jammy). CI sets Ubuntu mirror priorities; local does not unless DUCKBOX_APT_MIRRORS=1.
bash scripts/install_arrow.sh

# macOS — Homebrew Arrow (Flight SQL) + aws-sdk-cpp + openssl@4
# Do not mix vcpkg OpenSSL 3.5 with Homebrew openssl@4 in one binary (heap abort).
brew install apache-arrow aws-sdk-cpp openssl@4 cmake
```

```bash
bash scripts/fetch_deps.sh          # DuckDB 2.0.0 headers + static libs + yaml-cpp + nlohmann/json + jwt-cpp + CLI11 + cppcodec

# Linux only — AWS SDK for C++ (S3, vcpkg). First run takes several minutes.
bash scripts/install_aws_sdk.sh
```

### 2. Build

```bash
# Linux
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++
cmake --build build --parallel
# equivalent: make build CXX=g++

# macOS — omit -DCMAKE_CXX_COMPILER=g++; AppleClang is the default
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

### 3. Tests (no Docker)

```bash
ctest --test-dir build --output-on-failure
make validate
```

### 4. DuckLake: Postgres + RustFS, seed, serve, CLI, quickstart

```bash
docker compose up -d --wait

python3 -m venv .venv
.venv/bin/pip install -r examples/python/requirements.txt

# Set these in the terminal that runs `serve` (the daemon reads them at warmup).
# The CLI / quickstart terminal does not need them.
export DUCKBOX_S3_KEY=rustfsadmin DUCKBOX_S3_SECRET=rustfsadmin
export DUCKBOX_HANDLE_SECRET=duckbox-dev-secret
export DUCKBOX_LAKE_CATALOG='ducklake:postgres:dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox'

.venv/bin/python scripts/seed_ducklake.py

./build/duckbox serve --daemon ./daemons/ducklake.yaml --listen 127.0.0.1:4747
```

In another terminal (the CLI does not need those env vars; they belong on the `serve` process):

```bash
./build/duckbox sandbox create --url grpc://127.0.0.1:4747 \
  --spec ./policies/ducklake/analyst.yaml \
  --id acme-analyst --key tenant_21:user_sergio

.venv/bin/python examples/python/quickstart.py
# or open examples/python/quickstart.ipynb  (same walkthrough as quickstart.py)
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

`lake.bootstrap_sql` file paths are **relative to the spec file**, not the working directory (`policies/memory/analyst.yaml` uses `../../examples/sql/memory_init.sql`). Inlined SQL is also accepted. The daemon never re-reads that host path at warmup — LoadSpecFile inlines the file first. That SQL is trusted SaaS seed input (it can `read_csv` / `query()` via `CREATE TABLE AS SELECT` or `INSERT … SELECT` before external access is disabled). Agent queries stay tenant-wrapped. On DuckLake the field is a validation error.

**RustFS** is the only S3-compatible store in `docker-compose.yml` (pinned `rustfs/rustfs:1.0.3`). The README runbook, STS suite, and multi-node e2e all use it at `127.0.0.1:9000`. Reads use DuckDB httpfs path-style S3. Conditional S3 (If-Match / If-None-Match) is for **leases and the named-sandbox registry**, not for lake reads — that client is **aws-sdk-cpp S3Client** (vcpkg: S3, STS, identity-management) with endpoint override and path-style addressing. Arrow `S3FileSystem` has no conditional-write headers, so it is not used for the control plane. Tests inject an in-memory `S3ControlClient`.

## Named sandboxes

A sandbox is a **named resource** with a stable id (`acme-analyst`), like a VM name. That replaces `(key, hash)` identity and the per-key sandbox cap.

The **daemon is a control plane**. It has **no data access**. It owns:

- the Flight SQL listener
- the named-sandbox **registry** (S3 next to leases, or in-memory)
- routing of calls to warm instances
- S3 **ownership leases** (its only credential is the lease/registry prefix)

**Lake attach, attachments, and credentials belong on the sandbox definition** and are used only by that sandbox’s DuckDB instance, at create/warmup (before `lock_configuration`). The registry stores **credential references only** (`env:DUCKBOX_S3_KEY`, `file:/run/secrets/x`) — never values. Values are resolved inside the sandbox at each warmup. Refs are checked syntactically at create; every env/file ref and every `profile` / `role_arn` must be on the node's `lake_allow` lists (fail closed). Resolvability is checked at warmup. Values are never logged.

Lake S3 supports two modes: static keys, or DuckDB `PROVIDER credential_chain` (refresh via profile / assume-role / the default chain, including IRSA web identity). Full examples and the AWS-only (no IAM user) path: [docs/lake-s3-credentials.md](docs/lake-s3-credentials.md).

Mode 1 — static keys (refs only; every env name must appear on `lake_allow.secret_refs`):

```yaml
lake:
  s3:
    access_key_env: DUCKBOX_S3_KEY
    secret_key_env: DUCKBOX_S3_SECRET
    region: us-east-1
```

Mode 2 — credential chain (refreshable; no IAM user). List each profile and role on the daemon, or set `allow_default_credential_chain` for IRSA / the default chain. Do not use `*`:

```yaml
# spec
lake:
  extensions: [httpfs, postgres, ducklake, aws]
  s3:
    provider: credential_chain
    profile: lake-readonly
    # role_arn: arn:aws:iam::123456789012:role/duckbox-lake  # not with profile
    region: us-east-1
    use_ssl: true
    url_style: vhost
# daemon
lake_allow:
  s3_endpoints: ["s3.amazonaws.com"]
  secret_refs: ["env:DUCKBOX_LAKE_CATALOG"]
  aws_profiles: [lake-readonly]
  role_arns: ["arn:aws:iam::123456789012:role/duckbox-lake"]
```

A definition is: **id**, **key**, **policy** (with a bounded `policy_class` name), lake, attachments, credential refs, limits.

Trusted-caller CRUD (Flight SQL `DoAction`, mirrored as CLI):

```bash
duckbox sandbox create|get|update|delete|list --url grpc://127.0.0.1:4747 --spec FILE [--id ID] [--key KEY]
```

Create on an existing id with different content is rejected (409). `UpdateSandbox` explicitly bumps **version** (hash of the deny-by-default contract is the content identity; S3 keeps immutable `sandboxes/<id>/v<N>.json` plus `current.json` with If-None-Match / If-Match). Warm instances of versions older than N-1 drain/passivate; N-1 stays warm when `handles.stale_version_grace` is >0. Delete writes a tombstone. Any node can load a definition after failover.

Queries send **id + SQL** (`x-duckbox-sandbox`). The bound key comes from the definition; send `x-duckbox-key` only when the spec’s `auth.key` extractor needs a per-query key. The caller must be authorized for the sandbox’s key (`auth.callers` maps identities to key globs). Empty `auth.callers` is allow-all only with `auth.allow_insecure_dev`; production YAML must list callers. Example daemons load `handle_secret` from `DUCKBOX_HANDLE_SECRET` (the well-known `duckbox-dev-secret` is refused unless that flag is set).

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

1. **Static** (create/update): schema, types, key extractors, filters, `:vars`, function names, secret-ref syntax, lake S3 credential mode, `lake_allow` (secret refs, profiles, roles; fail closed), `handles.stale_version_grace` (duration, cap 1h). Table names, column names, and `tenant_column` must be unquoted ASCII identifiers (`[A-Za-z_][A-Za-z0-9_]*`, not a SQL keyword). **All** errors, with field paths (`tables.deals.filters[0]: …`). Tables are keyed by `catalog.schema.name` after lake defaults; an exact duplicate is rejected. Memory `lake.bootstrap_sql` is checked with `CheckBootstrapSql` here (not only at warmup / `duckbox validate`): only `CREATE TABLE` / `CREATE SCHEMA` / `INSERT`. DuckLake `lake.bootstrap_sql` is a field-path error (`only valid when lake.kind=memory`). Every allowlisted name the catalog resolves as a macro, table macro, aggregate, scalar, or table function is rejected (`macro is not allowlisted: <name>`) unless it is on the tested exception list (`count`, `count_star`, `sum`, `avg`, `min`, `max`, `lower`, `upper`, `length`, `coalesce`, `round`, `abs`) and that catalog entry is internal in the `system` catalog. That restores the 1.5.6 reject for names such as `string_agg`, `concat`, `read_csv`, and `duckdb_tables`. Window functions (`row_number`, `rank`, …) are not rejected as macros and may be allowlisted. Table-function names on the always-denied list are also rejected at static validation.
2. **Lake** (inside the sandbox on first warmup for that **(id, version)**): whitelisted tables/columns exist. Cached on the registry record so later warmups skip it. `duckbox validate` uses a throwaway sandbox.

Daemon startup validates **only** daemon config (listen, limits, optional lease prefix reachability / If-None-Match probe). Not the lake.

### Sandbox lifecycle

Runtime instances are keyed by **id@version**. Idle instances **passivate** (DuckDB freed); **warmup** recreates the instance, resolves secret refs, attaches the spec’s lake, then `lock_configuration`. Global `max_sandboxes` still applies; there is no per-key cap. Spec `lifecycle.idle_timeout` overrides the daemon default (capped by `limits.max_idle_timeout`). Spec `lifecycle.ttl` / `expires_at` tombstone the named definition when due.

DuckDB `allowed_directories`/`allowed_paths` are derived from `lake.data_path`, path-like `attachments`, and optional `extra_paths` before external access is disabled (prefixes are canonicalized: no `..`, no extra `//`, no query string, trailing slash). Agent SQL cannot `COPY`/`read_*` except for prefixes the spec already declared. `lake.bootstrap_sql` (memory lakes) is trusted SaaS seed SQL — `CREATE TABLE` / `CREATE SCHEMA` / `INSERT` only — and cannot create views, macros, or other objects tenants can query. Because it runs before `enable_external_access=false`, `CREATE TABLE AS SELECT` / `INSERT … SELECT` may read files (`read_csv`, `query()`). Agent queries remain rewriter-wrapped. On DuckLake the field is rejected.

Spec table and column names are ASCII-only unquoted identifiers. A DuckLake table or column whose real name is unicode or quoted cannot be listed in the spec.

### Metrics

`GET /metrics` (Prometheus text). Query histogram `duckbox_query_duration_seconds{policy,outcome,cold,node}` plus rejections, limits, result rows/bytes, sandbox lifecycle, policy-validation cache, and lease/router series (`duckbox_route_decisions_total`, `duckbox_node_lease_*`, `duckbox_node_healthy`, `duckbox_proxy_requests_total`, `duckbox_proxy_errors_total`, `duckbox_proxy_seconds`). Histogram buckets: 5ms … 120s for queries; 10ms … 30s for warmup. `duckbox_node_healthy` is 1 while the published node lease is live. A heartbeat failure retries until that expiry; then the node self-fences (interrupt, passivate, exit 3) so a supervisor restarts it. Do not stay alive unhealthy.

## Arrow Flight SQL

v1 wire protocol. With production auth, JDBC/ADBC cannot authenticate until https://github.com/paulosuzart/duckbox/issues/16 is fixed (they do not send `auth-token-bin`); they work with `auth.allow_insecure_dev`. Headers:

- `x-duckbox-sandbox` — named sandbox id (required for queries)
- `x-duckbox-key` — optional; definition key is used otherwise
- `x-duckbox-caller` — trusted caller identity; used only when `auth.allow_insecure_dev` is set and no bearer/JWT is configured
- `Authorization: Bearer` — static `auth.bearer_secrets` or HS256 JWT (`auth.jwt_secret`). `alg` must be `"HS256"` exactly (not a substring); `exp` is required (`nbf` optional, 60s leeway). Unsigned tokens are rejected. JDBC/ADBC send this header but not `auth-token-bin`, so production auth still rejects them (same issue).

Public CRUD actions: `CreateSandbox`, `GetSandbox`, `UpdateSandbox`, `DeleteSandbox`, `ListSandboxes`, `ExpireSandbox`. Create/Update body is spec YAML; ListSandboxes YAML body filters `id_prefix`, `key_prefix`, `policy_class`, `state` (`warm`|`passive`|`defined`) plus `limit`/`offset`. Each list item is a summary (`id`, `key`, `version`, `policy_class`, `state`, `owner`, `created_at`, `updated_at`, `last_used_at`, `expires_at`) — not the full spec. `owner` is the live lease holder. `ExpireSandbox` passivates the instance and invalidates prepared handles; the definition stays. Operator actions `DrainNode` / `NodeStatus` (`duckbox node drain`) are served only on the **internal** listener, restricted to `auth.operators` (deny by default; sandbox CRUD callers are not operators). Peer proxy calls use `auth.peer_secret_ref` (`env:` / `file:`). Never expose `internal_listen` publicly.

Optional spec `lifecycle.idle_timeout` passivates an idle instance (daemon `limits.idle_timeout` / `idle_evict_ms` is the default; `limits.max_idle_timeout` caps it). `lifecycle.ttl` / `lifecycle.expires_at` tombstone the definition.

`GetCatalogs` / `GetDbSchemas` / `GetTables` / `GetSqlInfo` are answered **by the sandbox** and filtered to spec-whitelisted tables/columns.

**Offset alignment (third-party clients).** Flight gRPC zero-copy can deliver `StringArray` / `BinaryArray` offset buffers misaligned. The server does **not** guarantee 4/8-byte-aligned offsets on the wire. Query `DoGet` streams decoded batches as-is (no per-buffer re-encode). pyarrow, ADBC, and JDBC readers must enable alignment on their IPC reader:

```python
import pyarrow.flight as flight
import pyarrow.ipc as ipc

opt = flight.FlightCallOptions(
    headers=headers,
    read_options=ipc.IpcReadOptions(
        ensure_alignment=ipc.Alignment.DataTypeSpecific
    ),
)
```

Without that option, ARM64 clients can SIGSEGV in `StringArray::GetView`. Duckbox's own C++ Flight client (peer proxy and schema tests) sets `IpcReadOptions::ensure_alignment`. ADBC / JDBC should turn on the equivalent reader option when one is exposed.

Advertised Flight SQL schemas (`GetFlightInfo`, `GetSchema`, prepared `dataset_schema`, and `GetTables` with `include_schema`) use the same Arrow conversion as DoGet batches. Clients that cached the previous mapping will see type changes — for example `count(*)` is `int64` (BIGINT), not `int32`. Nested `LIST` / `STRUCT` / `MAP` columns keep those Arrow types instead of collapsing to `utf8`. `GetTables include_schema` describes each allowlisted table through the rewriter (`DescribeRewrittenArrow`); there is no un-rewritten catalog fallback.

Python is Arrow Flight SQL via ADBC. Use `examples/python/quickstart.ipynb` (or `quickstart.py`) after the daemon is up. `create_sandbox()` / `connect(sandbox=...)` send the id header for you.

The registry is `SandboxRegistry` (S3 impl against RustFS in CI, in-memory impl for tests). With a `lease` endpoint, `S3ConditionalLeaseManager` owns sandboxes via If-None-Match / If-Match and a fencing epoch; memory daemons keep `SingleNodeLeaseManager`. Multi-node add/drain/crash: [docs/multi-node.md](docs/multi-node.md). CRUD also includes `DrainNode` (`duckbox node drain`).

## Layout

| Path | What |
| --- | --- |
| `daemons/` | Control-plane YAML (listen, limits, optional lease) |
| `policies/` | Sandbox specs (lake + tables + key + functions) |
| `server/src/<area>/` | C++ node + enforcement, headers next to sources |
| `examples/python/` | Quickstart notebook/script, `duckbox_client`, CLI utility |
| `test/` | CTest suites: `unit`, `guardrails` (YAML SQL corpus), `integration` |

## Stubbed

- mTLS caller certs (bearer secrets and HS256 JWT are implemented)
- Multi-node S3 leases with fencing epoch (`S3ConditionalLeaseManager`)
- Per-process cgroup/seccomp
