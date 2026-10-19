# duckbox

A **deny-by-default SQL sandbox** for untrusted, often AI-generated, SQL over a shared DuckLake (Parquet on S3, catalog in Postgres or a DuckDB file). In the spirit of smolvm/microVM CLIs: a sandbox sees **nothing** except what its spec hands it.

This is **not** a DuckDB fork. Parser/planner/settings stay behind `server/include/duckbox/duckdb_layer.hpp` for a later DuckDB 2.0 upgrade. Development is DuckDB **1.5.6**.

## Actors and trust model

1. **AI agent** (untrusted). Generates SQL and runs it via ADBC / Flight SQL on an **existing** sandbox. It cannot create sandboxes, cannot run initSQL, and cannot `CREATE VIEW`.
2. **SaaS** (trusted caller). Creates, updates, expires, and deletes sandboxes through its own harness (CRUD is authenticated and scoped by key prefix). It supplies **initSQL**. Duckbox does not AST-check that SQL.
3. **Sandbox**. Exposes spec-whitelisted tables/views and scalar functions. Agent SQL is fully guarded (AST + plan): only those names, plus tenant filters on **direct table** access.

**initSQL** is trusted. It runs at warmup **before** `enable_external_access=false` and `lock_configuration`. The agent never executes in that phase. Views (and macros) created there are **authorized views** (BigQuery-style): if the spec exposes the view, the plan guard treats that view's expansion as opaque (no table-function/allowlist rejection *inside* it) and still checks everything the agent wrote around it. The same function or non-allowlisted table used directly by the agent is denied.

**Authorized views bypass tenant filters.** The rewriter does not wrap them in `WHERE tenant_id = :tenant_id`. The SaaS must embed the tenant predicate (a key variable such as `:tenant_id`) in the view body. Create/Update return a `warnings` array and write the same text to the audit log when an authorized view's body does not reference a key variable.

Allowed external locations are derived from the spec — not parsed from initSQL: `lake.data_path`, each `attachments` entry, and rarely `extra_paths` for a prefix with no attachment. Those prefixes are applied to DuckDB `allowed_paths` / `allowed_directories` **before** external access is disabled. Authorized views may read anything under the declared lake/attachments using the sandbox's resolved credentials. Anything undeclared fails. initSQL is written to the audit log with secrets redacted.

```yaml
attachments:
  authorized_parquet:
    location: s3://duckbox-lake/authorized/   # optional credential: env:NAME
# extra_paths: [/rarely/needed]              # only when there is no attachment
```

## Run everything locally (macOS and Linux)

Copy-paste from the repo root. CI job `readme-runbook` runs the DuckLake path (compose → seed → serve → CLI create → quickstart). Job `enforcement` runs the test commands. Job `macos-arm64` builds with AppleClang and runs unit tests (no Docker).

### Prerequisites

- Docker Engine with Compose v2 (Postgres + RustFS)
- Python 3.10+
- CMake 3.20+ and a C++17 compiler (`g++` on Linux, Apple Clang or `g++` on macOS)
- **Linux:** `sudo` for the Arrow APT source
- **macOS:** Homebrew

### 1. C++ dependencies and Arrow

```bash
# Linux
bash scripts/install_arrow.sh

# macOS (Homebrew formulae enable Flight SQL)
brew install apache-arrow openssl cmake
```

```bash
bash scripts/fetch_deps.sh          # DuckDB 1.5.6 headers + static libs + yaml-cpp + nlohmann/json + jwt-cpp + CLI11 + cppcodec
bash scripts/install_aws_sdk.sh     # AWS SDK for C++ (S3 only, vcpkg) — registry/lease conditional PUTs
                                    # First run takes several minutes (vcpkg builds aws-sdk-cpp S3).
```

On **macOS 26+** (SDK 27 headers), first-time `install_aws_sdk.sh` uses overlay triplets `cmake/vcpkg-triplets/{arm64,x64}-osx.cmake`. Those add `-Wno-error=unguarded-availability-new` and pass `-DHAVE_PIPE2=OFF` so vcpkg curl does not compile in a `pipe2` call (SDK 27 marks it 27.0+; calling it on 26.x aborts). Do **not** raise `MACOSX_DEPLOYMENT_TARGET` to 27 — that binary would not run on 26.x. The extra flag is a no-op on older SDKs. AppleClang only: do not set `CC=gcc` / `CXX=g++` on macOS. If a previous run failed while building curl, or unit tests abort in the AWS S3 client:

```bash
rm -rf .deps/vcpkg/buildtrees/curl .deps/vcpkg_installed
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
.venv/bin/python examples/python/authorized_views_e2e.py
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

`lake.bootstrap_sql` file paths are **relative to the spec file**, not the working directory (`policies/memory/analyst.yaml` uses `../../examples/sql/memory_init.sql`). Inlined SQL is also accepted. The daemon never re-reads that host path at warmup — LoadSpecFile inlines the file first.

**RustFS** is the emulator in `docker-compose.yml` to match the product S3 target; if the image is unusable, MinIO is the fallback (same path-style endpoint). Reads use DuckDB httpfs path-style S3. Conditional S3 (If-Match / If-None-Match) is for **leases and the named-sandbox registry**, not for lake reads — that client is **aws-sdk-cpp S3Client** (vcpkg, S3 component only) with endpoint override and path-style addressing. Arrow `S3FileSystem` has no conditional-write headers, so it is not used for the control plane. Tests inject an in-memory `S3ControlClient`.

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

1. **Static** (create/update): schema, types, key extractors, filters, `:vars`, function names, secret-ref syntax, `handles.stale_version_grace` (duration, cap 1h). **All** errors, with field paths (`tables.deals.filters[0]: …`). initSQL is not AST-validated (trusted SaaS input).
2. **Lake** (inside the sandbox on first warmup for that **(id, version)**): whitelisted tables/columns exist. Cached on the registry record so later warmups skip it. `duckbox validate` uses a throwaway sandbox.

Daemon startup validates **only** daemon config (listen, limits, optional lease prefix reachability / If-None-Match probe). Not the lake.

### Sandbox lifecycle

Runtime instances are keyed by **id@version**. Idle instances **passivate** (DuckDB freed); **warmup** recreates the instance, resolves secret refs, attaches the spec’s lake, **reruns initSQL**, then `lock_configuration`. Global `max_sandboxes` still applies; there is no per-key cap. Spec `lifecycle.idle_timeout` overrides the daemon default (capped by `limits.max_idle_timeout`). Spec `lifecycle.ttl` / `expires_at` tombstone the named definition when due.

**initSQL**: trusted SaaS SQL, rerun on every warmup, then `enable_external_access=false` and `lock_configuration`. Objects it creates are visible to agent SQL **only if the spec lists them**. Exposed views are authorized (expansion opaque in the plan guard by catalog-entry oid / table-function operator; agent-written SQL around them is still checked). Authorized views are **not** wrapped with spec tenant filters — put `:tenant_id` (or another key variable) in the view itself. DuckDB `allowed_directories`/`allowed_paths` are derived from `lake.data_path`, path-like `attachments`, and optional `extra_paths` before external access is disabled (prefixes are canonicalized: no `..`, no extra `//`, no query string, trailing slash). Agent SQL cannot `COPY`/`read_*` except through those views, and only for prefixes the spec already declared.

### Metrics

`GET /metrics` (Prometheus text). Query histogram `duckbox_query_duration_seconds{policy,outcome,cold,node}` plus rejections, limits, result rows/bytes, sandbox lifecycle, policy-validation cache, and lease/router stubs (`duckbox_route_decisions_total`, `duckbox_node_lease_*`). Histogram buckets: 5ms … 120s for queries; 10ms … 30s for warmup/initSQL. A self-fence logs `{"event":"self_fence",...}` and exits **3**.

## Arrow Flight SQL

v1 wire protocol. JDBC and ADBC work. Headers:

- `x-duckbox-sandbox` — named sandbox id (required for queries)
- `x-duckbox-key` — optional; definition key is used otherwise
- `x-duckbox-caller` — trusted caller identity; used only when `auth.allow_insecure_dev` is set and no bearer/JWT is configured
- `Authorization: Bearer` — static `auth.bearer_secrets` or HS256 JWT (`auth.jwt_secret`). `alg` must be `"HS256"` exactly (not a substring); `exp` is required (`nbf` optional, 60s leeway). Unsigned tokens are rejected

CRUD actions: `CreateSandbox`, `GetSandbox`, `UpdateSandbox`, `DeleteSandbox`, `ListSandboxes`, `ExpireSandbox`. Create/Update body is spec YAML; ListSandboxes YAML body filters `id_prefix`, `key_prefix`, `policy_class`, `state` (`warm`|`passive`|`defined`) plus `limit`/`offset`. Each list item is a summary (`id`, `key`, `version`, `policy_class`, `state`, `owner`, `created_at`, `updated_at`, `last_used_at`, `expires_at`) — not the full spec. `ExpireSandbox` passivates the instance and invalidates prepared handles; the definition stays.

Optional spec `lifecycle.idle_timeout` passivates an idle instance (daemon `limits.idle_timeout` / `idle_evict_ms` is the default; `limits.max_idle_timeout` caps it). `lifecycle.ttl` / `lifecycle.expires_at` tombstone the definition.

`GetCatalogs` / `GetDbSchemas` / `GetTables` / `GetSqlInfo` are answered **by the sandbox** and filtered to spec-whitelisted tables/columns.

Python is Arrow Flight SQL via ADBC. Use `examples/python/quickstart.ipynb` (or `quickstart.py`) after the daemon is up. `create_sandbox()` / `connect(sandbox=...)` send the id header for you.

The registry is `SandboxRegistry` (S3 impl against RustFS in CI, in-memory impl for tests). `S3ConditionalLeaseManager` is the v1 lease interface; this draft uses `SingleNodeLeaseManager` and probes the lease endpoint when configured.

## Layout

| Path | What |
| --- | --- |
| `daemons/` | Control-plane YAML (listen, limits, optional lease) |
| `policies/` | Sandbox specs (lake + tables + key + functions) |
| `server/` | C++ daemon + enforcement |
| `examples/python/` | Quickstart notebook/script, `duckbox_client`, CLI utility |
| `test/` | CTest suites: `unit`, `guardrails` (YAML SQL corpus), `integration` |

## Stubbed

- mTLS caller certs (bearer secrets and HS256 JWT are implemented)
- Multi-node S3 leases with fencing epoch (`S3ConditionalLeaseManager`)
- Per-process cgroup/seccomp
