# Goose ADBC example

Optional, self-contained client: a [Goose](https://github.com/aardappel/goose)
program talks to a running duckbox over the
[ADBC C/C++ API](https://arrow.apache.org/adbc/current/cpp/index.html)
(Flight SQL driver). It is **not** part of the default CMake/Make build or CI.

The goose-facing API (`duckbox.goose`) is backend-agnostic. Today
`shim/adbc_backend.c` implements the `dbx_*` symbols with ADBC. A later
direct-core sidecar can implement the same symbols without changing the
Goose side.

## What it does

1. Connects to Flight SQL (`grpc://127.0.0.1:4747` by default).
2. Sends `x-duckbox-sandbox` (and optional `x-duckbox-key`) through the
   driver's call-header option
   `adbc.flight.sql.rpc.call_header.<lowercase-header-name>`
   ([Flight SQL driver](https://arrow.apache.org/adbc/current/driver/flight_sql.html);
   header names must be lowercase).
3. Runs one `SELECT` inside that named sandbox and prints the rows as TSV.

## Prerequisites

- A C compiler and a C++17 compiler (`cc` / `c++`). Goose finds `cc` itself.
- `curl`, `python3`, `tar` (to fetch pinned goose + ADBC into `.deps/`).
- A **running** duckbox with a named sandbox already created.

This directory never installs packages into the default duckbox build.
The Makefile fetches a pinned goose (`v2026.3`) and the ADBC Flight SQL
shared library (Linux x86_64 wheel 1.12.0) plus the ADBC 18 driver-manager
sources under `.deps/`.

### Start duckbox (memory lake, no Docker)

From the repository root, in another terminal:

```bash
export DUCKBOX_HANDLE_SECRET=duckbox-dev-secret
./build/duckbox serve --daemon ./daemons/memory.yaml --listen 127.0.0.1:4747

./build/duckbox sandbox create --url grpc://127.0.0.1:4747 \
  --spec ./policies/memory/analyst.yaml \
  --id acme-analyst --key tenant_21:user_sergio
```

The memory spec seeds `deals` from `examples/sql/memory_init.sql`. Tenant 21
sees row `id=1` (`alpha deal`). DuckLake + docker-compose/RustFS also works;
create the sandbox the same way as `examples/python`.

## Build and run

```bash
cd examples/goose-adbc
make          # fetch .deps if needed, build ./query
./query
./query --sandbox acme-analyst --sql 'SELECT id, title, amount FROM deals ORDER BY id'
```

`make run` builds and runs with the defaults.

| Flag / env | Default |
| --- | --- |
| `--url` / `DUCKBOX_URL` | `grpc://127.0.0.1:4747` |
| `--sandbox` / `DUCKBOX_SANDBOX` | `acme-analyst` |
| `--key` / `DUCKBOX_KEY` | empty (definition key is used) |
| `--sql` / `DUCKBOX_SQL` | `SELECT id, title, amount FROM deals ORDER BY id` |
| `DBX_ADBC_FLIGHTSQL` | `.deps/adbc/lib/libadbc_driver_flightsql.so` next to the binary |

## Layout

| Path | Role |
| --- | --- |
| `duckbox.goose` | Stable goose API: `connect` / `query` / cell accessors |
| `query.goose` | CLI that prints a TSV |
| `query.build` | Goose sidecar: compile `shim/adbc_backend.c`, link the manager |
| `shim/adbc_backend.c` | Opaque-handle ADBC backend |
| `scripts/fetch_deps.sh` | Pinned goose + ADBC download |
| `testdata/e2e-output.txt` | Captured local run (when the daemon was up) |

## Design: one goose API, swappable C backends

Goose `extern fn` may pass only scalars, `bool`, flat fixed-size structs
(by value or reference), slices of those (`{ data, len }`), and a
`u8[>..]&` builder (`gs_bld_append`). There are no raw pointers or
function pointers.

`AdbcDatabase`, `AdbcConnection`, `AdbcStatement`, and `ArrowArrayStream`
all carry `private_data` and callbacks, so they cannot cross the FFI.
The shim therefore:

- hands goose **opaque `i64` handles** (connection, result);
- keeps ADBC objects in a small C table;
- **decodes Arrow C Data Interface batches in C** into a flat cell table
  (null / i64 / f64 / utf8 / bool; other types become a `<format>` marker);
- returns cells through the allowed shapes.

A direct-core backend would implement the same `dbx_*` symbols and fill
the same cell table, for example by calling `sandbox::TenantSandbox::Execute`
and decoding `QueryOutput::arrow_ipc` (or `text_table`). The goose files
would not change.

## Limitations

**FFI.** No streaming Arrow into goose. Results are materialized in C (the
sandbox `max_result_rows` cap already bounds this). No prepared statements
or bound parameters in this example. Nested Arrow (`LIST` / `STRUCT` / `MAP`)
is not decoded.

**Arrow decoding.** Offsets and values are `memcpy`'d so misaligned Flight
buffers should not SIGSEGV on this path. The server still does not guarantee
4/8-byte-aligned string offsets; ARM64 clients that parse the C Data
Interface in place can fault. Dictionary-encoded and nested columns are
printed as `<format>`.

**Auth / TLS.** Same as the Python ADBC helper: works with
`auth.allow_insecure_dev`. Production bearer/JWT still needs the Flight
`auth-token-bin` work (see issue #16).

**Platform.** `scripts/fetch_deps.sh` pins a Linux x86_64 Flight SQL wheel.
Goose itself has macOS tarballs. On other hosts, place
`libadbc_driver_flightsql.so` (or `.dylib`) in `.deps/adbc/lib/` or set
`DBX_ADBC_FLIGHTSQL`.

**Not in the default build.** No root CMake, CI, or `.deps` changes.

## Calling the duckbox core as a library later

What this example does *not* do, and what it would take:

1. **C ABI on the core.** `duckbox_core` is a C++ static library
   (`TenantSandbox`, `Policy`, Arrow C++, DuckDB). Goose still cannot
   hold those types. Export a small C surface with the same `dbx_*`
   handles, or keep a C++ sidecar behind those symbols.
2. **Link closure.** A core backend pulls DuckDB 2.0, Arrow Flight,
   yaml-cpp, OpenSSL, and the S3 SDK even for a memory lake. That is
   why this example talks to a running daemon instead.
3. **Lifecycle.** ADBC assumes an already-created named sandbox. A core
   backend must load a spec, resolve secret refs, attach the lake, run
   bootstrap SQL, then `lock_configuration` — the same warmup `serve`
   already does.
4. **Swap.** Add `shim/core_backend.c` (or `.cc` via the Makefile),
   implement `dbx_connect` / `dbx_query` / cell accessors, and link
   `duckbox_core` instead of the Flight SQL driver. `duckbox.goose`
   stays the API.

## Local e2e

`testdata/e2e-output.txt` is a captured run against a local memory
daemon (no Docker in that environment; Flight SQL and the sandbox
header are the same as DuckLake + compose/RustFS).

```
$ ./query
id	title	amount
1	alpha deal	100

$ ./query --sandbox acme-kim --sql 'SELECT id, title, amount FROM deals ORDER BY id'
id	title	amount
3	bravo deal	500
4	bravo two	50
```

Tenant 21 sees `id=1` only; tenant 22 sees `3` and `4`. `SELECT * FROM secrets` is rejected (`table not allowlisted`).
