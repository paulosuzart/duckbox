# Zig ADBC example

Optional, self-contained client: a [Zig](https://ziglang.org/) 0.17 program
talks to a running duckbox over the
[ADBC C/C++ API](https://arrow.apache.org/adbc/current/cpp/index.html)
(Flight SQL driver). It is **not** part of the default CMake/Make build or CI.

Zig 0.17 removed `@cImport`. This example uses the official
[translate-c](https://codeberg.org/ziglang/translate-c) package on `adbc.h`
(the supported replacement) and then holds `AdbcDatabase`, `AdbcConnection`,
`AdbcStatement`, and `ArrowArrayStream` — including `private_data` and
release callbacks — as ordinary Zig values. There is no C shim.

`src/main.zig` is a short program, not a CLI. URI, sandbox id, and SQL are
constants at the top of the file.

## What it does

1. Links the official Flight SQL `.so` (it exports `AdbcDatabaseNew` and
   the rest of the ADBC C API). No driver-manager C++ is compiled.
2. Sets `uri` and the Flight SQL call-header option
   `adbc.flight.sql.rpc.call_header.x-duckbox-sandbox` (header names must
   be lowercase; same prefix as `examples/python/duckbox_client.py`).
3. Runs `SELECT id, title, amount FROM deals ORDER BY id` inside that named
   sandbox and prints the rows as TSV.

## Prerequisites

- [Zig 0.17.0](https://ziglang.org/download/0.17.0/release-notes.html)
  (`zig version` should print `0.17.0`). Linux x86_64 tarball:
  `https://ziglang.org/download/0.17.0/zig-x86_64-linux-0.17.0.tar.xz`
- `curl`, `python3`, `tar` (to fetch pinned ADBC headers + the Flight SQL
  `.so` into this directory's `.deps/`)
- A **running** duckbox with a named sandbox already created

This directory never installs packages into the default duckbox build.

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
cd examples/zig-adbc
make          # fetch .deps if needed, then zig build
./query
```

`make run` builds and runs. Equivalent without Make:

```bash
./scripts/fetch_deps.sh
zig build -Doptimize=ReleaseSafe
./zig-out/bin/query
```

Edit the constants at the top of `src/main.zig` to change URI, sandbox, or
SQL. `zig build` installs the Flight SQL `.so` next to the binary
(`zig-out/lib/`, rpath `$ORIGIN/../lib`).

## Layout

| Path | Role |
| --- | --- |
| `src/main.zig` | The program: connect, header, SELECT, print, release |
| `src/c.h` | `#include <arrow-adbc/adbc.h>` for translate-c |
| `build.zig` | translate-c + link libc; no C sources |
| `scripts/fetch_deps.sh` | Pinned ADBC 18 headers + Flight SQL 1.12.0 wheel |
| `testdata/e2e-output.txt` | Captured local run against the memory daemon |

## No C shim

Goose (PR #44, `examples/goose-adbc/`) needed `shim/adbc_backend.c` with
opaque `i64` handles because Goose `extern fn` cannot pass raw pointers or
function pointers. `AdbcDatabase` / `ArrowArrayStream` carry `private_data`
and callbacks, so they cannot cross that FFI.

Zig can. This file calls `AdbcDatabaseNew` / `AdbcStatementExecuteQuery`
and the `ArrowArrayStream` callbacks (`get_schema`, `get_next`, `release`)
directly. The only C is Apache's `adbc.h`, translated by Zig, plus the
official Flight SQL shared library.

The official ADBC driver-manager C++ is **not** compiled. The pinned
Flight SQL wheel already exports the ADBC C entry points.

## Limitations

**Arrow decoding.** Integer and string values are `memcpy`'d so misaligned
Flight buffers should not SIGSEGV. The server still does not guarantee
4/8-byte-aligned string offsets; ARM64 clients that parse the C Data
Interface in place can fault (same note as the root README). Nested Arrow
(`LIST` / `STRUCT` / `MAP`) is printed as `<format>`.

**Auth / TLS.** Same as the Python helper: works with
`auth.allow_insecure_dev`. Production bearer/JWT still needs the Flight
`auth-token-bin` work (issue #16).

**Platform.** `scripts/fetch_deps.sh` pins a Linux x86_64 Flight SQL wheel.
On other hosts, place `libadbc_driver_flightsql.so` (or `.dylib`) in
`.deps/adbc/lib/` (SONAME symlink `.so.112` on Linux).

**Not in the default build.** No root CMake, CI, or shared `.deps` changes.

## Calling the duckbox core as a library later

What this example does *not* do, and what it would take:

1. **C ABI or Zig bindings on the core.** `duckbox_core` is a C++ static
   library (`TenantSandbox`, `Policy`, Arrow C++, DuckDB). Zig can
   `extern` a small C surface or wrap selected C++ symbols; it cannot
   construct those types from `adbc.h`.
2. **Link closure.** A core backend pulls DuckDB 2.0, Arrow Flight,
   yaml-cpp, OpenSSL, and the S3 SDK even for a memory lake. That is why
   this example talks to a running daemon.
3. **Lifecycle.** ADBC assumes an already-created named sandbox. A core
   backend must load a spec, resolve secret refs, attach the lake, run
   bootstrap SQL, then `lock_configuration` — the same warmup `serve`
   already does. `TenantSandbox::Execute` already returns `QueryOutput`
   (`arrow_ipc` + `text_table`).
4. **Swap.** Replace the Flight SQL `AdbcDatabaseNew` path with a Zig
   (or C) wrapper around `TenantSandbox::Execute`, then decode
   `arrow_ipc` with the same Arrow C Data Interface helpers. The printed
   TSV would stay the same.

## Local e2e

`testdata/e2e-output.txt` is a captured run against a local memory daemon
(no Docker in this environment; Flight SQL and the sandbox header are the
same as DuckLake + compose/RustFS).

```
$ ./query
id	title	amount
1	alpha deal	100
```

Changing the `sandbox` constant to `acme-kim` prints tenant 22 (`id=3,4`).
`SELECT * FROM secrets` is rejected (`table not allowlisted`).
