# C3 ADBC example

Optional, self-contained client: a [C3](https://c3-lang.org/) program talks
to a running duckbox over the
[ADBC C/C++ API](https://arrow.apache.org/adbc/current/cpp/index.html)
(Flight SQL driver). It is **not** part of the default CMake/Make build or CI.

C3 is C ABI compatible but has no C header import. `src/adbc.c3` declares
the part of `arrow-adbc/adbc.h` (ADBC 1.1.0, `apache-arrow-adbc-18`) and of
the Arrow C Data / C Stream interface that the program uses, as C3 structs
with the same layout and `extern fn … @cname("Adbc…")`. `src/main.c3` then
holds `AdbcDatabase`, `AdbcConnection`, `AdbcStatement`, and
`ArrowArrayStream`, including `private_data` and release callbacks, as
ordinary C3 values. There is no C shim.

`src/main.c3` is a short program, not a CLI. URI, sandbox id and SQL are
constants at the top of the file. The environment variables `DUCKBOX_URL`,
`DUCKBOX_SANDBOX` and `DUCKBOX_SQL` override them.

## What it does

The flow is the same as the Zig example (PR #51, `examples/zig-adbc/`):

1. Links the official Flight SQL driver library, which exports
   `AdbcDatabaseNew` and the rest of the ADBC C API. No driver-manager C++
   is compiled.
2. Sets `uri` and the Flight SQL call-header options
   `adbc.flight.sql.rpc.call_header.x-duckbox-sandbox` and
   `…x-duckbox-caller` (header names must be lowercase; same prefix as
   `examples/python/duckbox_client.py`).
3. Runs `SELECT id, title, amount FROM deals ORDER BY id` inside that named
   sandbox and prints the rows as TSV.

## Prerequisites

- [c3c](https://c3-lang.org/getting-started/prebuilt-binaries/) 0.8.x
  (tested with 0.8.1). For example `brew install c3c`, or a release
  tarball on `PATH`.
- `curl`, `python3`, `make`. On macOS also `install_name_tool` and
  `codesign` (Xcode command line tools).
- A **running** duckbox with a named sandbox already created.

`scripts/fetch_deps.sh` downloads a pinned Flight SQL driver (PyPI wheel
`adbc-driver-flightsql` 1.12.0, sha256-checked) for macOS arm64/x86_64 or
Linux x86_64/aarch64 into this directory's `.deps/`. It never touches the
default duckbox build.

### Start duckbox (memory lake, no Docker)

From the repository root, in another terminal:

```bash
export DUCKBOX_HANDLE_SECRET=duckbox-dev-secret
./build/duckbox serve --daemon ./daemons/memory.yaml

./build/duckbox sandbox create --url grpc://127.0.0.1:4747 \
  --spec ./policies/memory/analyst.yaml \
  --id acme-analyst --key tenant_21:user_sergio
```

The memory spec seeds `deals` from `examples/sql/memory_init.sql`. Tenant 21
sees row `id=1` (`alpha deal`). On another port, also pass
`--internal-listen` (for example `--listen 127.0.0.1:47471
--internal-listen 127.0.0.1:48471`) and set `DUCKBOX_URL`.

## Build and run

```bash
cd examples/c3-adbc
make          # fetch .deps if needed, then c3c compile
./build/query
```

`make run` builds and runs. Equivalent without Make (Linux):

```bash
./scripts/fetch_deps.sh
mkdir -p build
c3c compile -O1 --output-dir build -o query src/main.c3 src/adbc.c3 \
  -L .deps/adbc/lib -l adbc_driver_flightsql -z -rpath -z '$ORIGIN/../.deps/adbc/lib'
./build/query
```

On macOS the wheel's dylib id is a bare file name, so the Makefile rewrites
it to `@rpath/libadbc_driver_flightsql.dylib` with `install_name_tool` and
re-signs the binary ad hoc. Use `make` there.

```bash
DUCKBOX_SANDBOX=acme-kim ./build/query
DUCKBOX_SQL='SELECT count(*) AS n FROM deals' ./build/query
```

## Layout

| Path | Role |
| --- | --- |
| `src/main.c3` | The program: connect, headers, SELECT, print, release |
| `src/adbc.c3` | C3 declarations of the ADBC / Arrow C structs and functions used |
| `Makefile` | `c3c compile`, link the driver, rpath (and the macOS install-name fix) |
| `scripts/fetch_deps.sh` | Pinned Flight SQL 1.12.0 wheel → `.deps/adbc/lib/` |
| `testdata/e2e-output.txt` | Captured local run against the memory daemon |

## No C shim

Goose (PR #44, `examples/goose-adbc/`) needed `shim/adbc_backend.c` with
opaque `i64` handles, because Goose `extern fn` cannot pass raw pointers or
function pointers. Zig (PR #51) translates `adbc.h` with translate-c.

C3 can pass pointers and call C function pointers directly, but cannot read
C headers. So the structs are written out by hand in `src/adbc.c3`, one for
one with `adbc.h` and the Arrow C Data Interface. If ADBC changes a struct
layout, that file has to follow.

## Limitations

**Arrow decoding.** Same as the Zig example. Integer and string values are
`mem::copy`'d, so misaligned Flight buffers do not SIGSEGV on ARM64.
Booleans, `int32`/`int64`, dates and timestamps (raw integer), and
`utf8`/`binary` (and their large variants) are printed. Anything else, such
as `DECIMAL` from `sum()` or nested types, is printed as `<format>`.

**Auth / TLS.** Same as the Python helper. It works with
`auth.allow_insecure_dev`. Production bearer/JWT still needs the Flight
`auth-token-bin` work (issue #16).

**Not in the default build.** No root CMake, CI, or shared `.deps` changes.
There is no `clean` target: delete `build/` and `.deps/` by hand.

## Local e2e

`testdata/e2e-output.txt` is a captured run on macOS arm64 against a local
memory daemon:

```
$ ./build/query
id	title	amount
1	alpha deal	100
```

`DUCKBOX_SANDBOX=acme-kim` prints tenant 22 (`id=3,4`).
`SELECT * FROM secrets` is rejected (`table not allowlisted`).
