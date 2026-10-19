# proto/

v1 is **Arrow Flight SQL** (gRPC). JDBC and ADBC clients work.

Per-RPC headers (or handshake username for the key):

- `x-duckbox-key` — tenant key, parsed by the spec’s `auth.key`
- `x-duckbox-spec` / `x-duckbox-policy` — sandbox spec YAML, **base64url-encoded** (gRPC metadata cannot carry newlines). Raw YAML is still accepted when it has no newlines.
- `x-duckbox-spec-dir` — directory for spec-relative paths (`lake.bootstrap_sql`)
- `x-duckbox-init-sql` — optional initSQL
- `Authorization: Bearer …` — token mode (JWT stub; spec must be in the token)

Prepared statements are signed opaque handles (HMAC), not server session state.

`GetCatalogs` / `GetTables` / … are served by the **sandbox** and filtered to spec-whitelisted objects.

**Debug HTTP** `POST /v1/query` exists only with `--debug-http` (off by default). Same headers; JSON `{"sql":"…"}`; Arrow IPC body.
