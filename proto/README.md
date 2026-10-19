# proto/

v1 is **Arrow Flight SQL** (gRPC). JDBC and ADBC clients work.

Per-RPC headers:

- `x-duckbox-sandbox` — named sandbox id (required for queries)
- `x-duckbox-key` — optional per-query key for `auth.key` variable extraction; otherwise the definition’s bound key is used
- `x-duckbox-caller` — trusted caller identity (default `local` / handshake peer)
- `x-duckbox-spec-dir` — directory for spec-relative paths on Create/Update
- `Authorization: Bearer …` — token mode (JWT stub)

CRUD `DoAction` types: `CreateSandbox`, `GetSandbox`, `UpdateSandbox`, `DeleteSandbox`, `ListSandboxes`. Create/Update body is the spec YAML.

Prepared statements are signed opaque handles (HMAC) carrying **id + version**, not server session state. A non-current version returns a `re-prepare` error unless the current spec’s `handles.stale_version_grace` (default `0s`, cap `1h`) still covers the immediately previous version (`updated_at + grace`). That handle runs against the previous version’s rules.

`GetCatalogs` / `GetTables` / … are served by the **sandbox** and filtered to spec-whitelisted objects.

**Debug HTTP** `POST /v1/query` exists only with `--debug-http` (off by default). Header `X-Duckbox-Sandbox`; JSON `{"sql":"…"}`; Arrow IPC body.
