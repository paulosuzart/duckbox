# proto/

v1 is **Arrow Flight SQL** (gRPC). JDBC and ADBC clients work.

Per-RPC headers:

- `x-duckbox-sandbox` — named sandbox id (required for queries)
- `x-duckbox-key` — optional per-query key for `auth.key` variable extraction; otherwise the definition’s bound key is used
- `x-duckbox-caller` — trusted caller identity (default `local` / handshake peer). Ignored when `auth.bearer_secrets` or JWT is configured
- `Authorization: Bearer …` — static bearer secret or HS256 JWT (`auth.jwt_secret`). Unsigned tokens are rejected

CRUD `DoAction` types: `CreateSandbox`, `GetSandbox`, `UpdateSandbox`, `DeleteSandbox`, `ListSandboxes`, `ExpireSandbox`, `DrainNode`. Create/Update body is the spec YAML. `ListSandboxes` body is optional YAML filters (`id_prefix`, `key_prefix`, `policy_class`, `state`, `limit`, `offset`); items are summaries, not full specs (`owner` is the lease holder). `ExpireSandbox` body is the id. `DrainNode` body is optional YAML `timeout_ms` / `timeout`.

Prepared statements are signed opaque handles (HMAC) carrying **id + version**, not server session state. A non-current version returns a `re-prepare` error unless the current spec’s `handles.stale_version_grace` (default `0s`, cap `1h`) still covers the immediately previous version (`updated_at + grace`). That handle runs against the previous version’s rules.

`GetCatalogs` / `GetTables` / … are served by the **sandbox** and filtered to spec-whitelisted objects.

**Debug HTTP** `POST /v1/query` exists only with `--debug-http` (off by default). Header `X-Duckbox-Sandbox`; JSON `{"sql":"…"}`; Arrow IPC body.
