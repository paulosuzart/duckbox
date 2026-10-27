# proto/

v1 is **Arrow Flight SQL** (gRPC). JDBC and ADBC clients work. The Flight listener does not terminate TLS; bearer secrets and JWTs travel in the clear on `grpc://`. Outside local development, terminate TLS in front of the public Flight listener. Peer traffic may stay plaintext gRPC; TLS between nodes is opt-in only.

Per-RPC headers:

- `x-duckbox-sandbox` — named sandbox id (required for queries). Tenant binding is the definition’s key after caller auth, not a client-chosen header alone
- `x-duckbox-key` — optional per-query key for `auth.key` variable extraction; must match the definition key when sent
- `x-duckbox-caller` — trusted caller identity (default `local` / handshake peer). Used only with `auth.allow_insecure_dev`. Ignored when `auth.bearer_secrets` or JWT is configured
- `Authorization: Bearer …` — static bearer secret (constant-time) or HS256 JWT (`auth.jwt_secret`). Validated on every call; the Flight handshake is optional. `sub` and `exp` are required (`nbf` optional). Unsigned tokens are rejected. Failures are `Unauthenticated` and do not echo the token. The listener itself is still plaintext unless TLS is terminated in front of it.

Public `DoAction` types: `CreateSandbox`, `GetSandbox`, `UpdateSandbox`, `DeleteSandbox`, `ListSandboxes`, `ExpireSandbox`. Create/Update body is the spec YAML. `ListSandboxes` body is optional YAML filters (`id_prefix`, `key_prefix`, `policy_class`, `state`, `limit`, `offset`); items are summaries, not full specs (`owner` is the lease holder). `ExpireSandbox` body is the id.

The **internal** listener (never public) serves peer proxy Flight SQL plus operator actions `DrainNode` and `NodeStatus`. `DrainNode` body is optional YAML `timeout_ms` / `timeout`; it requires `auth.operators` (deny by default). Peer RPCs authenticate with the shared secret from `auth.peer_secret_ref` (`env:` / `file:`), not the caller’s bearer. Public Flight SQL must not serve `DrainNode` or peer calls. Endpoint `locations` returned to clients are empty (never a peer-internal address).

Prepared statements are signed opaque handles (AES-GCM + HMAC). The handle carries rewritten SQL, tenant, sandbox id + version, and — after DoPut — the bound parameter IPC. It is not server session state. Clients should use the handle that DoPut returns. Reusing the original handle works only on the node that received the DoPut: a local bind cache is a same-node fallback, bounded by a total byte budget that counts every stored key (up to three keys per bind). DoPut rejects bind parameters larger than 1 MiB (`InvalidArgument`; the error does not echo the params). A non-current version returns a `re-prepare` error unless the current spec’s `handles.stale_version_grace` (default `0s`, cap `1h`) still covers the immediately previous version (`updated_at + grace`). That handle runs against the previous version’s rules.

`GetCatalogs` / `GetTables` / … are served by the **sandbox** and filtered to spec-whitelisted objects.

**Debug HTTP** `POST /v1/query` exists only with `--debug-http` (off by default) and `auth.allow_insecure_dev`. Header `X-Duckbox-Sandbox`; JSON `{"sql":"…"}`; Arrow IPC body.
