# proto/

This draft does **not** use gRPC or Arrow Flight protobufs. The wire protocol is HTTP:

`POST /v1/query`

Headers:

- `X-Duckbox-Key`: tenant key, e.g. `tenant_21:user_sergio`
- `X-Duckbox-Policy`: policy name, e.g. `analyst`
- `Authorization: Bearer …` required only when the policy `auth.mode` is `token` (JWT verify is stubbed)

JSON body:

```json
{"sql": "SELECT id, title, amount FROM deals"}
```

Success: `Content-Type: application/vnd.apache.arrow.stream` (Arrow IPC stream from DuckDB `COPY … (FORMAT ARROWS)`).

Error: JSON `{"error":"…"}` with HTTP 400/401/500.

`GET /health` returns `{"ok":true}`.

A future Flight endpoint can sit next to this without changing SQL enforcement.
