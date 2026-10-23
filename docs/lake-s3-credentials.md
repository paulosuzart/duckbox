# Lake S3 credentials

Each sandbox spec chooses how its DuckDB instance authenticates to lake data
on S3. Two sandboxes on the same node can use different keys, session tokens,
profiles, or roles. The daemon never stores secret values — only references —
and `lake_allow` is fail-closed at spec validation.

Secrets are created during warmup (`CREATE OR REPLACE SECRET duckbox_s3`)
**before** `enable_external_access=false` and `lock_configuration`. Agent SQL
cannot list, read, create, replace, or drop them, and cannot `SET s3_*` or
read those settings through `current_setting`.

## Mode 1 — static keys (backward compatible)

Use long-lived access key/secret refs. This is the current default
(`PROVIDER config`).

Sandbox spec:

```yaml
lake:
  kind: ducklake
  catalog_env: DUCKBOX_LAKE_CATALOG
  data_path: "s3://duckbox-lake/data/"
  extensions: [httpfs, postgres, ducklake]
  s3:
    endpoint: "127.0.0.1:9000"   # omit for AWS; then allowlist s3.amazonaws.com
    url_style: path
    use_ssl: false
    access_key_env: DUCKBOX_S3_KEY
    secret_key_env: DUCKBOX_S3_SECRET
    region: us-east-1
```

Daemon allowlist (every env ref must appear, including the catalog DSN):

```yaml
lake_allow:
  s3_endpoints:
    - "127.0.0.1:9000"
  secret_refs:
    - env:DUCKBOX_S3_KEY
    - env:DUCKBOX_S3_SECRET
    - env:DUCKBOX_LAKE_CATALOG
```

Do not put key material in the spec or daemon YAML. Do not use `*` in
allowlists.

## Mode 2a — pre-fetched temporary credentials

Same as mode 1, plus `session_token_env`. DuckDB stores `SESSION_TOKEN` in the
warmup secret. These credentials **do not refresh**. When they expire, queries
fail with:

`lake S3 session credentials expired; re-warmup the sandbox after refreshing session_token_env`

Refresh the environment (or secret file), then passivate/re-warmup the
sandbox so warmup re-resolves the refs.

```yaml
lake:
  s3:
    access_key_env: DUCKBOX_S3_KEY
    secret_key_env: DUCKBOX_S3_SECRET
    session_token_env: DUCKBOX_S3_SESSION
    region: us-east-1
    use_ssl: true
    url_style: vhost
```

Add `env:DUCKBOX_S3_SESSION` to `lake_allow.secret_refs`.

## Mode 2b — DuckDB `PROVIDER credential_chain`

Use this when the node has **no** long-lived IAM user: SSO profiles, assumed
roles, or a process that already exported AWS credentials. DuckDB's `aws`
extension refreshes via the chain (`REFRESH auto`). Mid-session expiry is
handled by the provider; a refresh failure is returned as the DuckDB/S3
error (re-warmup after fixing the profile/role/SSO login).

`profile` and `role_arn` are optional, but a spec with **neither** is denied
unless the daemon sets `lake_allow.allow_default_credential_chain: true`
(or `auth.allow_insecure_dev`). That flag is off by default so a spec cannot
silently pick up arbitrary node credentials.

```yaml
lake:
  kind: ducklake
  catalog_env: DUCKBOX_LAKE_CATALOG
  data_path: "s3://analytics-lake/data/"
  extensions: [httpfs, postgres, ducklake, aws]
  s3:
    provider: credential_chain
    profile: lake-readonly          # optional; must be on lake_allow.aws_profiles
    role_arn: arn:aws:iam::123456789012:role/duckbox-lake  # optional
    region: us-east-1
    use_ssl: true
    url_style: vhost
    # no endpoint → DuckDB default s3.amazonaws.com
```

Daemon:

```yaml
lake_allow:
  s3_endpoints:
    - "s3.amazonaws.com"
  secret_refs:
    - env:DUCKBOX_LAKE_CATALOG
  aws_profiles:
    - lake-readonly
  role_arns:
    - arn:aws:iam::123456789012:role/duckbox-lake
```

List every profile and role a spec may use. Empty `aws_profiles` / `role_arns`
deny those fields. Wildcards are rejected at daemon load.

## Target path: DuckLake on AWS S3 (no IAM user)

Postgres catalog + Parquet on S3 in `us-east-1`, authenticated only with
SSO or assume-role:

1. On the node, log in so a named profile can assume the lake role
   (`aws sso login --profile lake-readonly`, or a profile whose
   `role_arn` is the lake role).
2. Allowlist that profile and/or role on the daemon as above.
3. Use mode 2b on the sandbox spec. Omit `endpoint` (or set
   `s3.amazonaws.com`), set `use_ssl: true`, `url_style: vhost`,
   `region: us-east-1`.
4. Put only the catalog DSN in `secret_refs` (`env:DUCKBOX_LAKE_CATALOG`).
5. Create the sandbox. Warmup loads `aws` + `httpfs` and creates
   `duckbox_s3` with `PROVIDER credential_chain` and `REFRESH auto`.

Mode 2a is the fallback when you already ran `aws configure export-credentials`
and exported `DUCKBOX_S3_KEY` / `DUCKBOX_S3_SECRET` / `DUCKBOX_S3_SESSION`.
Plan to re-warmup before the token's expiry.

## Lease / control-plane S3

The daemon `lease` block (registry + ownership) accepts the same options.
Use the AWS SDK default chain, a named profile, or STS assume-role
(`STSAssumeRoleCredentialsProvider`) — not a hand-rolled signer and not a
silent profile fallback when `role_arn` is set.

```yaml
lease:
  endpoint: "http://127.0.0.1:9000"
  bucket: duckbox-control
  prefix: leases/
  access_key_env: DUCKBOX_LEASE_KEY
  secret_key_env: DUCKBOX_LEASE_SECRET
  # session_token_env: DUCKBOX_LEASE_SESSION
  # provider: credential_chain
  # profile: duckbox-control
  # role_arn: arn:aws:iam::123456789012:role/duckbox-control
```

`credential_chain` cannot be mixed with `access_key_env` / `secret_key_env` /
`session_token_env`. A chain without `profile` or `role_arn` is refused unless
`auth.allow_insecure_dev` is set.

## Local STS (MinIO)

```bash
docker compose --profile sts up -d --wait minio
# MinIO console/API: 127.0.0.1:19000  (root minioadmin / minioadmin)
./build/duckbox_s3_sts_tests
```

MinIO `AssumeRole` mints temporary creds for mode 2a tests. DuckDB's `sts`
chain talks to AWS STS; against MinIO, prefer a named profile (mode 2b
`CHAIN config`) or a pre-fetched session token.
