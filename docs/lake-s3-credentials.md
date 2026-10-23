# Lake S3 credentials

Each sandbox spec chooses how its DuckDB instance authenticates to lake data
on S3. There are **exactly two** modes, for both `lake.s3` and the daemon
`lease` block:

1. **Static keys** — `access_key_env` + `secret_key_env` (service-account style).
2. **Refreshable credentials** — `provider: credential_chain`, with optional
   `profile` and/or `role_arn`, or the default AWS chain (IRSA / env / instance
   profile).

Two sandboxes on the same node can use different keys, profiles, or roles. The
daemon never stores secret values — only references — and `lake_allow` is
fail-closed at spec validation.

Secrets are created during warmup (`CREATE OR REPLACE SECRET duckbox_s3`)
**before** `enable_external_access=false` and `lock_configuration`. Agent SQL
cannot list, read, create, replace, or drop them, and cannot `SET s3_*` or
read those settings through `current_setting`.

`session_token` / `session_token_env` are not supported. A spec or daemon
YAML that still has those keys fails with `unknown key`. Use
`provider: credential_chain` when credentials must refresh.

## Mode 1 — static keys

Use long-lived access key/secret refs (`PROVIDER config`). These do not
refresh.

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

## Mode 2 — DuckDB `PROVIDER credential_chain`

Use this when the node has **no** long-lived IAM user: SSO profiles, assumed
roles, IRSA / web identity, or a process that already exported AWS credentials.
DuckDB's `aws` extension refreshes via the chain (`REFRESH auto`). The lease
client uses the matching AWS SDK providers (`DefaultAWSCredentialsProviderChain`,
a named profile, or `STSAssumeRoleCredentialsProvider`). Mid-session expiry is
handled by the provider; a refresh failure is returned as the DuckDB/S3 error
(re-warmup after fixing the profile/role/SSO login).

`profile` and `role_arn` are optional, but a **sandbox spec** with **neither**
is denied unless the daemon sets `lake_allow.allow_default_credential_chain: true`
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

### Default chain and IRSA (web identity)

A credential_chain with **no** `profile` and **no** `role_arn` uses the default
AWS provider order. That is the supported path for Kubernetes IRSA (and any
other STS web-identity setup):

- The node (or pod) must have `AWS_WEB_IDENTITY_TOKEN_FILE` and `AWS_ROLE_ARN`
  (IRSA injects both; `AWS_ROLE_SESSION_NAME` is optional).
- The sandbox spec sets only `provider: credential_chain`.
- The daemon sets `lake_allow.allow_default_credential_chain: true`.
- DuckDB warmup uses `CHAIN 'config;sts'` and `REFRESH auto`. The `sts` provider
  includes `AssumeRoleWithWebIdentity`.
- The lease client uses `DefaultAWSCredentialsProviderChain`, which includes
  `STSAssumeRoleWebIdentityCredentialsProvider`.

```yaml
# spec
lake:
  extensions: [httpfs, postgres, ducklake, aws]
  s3:
    provider: credential_chain
    region: us-east-1
    use_ssl: true
    url_style: vhost
# daemon
lake_allow:
  s3_endpoints: ["s3.amazonaws.com"]
  secret_refs: ["env:DUCKBOX_LAKE_CATALOG"]
  allow_default_credential_chain: true
```

Do not put the web-identity token or role ARN in the spec. The SDK reads them
from the process environment.

## Target path: DuckLake on AWS S3 (no IAM user)

Postgres catalog + Parquet on S3 in `us-east-1`, authenticated only with
SSO, assume-role, or IRSA:

1. On the node, either log in so a named profile can assume the lake role
   (`aws sso login --profile lake-readonly`), or run under IRSA so
   `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN` are set.
2. Allowlist that profile and/or role on the daemon, **or** set
   `allow_default_credential_chain: true` for IRSA / the default chain.
3. Use mode 2 on the sandbox spec. Omit `endpoint` (or set
   `s3.amazonaws.com`), set `use_ssl: true`, `url_style: vhost`,
   `region: us-east-1`.
4. Put only the catalog DSN in `secret_refs` (`env:DUCKBOX_LAKE_CATALOG`).
5. Create the sandbox. Warmup loads `aws` + `httpfs` and creates
   `duckbox_s3` with `PROVIDER credential_chain` and `REFRESH auto`.

## Lease / control-plane S3

The daemon `lease` block (registry + ownership) accepts the same two modes.
Use static key refs, or `provider: credential_chain` with a named profile,
an assume-role ARN (`STSAssumeRoleCredentialsProvider`, fail closed if the
STS SDK is not linked), or the default chain (IRSA / env / instance). There
is no silent profile fallback when `role_arn` is set.

```yaml
lease:
  endpoint: "http://127.0.0.1:9000"
  bucket: duckbox-control
  prefix: leases/
  access_key_env: DUCKBOX_LEASE_KEY
  secret_key_env: DUCKBOX_LEASE_SECRET
  # provider: credential_chain
  # profile: duckbox-control
  # role_arn: arn:aws:iam::123456789012:role/duckbox-control
```

IRSA for the control plane (no static keys):

```yaml
lease:
  endpoint: "https://s3.amazonaws.com"
  bucket: duckbox-control
  prefix: leases/
  provider: credential_chain
```

`credential_chain` cannot be mixed with `access_key_env` / `secret_key_env`.
A lease default chain is allowed when the operator sets
`provider: credential_chain` with no profile/role.

## Local STS (MinIO)

```bash
docker compose --profile sts up -d --wait minio
# MinIO-compatible API: 127.0.0.1:19000  (root minioadmin / minioadmin)
./build/duckbox_s3_sts_tests
```

Compose pins `docker.io/pgsty/silo:RELEASE.2026-10-18T00-00-00Z` (digest in
`docker-compose.yml`). Official `minio/minio` and `quay.io/minio/minio` images
are no longer publicly pullable; Silo keeps the MinIO S3/STS wire and
`MINIO_*` env. `AssumeRole` can mint temporary creds for local tests. DuckDB's
`sts` chain talks to AWS STS; against this emulator, prefer a named profile
(mode 2 `CHAIN config`). `AssumeRoleWithWebIdentity` is not exercised here —
IRSA is covered by default-chain provider-selection tests.
