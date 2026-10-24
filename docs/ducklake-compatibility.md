# DuckLake compatibility (Postgres catalog, data on S3)

duckbox 2.0 attaches an **existing** DuckLake. It does not create the lake
and it does not migrate the catalog.

`BuildDuckLakeAttachSql` emits:

```sql
ATTACH '<catalog>' AS lake (DATA_PATH '<s3 path>', READ_ONLY)
```

It does **not** pass `AUTOMATIC_MIGRATION`, `DUCKLAKE_VERSION`, or
`STORAGE_VERSION`. DuckDB 2.0's `ducklake` extension reads DuckLake 1.0
catalogs without migration. Migration is opt-in on the operator's
`ATTACH`, not a duckbox flag.

## How CI creates the lake

Job **DuckLake compatibility (Postgres catalog, RustFS)**
(`ducklake-compat`) runs `scripts/e2e_ducklake_compat.sh`.

1. Start the repo Compose file (Postgres + RustFS only; never MinIO).
2. Prefer seeding with **DuckDB 1.5.6** and that release's `ducklake`
   extension (`pip install duckdb==1.5.6` in `.venv-ducklake-1.5.6`), so
   the catalog looks like a lake that existed before the 2.0 bump.
3. If 1.5.6 cannot be installed or `INSTALL ducklake` fails, seed with
   DuckDB 2.0.0 and write the reason to `ducklake-compat-result.txt`.
4. Start duckbox 2.0, create two named sandboxes on
   `policies/ducklake/analyst.yaml` (`compat-analyst` / tenant 21,
   `compat-kim` / tenant 22).
5. Query `deals` through the rewriter. Tenant 21 sees id `1` only;
   tenant 22 sees `3` and `4`. `WHERE tenant_id = 22` as tenant 21
   returns no rows (the rewriter binds the key, not the user literal).

Tenant isolation is rewriter-only. The lake itself is shared.

## If attach ever requires migration

A version-mismatch error from DuckDB looks like:

```
DuckLake catalog version mismatch: catalog version is 1.0, but the
extension requires version 1.1. To automatically migrate, set
AUTOMATIC_MIGRATION to TRUE when attaching.
```

The operator-side fix (run **outside** duckbox, after a catalog backup) is:

```sql
ATTACH 'ducklake:postgres:…' AS lake (
    DATA_PATH 's3://duckbox-lake/data/',
    AUTOMATIC_MIGRATION true
);
```

Do not add `AUTOMATIC_MIGRATION` to a sandbox spec. duckbox will not
migrate a shared catalog as a side effect of warmup.

## Local run

```bash
docker compose up -d --wait
# build/ already has duckbox
export DUCKBOX_S3_KEY=rustfsadmin DUCKBOX_S3_SECRET=rustfsadmin
export DUCKBOX_HANDLE_SECRET=duckbox-dev-secret
export DUCKBOX_LAKE_CATALOG='ducklake:postgres:dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox'
bash scripts/e2e_ducklake_compat.sh
```

The README runbook still seeds with DuckDB 2.0 (`scripts/seed_ducklake.py`
in the project venv). That path is "create a lake today". This job is
"read a lake that already existed".
