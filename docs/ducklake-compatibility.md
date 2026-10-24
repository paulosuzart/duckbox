# DuckLake attach (Postgres catalog, data on S3)

duckbox 2.0 attaches an **existing** DuckLake. It does not create the lake
and it does not migrate the catalog. On-disk lake format compatibility is
DuckLake's responsibility; duckbox only targets DuckDB 2.0.

`BuildDuckLakeAttachSql` always emits:

```sql
ATTACH '<catalog>' AS lake (DATA_PATH '<s3 path>', READ_ONLY)
```

`kind: ducklake` specs must be `read_only: true` (the default).
`read_only: false` is a spec-validation error
(`kind: ducklake requires read_only: true`). The alias is quoted with
`QuoteSqlIdent` after `ValidSqlIdent`.

It does **not** pass `AUTOMATIC_MIGRATION`, `DUCKLAKE_VERSION`, or
`STORAGE_VERSION`. DuckDB 2.0's `ducklake` extension reads DuckLake 1.0
catalogs without migration. Migration is opt-in on the operator's
`ATTACH`, not a duckbox flag.

The README runbook seeds a lake with DuckDB 2.0 (`scripts/seed_ducklake.py`
in the project venv). That is the supported path: create and read a lake
today.

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
