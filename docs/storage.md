# Storage format (DuckDB 2.0)

DuckDB 2.0 writes new database files in storage format **v2.0.0** (version 69).
Files created by 1.x stay readable; 2.0 writes to those files keep the older
version so a 1.x process can still open them. A file created with the 2.0
default cannot be opened by 1.5.x.

## What duckbox creates

Sandbox instances are **in-memory** (`DuckDB(nullptr)`). duckbox does not
create a persistent local `.db` on warmup, query, or passivate.

Agent SQL cannot `ATTACH` a local file (`only SELECT is allowed`). Memory-lake
`lake.bootstrap_sql` cannot `ATTACH` either.

The only attach duckbox issues is the lake catalog at warmup, built by
`BuildDuckLakeAttachSql`: `DATA_PATH` and `READ_ONLY` only.

## `storage_compatibility_version`

duckbox **does not set** `storage_compatibility_version` and does not pass
`STORAGE_VERSION` on lake attach.

| Situation | What happens |
| --- | --- |
| Sandbox DuckDB | In-memory. No file, so the setting does not matter. |
| Existing DuckDB file catalog (operator-created, 1.x) | DuckDB 2.0 reads it and keeps that storage version on write. |
| New DuckDB file catalog (operator-created with 2.0) | Default v2.0.0. Fine: duckbox is 2.0-only. |
| Agent `SET storage_compatibility_version` | Denied (`only SELECT`). |

Do not pin `storage_compatibility_version` to 1.x on a 2.0-only node. That
setting exists to write files an *older* DuckDB still has to open. duckbox
does not share sandbox files with 1.5.x.

If you still run a 1.5.x process against the same DuckDB *file catalog*,
create or convert that file yourself with `STORAGE_VERSION 'v1.5.6'` (or
`SET storage_compatibility_version`) **outside** duckbox. Do not add that
option to a sandbox spec or daemon YAML — those keys are not accepted.

Lake **data** is Parquet on S3. That is not a DuckDB storage-version file.
