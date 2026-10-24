# Tests

Four CTest-labeled binaries. `make test` runs all of them.

| Label | Binary | What |
| --- | --- | --- |
| `unit` | `duckbox_unit_tests` | Spec YAML, validator, rewriter (incl. CTE scope), DuckDB 2.0 deny surfaces, lambda new/old syntax, storage format, DuckLake ATTACH SQL, handles, registry, metrics |
| `unit` | `duckbox_s3_credentials_tests` | Lake/lease S3 credential modes, allowlists, SQL shape, default-chain/IRSA provider selection |
| `schema` | `duckbox_schema_tests` | Flight SQL advertised Arrow types (`LogicalTypeFromName`, `count(*)` int64, LIST/STRUCT/MAP, VARIANT) |
| `guardrails` | `duckbox_guardrail_tests` | Table-driven SQL corpus in `guardrails/cases.yaml` |
| `guardrails` | `duckbox_s3_secret_guardrail_tests` | Warm sandbox cannot list/read/change/drop lake secrets or `SET s3_*` |
| `integration` | `duckbox_integration_tests` | TenantSandbox execute, idle/list/expire, fake S3 registry, caller auth, in-process Flight SQL, DuckDB 2.0 runtime denials, lambda new/old syntax, storage-format denials |
| `integration` | `duckbox_s3_sts_tests` | RustFS STS / credential_chain (skips live hops if RustFS is down) |

Add a new bypass as a YAML case (`id`, `sql`, `expect: allow|deny`, optional `reason` / `stage` / `contains`). Reviewer repros live here. Handle forgery and stale versions stay in unit `handle` / `registry`. Lambda syntax has **separate** unit and integration suites (`lambda_new_syntax` / `lambda_old_syntax`) plus matching guardrail cases. DuckLake + S3 e2e stays in CI: `readme-runbook` (2.0 seed + quickstart) and `ducklake-compat` (CI requires a 1.5.6-created lake via `DUCKBOX_REQUIRE_LAKE_ENGINE=1.5.6`, then duckbox 2.0; see `docs/ducklake-compatibility.md`). Multi-node e2e is lease failover only (memory policy, RustFS).

Shared fixtures: `test/support/check.hpp`.

Local coverage: unit + guardrails + integration. `make coverage` instruments `server/src` and reports **gcovr** line coverage (target ≥75%). CI runs the same script; DuckLake e2e is `readme-runbook` plus `ducklake-compat`.
