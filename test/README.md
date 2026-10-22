# Tests

Four CTest-labeled binaries. `make test` runs all of them.

| Label | Binary | What |
| --- | --- | --- |
| `unit` | `duckbox_unit_tests` | Spec YAML, validator, rewriter (incl. CTE scope), handles, registry, metrics |
| `schema` | `duckbox_schema_tests` | Flight SQL advertised Arrow types (`LogicalTypeFromName`, `count(*)` int64, LIST/STRUCT/MAP) |
| `guardrails` | `duckbox_guardrail_tests` | Table-driven SQL corpus in `guardrails/cases.yaml` |
| `integration` | `duckbox_integration_tests` | TenantSandbox execute, idle/list/expire, fake S3 registry, caller auth, in-process Flight SQL |

Add a new bypass as a YAML case (`id`, `sql`, `expect: allow|deny`, optional `reason` / `stage` / `contains`). Reviewer repros live here. Handle forgery and stale versions stay in unit `handle` / `registry`. DuckLake + S3 e2e stays in CI (`ducklake-e2e`).

Shared fixtures: `test/support/check.hpp`.

Local coverage: unit + guardrails + integration. `make coverage` instruments `server/src` and reports **gcovr** line coverage (target ≥75%). CI runs the same script plus `ducklake-e2e`.
