# Tests

Three CTest-labeled binaries. `make test` runs all of them.

| Label | Binary | What |
| --- | --- | --- |
| `unit` | `duckbox_unit_tests` | Spec YAML, validator, rewriter, synthetic plan guard, initSQL, handles, registry, metrics |
| `guardrails` | `duckbox_guardrail_tests` | Table-driven SQL corpus in `guardrails/cases.yaml` |
| `integration` | `duckbox_integration_tests` | TenantSandbox execute, idle/list/expire, fake S3 registry, caller auth, in-process Flight SQL |

Add a new bypass as a YAML case (`id`, `sql`, `expect: allow|deny`, optional `reason` / `stage` / `contains`). Reviewer repros live here. Handle forgery and stale versions stay in unit `handle` / `registry`. DuckLake + S3 e2e stays in CI (`ducklake-e2e`).

Shared fixtures: `test/support/check.hpp`.

Local coverage: unit 233, guardrails 79, integration 140 (452 assertions). `make coverage` instruments `server/src` with gcov (75.1% line, target ≥75%). CI also runs `ducklake-e2e`.
