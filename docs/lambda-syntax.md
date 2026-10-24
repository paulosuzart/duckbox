# Lambda syntax (DuckDB 2.0)

DuckDB 2.0 accepts Python-style lambdas and disables the old single-arrow
form. DuckDB 2.1 removes the arrow form and the `lambda_syntax` flag.

| Syntax | Example | duckbox |
| --- | --- | --- |
| Python-style (default) | `lambda x : x + 1` | Accepted by the rewriter. The lambda body is walked; every function still needs to be allowlisted. |
| Single-arrow (removed in 2.1) | `x -> x + 1` | Denied. The rewriter rejects a parsed arrow lambda first (`single-arrow lambda syntax is denied`). If a statement reached the engine, the binder would fail later because warmup locked `lambda_syntax=disable_single_arrow`. |
| JSON arrow | `col -> '$.a'` | Denied as a single-arrow lambda (`single-arrow lambda syntax is denied`). DuckDB still parses `->` as `LambdaExpression`. |
| Multi-parameter | `lambda x, y : x + y` | Denied (`multi-parameter lambda is denied`). |

`SET` / `RESET` of `lambda_syntax` is agent-denied (`only SELECT`). Bootstrap
SQL cannot `SET` it either. There is no way to turn arrow lambdas back on
inside a sandbox.

`COLUMNS(lambda c : …)` is the same rule: Python-style is accepted and
tenant-wrapped; `COLUMNS(c -> …)` is denied as a single-arrow lambda.

## List functions and the 1.5.6 allowlist contract

`list_transform`, `list_filter`, `apply`, and the other list helpers are
ordinary catalog functions. They are **not** on the trusted exception list
(`count`, `sum`, `avg`, `min`, `max`, `lower`, `upper`, `length`,
`coalesce`, `round`, `abs`). A spec that allowlists `list_transform` is
rejected at warmup (`macro is not allowlisted: list_transform`).

List literals (`[1, 2, 3]`) parse as `list_value`. That name is also off the
exception list, so rewrite tests that use a literal add `list_value` to the
in-memory policy only.

A Python-style lambda **rewrites** when those names are on `functions:`
(guardrail / unit rewrite tests). `COLUMNS(lambda …)` parses with
`list_filter` in the AST, so it is the same rule. A warm sandbox cannot
allowlist those names today (warmup: `macro is not allowlisted`), so
lambdas do not execute until the exception list is reviewed.

Do not add `list_*` to a production spec to "make lambdas work". That fails
closed on purpose. Expanding the exception list is a separate review.

Unit suites: `lambda_new_syntax` and `lambda_old_syntax`. Integration:
`lambda_new_syntax_runtime` and `lambda_old_syntax_runtime`. Guardrail cases
use the same ids.
