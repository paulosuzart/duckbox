# Python examples

Start with **`quickstart.ipynb`** (or `quickstart.py` — same walkthrough, no flags).

- `duckbox_client.py` — `create_sandbox()` / `connect(sandbox=...)` / `.query()` → pandas
- `query_cli.py` — one-shot SQL with `--sandbox` / `--sql` / `--params`
- `isolation_check.py` — two named sandboxes, disjoint rows
- `authorized_views_e2e.py` — RustFS: authorized_paths view works; other prefix and direct `read_parquet` fail

Defaults: `grpc://127.0.0.1:4747`, sandbox id `acme-analyst`.
