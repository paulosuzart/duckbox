# cli/

The server binary is the CLI.

```bash
duckbox serve --daemon ./daemons/memory.yaml [--listen HOST:PORT] [--internal-listen HOST:PORT] [--metrics HOST:PORT] [--debug-http HOST:PORT]
duckbox sandbox create|get|update|delete|list|expire --url grpc://127.0.0.1:4747 [--spec FILE] [--id ID] [--key KEY]
duckbox sandbox list [--id-prefix P] [--key-prefix P] [--policy-class C] [--state warm|passive|defined] [--limit N] [--offset N]
duckbox sandbox expire --id ID
duckbox node drain --url grpc://127.0.0.1:5747 [--timeout 5000] [--caller local]
duckbox run --daemon FILE --spec FILE --key KEY --sql SQL
duckbox validate --daemon FILE --spec FILE
```

`serve` is the control plane (no lake). It binds a **public** Flight SQL listener (`--listen`) and an **internal** peer/operator listener (`--internal-listen`, default loopback). Named sandbox definitions live in the registry (memory, or S3 next to leases). Prometheus `/metrics` is on by default (`127.0.0.1:9477`). Queries send `x-duckbox-sandbox` (id) + SQL. `node drain` talks to the internal listener and requires `auth.operators`. Never expose the internal listener publicly. `run` creates a throwaway DuckDB from `--spec`. `validate` runs static checks plus a throwaway sandbox lake check.
