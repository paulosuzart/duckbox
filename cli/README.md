# cli/

The server binary is the CLI.

```bash
duckbox serve --daemon ./daemons/memory.yaml [--listen HOST:PORT] [--metrics HOST:PORT] [--debug-http HOST:PORT]
duckbox sandbox create|get|update|delete|list|expire --url grpc://127.0.0.1:4747 [--spec FILE] [--id ID] [--key KEY]
duckbox sandbox list [--id-prefix P] [--key-prefix P] [--policy-class C] [--state warm|passive|defined] [--limit N] [--offset N]
duckbox sandbox expire --id ID
duckbox run --daemon FILE --spec FILE --key KEY --sql SQL [--init-sql SQL]
duckbox validate --daemon FILE --spec FILE
```

`serve` is the control plane (no lake). Named sandbox definitions live in the registry (memory, or S3 next to leases). Prometheus `/metrics` is on by default (`127.0.0.1:9477`). Queries send `x-duckbox-sandbox` (id) + SQL. `run` creates a throwaway DuckDB from `--spec`. `validate` runs static checks plus a throwaway sandbox lake check.
