# cli/

The server binary is the CLI.

```bash
duckbox serve --daemon ./daemons/memory.yaml [--listen HOST:PORT] [--debug-http HOST:PORT]
duckbox run --daemon FILE --spec FILE --key KEY --sql SQL [--init-sql SQL]
duckbox validate --daemon FILE --spec FILE
```

`serve` is the control plane (no lake). `run` creates a throwaway sandbox from `--spec`. `validate` runs static checks plus a throwaway sandbox lake check.
