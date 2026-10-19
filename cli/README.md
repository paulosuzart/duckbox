# cli/

The server binary **is** the CLI:

```bash
./build/duckbox serve --policies ./policies/memory --listen 127.0.0.1:4747
./build/duckbox query --url http://127.0.0.1:4747 --key tenant_21:user_sergio --policy analyst \
  --sql 'SELECT id, title, amount FROM deals'
```

`query` prints the Arrow IPC stream (redirect to a `.arrows` file or use `examples/python/query.py` to decode it).
