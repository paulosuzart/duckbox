# extension/

Not in this draft. A later client-side DuckDB extension could look like:

```sql
LOAD duckbox;
ATTACH 'duckbox:host=127.0.0.1 port=4747 key=tenant_21:user_sergio policy=analyst' AS dbox;
SELECT * FROM dbox.deals;
-- or
SELECT * FROM duckbox_query('SELECT id, amount FROM deals');
```

That work is deferred so the first runnable path can stay Arrow Flight SQL plus ADBC.
