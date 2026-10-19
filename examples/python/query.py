#!/usr/bin/env python3
"""ADBC Flight SQL client. Sends tenant key + sandbox spec YAML per connection."""

from __future__ import annotations

import argparse
import base64
import pathlib
import sys

from adbc_driver_flightsql import dbapi


def encode_spec(yaml_text: str) -> str:
    # gRPC metadata cannot contain newlines; send base64url(YAML).
    return base64.urlsafe_b64encode(yaml_text.encode("utf-8")).decode("ascii")


def connect(url: str, key: str, spec_yaml: str, init_sql: str = "", spec_dir: str = ""):
    kwargs = {
        "adbc.flight.sql.rpc.call_header.x-duckbox-key": key,
        "adbc.flight.sql.rpc.call_header.x-duckbox-spec": encode_spec(spec_yaml),
    }
    if spec_dir:
        kwargs["adbc.flight.sql.rpc.call_header.x-duckbox-spec-dir"] = spec_dir
    if init_sql:
        kwargs["adbc.flight.sql.rpc.call_header.x-duckbox-init-sql"] = init_sql
    return dbapi.connect(url, db_kwargs=kwargs)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="grpc://127.0.0.1:4747")
    p.add_argument("--key", default="tenant_21:user_sergio")
    p.add_argument("--spec", default="policies/memory/analyst.yaml")
    p.add_argument("--sql", default="SELECT id, title, amount FROM deals ORDER BY id")
    p.add_argument("--params", nargs="*", default=None, help="optional positional params")
    p.add_argument("--init-sql", default="")
    args = p.parse_args()
    spec_path = pathlib.Path(args.spec)
    spec_yaml = spec_path.read_text()
    with connect(args.url, args.key, spec_yaml, args.init_sql, str(spec_path.resolve().parent)) as conn:
        with conn.cursor() as cur:
            if args.params:
                cur.execute(args.sql, tuple(int(x) if x.isdigit() else x for x in args.params))
            else:
                cur.execute(args.sql)
            table = cur.fetch_arrow_table()
    print(table)
    print(table.to_pydict())
    if "id" in table.column_names:
        print("ids:", [int(v) for v in table.column("id").to_pylist()])
    return 0


if __name__ == "__main__":
    sys.exit(main())
