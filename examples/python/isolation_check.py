#!/usr/bin/env python3
"""Tenant A must never see tenant B rows over Flight SQL."""

from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from query import connect


def ids_for(url: str, spec: str, key: str) -> list[int]:
    path = pathlib.Path(spec)
    yaml = path.read_text()
    with connect(url, key, yaml, spec_dir=str(path.resolve().parent)) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, title FROM deals ORDER BY id")
            table = cur.fetch_arrow_table()
    return [int(v) for v in table.column("id").to_pylist()]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="grpc://127.0.0.1:4747")
    p.add_argument("--spec", default="policies/ducklake/analyst.yaml")
    args = p.parse_args()
    a = ids_for(args.url, args.spec, "tenant_21:user_sergio")
    b = ids_for(args.url, args.spec, "tenant_22:user_kim")
    print("tenant_21 ids:", a)
    print("tenant_22 ids:", b)
    if a != [1]:
        print("FAIL: tenant 21 should see only id 1", file=sys.stderr)
        return 1
    if sorted(b) != [3, 4]:
        print("FAIL: tenant 22 should see ids 3,4", file=sys.stderr)
        return 1
    if set(a) & set(b):
        print("FAIL: tenant overlap", file=sys.stderr)
        return 1
    print("isolation ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
