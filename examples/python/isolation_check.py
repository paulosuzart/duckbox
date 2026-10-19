#!/usr/bin/env python3
"""Utility: assert two tenant keys see disjoint deals rows. Prefer quickstart.py."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from duckbox_client import connect  # noqa: E402


def main() -> int:
    sql = "SELECT id, title FROM deals ORDER BY id"
    with connect(key="tenant_21:user_sergio") as a_db, connect(key="tenant_22:user_kim") as b_db:
        a = [int(v) for v in a_db.query(sql)["id"].tolist()]
        b = [int(v) for v in b_db.query(sql)["id"].tolist()]
    print("tenant_21 ids:", a)
    print("tenant_22 ids:", b)
    if a != [1] or sorted(b) != [3, 4] or set(a) & set(b):
        print("FAIL: tenant isolation", file=sys.stderr)
        return 1
    print("isolation ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
