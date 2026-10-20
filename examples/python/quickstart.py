#!/usr/bin/env python3
"""Walk through a duckbox session: query, bind a parameter, isolation, rejection.

No flags. Defaults: grpc://127.0.0.1:4747. Creates named sandboxes acme-analyst
and acme-kim from policies/ducklake/analyst.yaml (override DUCKBOX_URL / DUCKBOX_SPEC).

    python examples/python/quickstart.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from duckbox_client import connect, create_sandbox, default_spec_path, format_error  # noqa: E402

SQL = "SELECT id, title, amount FROM deals ORDER BY id"


def show(title: str, df) -> None:
    """Print a labeled DataFrame without the pandas index."""
    print(f"\n{title}")
    print(df.to_string(index=False))


def main() -> int:
    """Create two named sandboxes, query, bind a parameter, show isolation and a rejection."""
    spec = default_spec_path()
    print(f"creating named sandboxes from {spec}")
    print(" ", create_sandbox(sandbox="acme-analyst", key="tenant_21:user_sergio", spec=spec))
    print(" ", create_sandbox(sandbox="acme-kim", key="tenant_22:user_kim", spec=spec))

    with connect(sandbox="acme-analyst") as sergio, connect(sandbox="acme-kim") as kim:
        deals = sergio.query(SQL)
        show("Sergio (acme-analyst / tenant 21) — live deals", deals)

        one = sergio.query("SELECT id, title, amount FROM deals WHERE id = ?", [1])
        show("Prepared statement: id = ?", one)

        kim_deals = kim.query(SQL)
        show("Kim (acme-kim / tenant 22) — same SQL", kim_deals)

        sergio_ids = [int(v) for v in deals["id"].tolist()]
        kim_ids = [int(v) for v in kim_deals["id"].tolist()]
        print(f"\nids  acme-analyst={sergio_ids}  acme-kim={kim_ids}")
        if sergio_ids != [1] or sorted(kim_ids) != [3, 4] or set(sergio_ids) & set(kim_ids):
            print("FAIL: tenant isolation", file=sys.stderr)
            return 1

        print("\nRejected query (table `secrets` is not in the spec)")
        try:
            sergio.query("SELECT * FROM secrets")
            print("FAIL: expected secrets to be denied", file=sys.stderr)
            return 1
        except Exception as exc:  # noqa: BLE001
            print("  ", format_error(exc))

    print("\nok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
