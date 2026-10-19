#!/usr/bin/env python3
"""Walk through a duckbox session: query, bind a parameter, isolation, rejection.

No flags. Defaults: grpc://127.0.0.1:4747 and policies/ducklake/analyst.yaml.
Override with DUCKBOX_URL / DUCKBOX_SPEC (or connect(spec=..., url=...)).

    python examples/python/quickstart.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from duckbox_client import connect, format_error  # noqa: E402

SQL = "SELECT id, title, amount FROM deals ORDER BY id"


def show(title: str, df) -> None:
    print(f"\n{title}")
    print(df.to_string(index=False))


def main() -> int:
    # Same SQL, two keys — each sandbox only sees its tenant's live rows.
    with connect(key="tenant_21:user_sergio") as sergio, connect(key="tenant_22:user_kim") as kim:
        deals = sergio.query(SQL)
        show("Sergio (tenant 21) — live deals", deals)

        one = sergio.query("SELECT id, title, amount FROM deals WHERE id = ?", [1])
        show("Prepared statement: id = ?", one)

        kim_deals = kim.query(SQL)
        show("Kim (tenant 22) — same SQL", kim_deals)

        sergio_ids = [int(v) for v in deals["id"].tolist()]
        kim_ids = [int(v) for v in kim_deals["id"].tolist()]
        print(f"\nids  tenant_21={sergio_ids}  tenant_22={kim_ids}")
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
