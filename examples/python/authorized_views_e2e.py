#!/usr/bin/env python3
"""RustFS e2e: authorized_paths + authorized views over read_parquet.

Creates named sandbox acme-authz from policies/ducklake/authz.yaml:
- view over s3://duckbox-lake/authorized/ works
- view over s3://duckbox-lake/forbidden/ fails
- agent read_parquet() directly is denied
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from duckbox_client import connect, create_sandbox, format_error, repo_root  # noqa: E402


def main() -> int:
    spec = repo_root() / "policies" / "ducklake" / "authz.yaml"
    print(f"creating named sandbox acme-authz from {spec}")
    print(" ", create_sandbox(sandbox="acme-authz", key="tenant_21:user_sergio", spec=spec))

    with connect(sandbox="acme-authz") as db:
        ok = db.query("SELECT id, title FROM parquet_ok")
        print("\nauthorized prefix view")
        print(ok.to_string(index=False))
        titles = [str(v) for v in ok["title"].tolist()]
        if "authorized parquet" not in titles:
            print("FAIL: expected authorized parquet row", file=sys.stderr)
            return 1

        print("\nnon-authorized prefix view (must fail)")
        try:
            leaked = db.query("SELECT id, title FROM parquet_no")
            print("FAIL: expected forbidden prefix view to be denied, got:", leaked, file=sys.stderr)
            return 1
        except Exception as exc:  # noqa: BLE001
            print("  ", format_error(exc))

        print("\ndirect read_parquet (must fail)")
        try:
            leaked = db.query("SELECT * FROM read_parquet('s3://duckbox-lake/authorized/ok.parquet')")
            print("FAIL: expected direct read_parquet to be denied, got:", leaked, file=sys.stderr)
            return 1
        except Exception as exc:  # noqa: BLE001
            print("  ", format_error(exc))

    print("\nok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
