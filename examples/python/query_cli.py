#!/usr/bin/env python3
"""Command-line utility: run one SQL string against duckbox (ADBC Flight SQL).

Most people want `quickstart.py` / `quickstart.ipynb` instead. This script is
for one-off queries and CI-style flags.

    python examples/python/query_cli.py
    python examples/python/query_cli.py --sql 'SELECT id FROM deals WHERE id = ?' --params 1
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from duckbox_client import connect, format_error  # noqa: E402


def main() -> int:
    """Parse flags, run one statement, print the DataFrame or a stripped error."""
    p = argparse.ArgumentParser(description="Run one SQL statement against a local duckbox.")
    p.add_argument("--url", default=None, help="Flight SQL URL (default grpc://127.0.0.1:4747)")
    p.add_argument("--sandbox", default="acme-analyst", help="named sandbox id")
    p.add_argument("--key", default="", help="optional per-query key (definition key is used otherwise)")
    p.add_argument("--sql", default="SELECT id, title, amount FROM deals ORDER BY id")
    p.add_argument("--params", nargs="*", default=None, help="positional bind values")
    args = p.parse_args()
    params = None
    if args.params:
        params = tuple(int(x) if x.isdigit() else x for x in args.params)
    try:
        with connect(sandbox=args.sandbox, key=args.key, url=args.url) as db:
            df = db.query(args.sql, params)
    except Exception as exc:  # noqa: BLE001
        print(format_error(exc), file=sys.stderr)
        return 1
    print(df.to_string(index=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
