#!/usr/bin/env python3
"""Call duckbox over HTTP and print Arrow results for the calling tenant."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request

import pyarrow as pa
import pyarrow.ipc as ipc


def query(url: str, key: str, policy: str, sql: str) -> pa.Table:
    body = json.dumps({"sql": sql}).encode("utf-8")
    req = urllib.request.Request(
        url.rstrip("/") + "/v1/query",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Duckbox-Key": key,
            "X-Duckbox-Policy": policy,
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            content_type = resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        err = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"HTTP {exc.code}: {err}") from exc
    if "json" in content_type:
        raise SystemExit(raw.decode("utf-8", errors="replace"))
    try:
        return ipc.open_stream(raw).read_all()
    except pa.ArrowInvalid:
        return ipc.open_file(raw).read_all()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:4747")
    parser.add_argument("--key", default="tenant_21:user_sergio")
    parser.add_argument("--policy", default="analyst")
    parser.add_argument("--sql", default="SELECT id, title, amount FROM deals ORDER BY id")
    args = parser.parse_args()
    table = query(args.url, args.key, args.policy, args.sql)
    print(table)
    print(table.to_pydict())
    tenants = table.column("id") if "id" in table.column_names else None
    if tenants is not None:
        ids = [int(v) for v in tenants.to_pylist()]
        print("ids:", ids)


if __name__ == "__main__":
    sys.exit(main())
