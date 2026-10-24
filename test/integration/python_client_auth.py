#!/usr/bin/env python3
"""Exercise the Python client against an auth-enabled duckbox daemon.

The C++ suite starts the daemon and passes --url / --token. This script never
prints the token. Failures that leak the credential are treated as test failures.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "examples" / "python"))

from duckbox_client import connect, create_sandbox, format_error, resolve_token  # noqa: E402


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def _expect_no_token(text: str, secrets: list[str], what: str) -> None:
    for secret in secrets:
        if secret and secret in text:
            _fail(f"{what} echoed a credential")


def _expect_unauth(fn, secrets: list[str], what: str) -> None:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        text = format_error(exc)
        raw = str(exc)
        _expect_no_token(text, secrets, what)
        _expect_no_token(raw, secrets, what)
        low = raw.lower()
        if "unauthenticated" not in low and "unauth" not in low and "invalid caller" not in low:
            # Auth-enabled daemons reject missing/wrong Bearer as Unauthenticated.
            if "permission" not in low and "denied" not in low:
                _fail(f"{what} raised an unexpected error: {text}")
        print(f"ok {what}")
        return
    _fail(f"{what} did not fail")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--token", default=None)
    parser.add_argument("--spec", default=str(ROOT / "policies" / "memory" / "analyst.yaml"))
    args = parser.parse_args()
    token = resolve_token(args.token)
    if not token:
        _fail("a token is required (pass --token or DUCKBOX_TOKEN)")

    os.environ.pop("DUCKBOX_TOKEN", None)

    secrets = [token, "wrong-secret-token"]
    _expect_unauth(
        lambda: create_sandbox(
            sandbox="py-unauth",
            key="tenant_21:user_sergio",
            spec=args.spec,
            url=args.url,
            caller="analyst-svc",
        ),
        secrets,
        "create_sandbox without a token",
    )
    _expect_unauth(
        lambda: create_sandbox(
            sandbox="py-wrong",
            key="tenant_21:user_sergio",
            spec=args.spec,
            url=args.url,
            caller="analyst-svc",
            token="wrong-secret-token",
        ),
        secrets,
        "create_sandbox with the wrong token",
    )
    def _query_without_token() -> None:
        # ADBC connect is lazy; the first RPC is what the daemon authenticates.
        with connect(
            sandbox="py-auth",
            url=args.url,
            retries=1,
            caller="analyst-svc",
        ) as db:
            db.query("SELECT id FROM deals")

    _expect_unauth(_query_without_token, secrets, "query without a token")

    created = create_sandbox(
        sandbox="py-auth",
        key="tenant_21:user_sergio",
        spec=args.spec,
        url=args.url,
        caller="analyst-svc",
        token=token,
    )
    _expect_no_token(created, secrets, "create_sandbox result")
    if "py-auth" not in created:
        _fail("create_sandbox with a token did not return the sandbox id")
    print("ok create_sandbox with token")

    with connect(
        sandbox="py-auth",
        url=args.url,
        retries=1,
        token=token,
        caller="analyst-svc",
    ) as db:
        df = db.query("SELECT id, title FROM deals ORDER BY id")
        ids = [int(v) for v in df["id"].tolist()]
        if ids != [1]:
            _fail("query with a token did not see the tenant row")
    print("ok connect+query with token")

    os.environ["DUCKBOX_TOKEN"] = token
    try:
        created_env = create_sandbox(
            sandbox="py-env",
            key="tenant_21:user_sergio",
            spec=args.spec,
            url=args.url,
            caller="analyst-svc",
        )
        _expect_no_token(created_env, secrets, "create_sandbox via DUCKBOX_TOKEN")
        if "py-env" not in created_env:
            _fail("create_sandbox via DUCKBOX_TOKEN did not return the sandbox id")
        with connect(sandbox="py-env", url=args.url, retries=1, caller="analyst-svc") as db:
            rows = db.query("SELECT id FROM deals")
            if rows.empty:
                _fail("connect via DUCKBOX_TOKEN returned no rows")
        print("ok create_sandbox/connect via DUCKBOX_TOKEN")
    finally:
        os.environ.pop("DUCKBOX_TOKEN", None)

    print("ok python client authenticates with Authorization: Bearer")
    return 0


if __name__ == "__main__":
    sys.exit(main())
