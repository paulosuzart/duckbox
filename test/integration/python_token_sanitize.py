#!/usr/bin/env python3
"""Separate suite: sanitize resolve_token and cover duckbox_client.query().

The C++ driver starts an auth-enabled daemon and passes --url / --token.
This script never prints the token.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "examples" / "python"))

from duckbox_client import (  # noqa: E402
    TokenError,
    create_sandbox,
    format_error,
    query,
    resolve_token,
)


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def _expect_no_token(text: str, secrets: list[str], what: str) -> None:
    for secret in secrets:
        if secret and secret in text:
            _fail(f"{what} echoed a credential")


def _expect_reject(token: Optional[str], secret: str, what: str) -> None:
    try:
        resolve_token(token)
    except TokenError as exc:
        text = str(exc)
        if text != "invalid bearer token":
            _fail(f"{what} used a non-generic error: {text!r}")
        _expect_no_token(text, [secret, token], what)
        if "\r" in text or "\n" in text or "\x00" in text:
            _fail(f"{what} echoed a control character")
        print(f"ok {what}")
        return
    except Exception as exc:  # noqa: BLE001
        _fail(f"{what} raised {type(exc).__name__}: {exc}")
    _fail(f"{what} did not fail")


def test_resolve_token() -> None:
    os.environ.pop("DUCKBOX_TOKEN", None)
    if resolve_token(None) != "":
        _fail("empty flag and unset env must yield no token")
    if resolve_token("") != "":
        _fail("empty string and unset env must yield no token")
    if resolve_token("ok-token") != "ok-token":
        _fail("plain token is returned as-is")
    if resolve_token("  ok-token  ") != "ok-token":
        _fail("leading and trailing spaces must be trimmed")
    if resolve_token("ok-token\n") != "ok-token":
        _fail("trailing newline must be trimmed")
    if resolve_token("\r\nok-token\r\n") != "ok-token":
        _fail("surrounding CRLF must be trimmed")
    if resolve_token("!ok-token~") != "!ok-token~":
        _fail("bang and tilde (0x21/0x7E) must be accepted")
    if resolve_token("\v\fok-token\f\v") != "ok-token":
        _fail("surrounding vertical tab and form feed must be trimmed")

    os.environ["DUCKBOX_TOKEN"] = "  env-token  "
    try:
        if resolve_token(None) != "env-token":
            _fail("DUCKBOX_TOKEN surrounding spaces must be trimmed")
    finally:
        os.environ.pop("DUCKBOX_TOKEN", None)

    _expect_reject("leak-crlf-TOKEN\r\nMORE", "leak-crlf-TOKEN", "CRLF inside the token")
    _expect_reject("leak\nlf-TOKEN", "leak\nlf-TOKEN", "embedded LF")
    _expect_reject("leak-nul-TOKEN\x00MORE", "leak-nul-TOKEN", "embedded NUL")
    _expect_reject("leak-del-TOKEN\x7f", "leak-del-TOKEN", "DEL control character")
    _expect_reject("   ", "   ", "whitespace-only token")
    _expect_reject("\n\t", "\n\t", "whitespace-and-control-only token")

    os.environ["DUCKBOX_TOKEN"] = "bad\r\nenv"
    try:
        _expect_reject(None, "bad", "DUCKBOX_TOKEN with embedded CRLF")
    finally:
        os.environ.pop("DUCKBOX_TOKEN", None)

    _expect_reject("LEAKTOK\u00e9X", "LEAKTOK", "UTF-8 e-acute inside the token")
    _expect_reject("LEAKTOK\u00a0X", "LEAKTOK", "NBSP inside the token")
    _expect_reject("LEAKTOK\u0085X", "LEAKTOK", "NEL U+0085 inside the token")
    _expect_reject("LEAKTOK\u00ffX", "LEAKTOK", "U+00FF inside the token")
    _expect_reject("\u00a0LEAKTOK", "LEAKTOK", "leading NBSP is not trimmed")
    _expect_reject("LEAK\tTOK", "LEAK", "tab inside the token")
    _expect_reject("A" * (100 * 1024 - 1) + "\u00e9", "AAAA", "100 KiB token fails without echoing")

    long_ascii = "LEAKLONGASCII" + "A" * (100 * 1024 - 13)
    got = resolve_token(long_ascii)
    if got != long_ascii:
        _fail("100 KiB visible-ASCII token must be accepted by resolve_token")
    print("ok 100 KiB visible-ASCII token is accepted")

    os.environ["DUCKBOX_TOKEN"] = "LEAKTOK\u00e9X"
    try:
        _expect_reject(None, "LEAKTOK", "DUCKBOX_TOKEN with e-acute")
    finally:
        os.environ.pop("DUCKBOX_TOKEN", None)
    print("ok resolve_token sanitization")


def test_query_wrapper(url: str, token: str, spec: str) -> None:
    secrets = [token]
    created = create_sandbox(
        sandbox="py-query-wrap",
        key="tenant_21:user_sergio",
        spec=spec,
        url=url,
        caller="analyst-svc",
        token=token,
    )
    _expect_no_token(created, secrets, "create_sandbox result")
    if "py-query-wrap" not in created:
        _fail("create_sandbox with a token did not return the sandbox id")

    # Module-level query() (connect + SELECT). This is the wrapper the
    # coverage review asked for; python_client_auth uses connect().query.
    df = query(
        "SELECT id FROM deals ORDER BY id",
        sandbox="py-query-wrap",
        url=url,
        token=token,
    )
    ids = [int(v) for v in df["id"].tolist()]
    if ids != [1]:
        _fail("query() wrapper did not see the tenant row")
    print("ok duckbox_client.query() wrapper")

    long_ascii = "LEAKLONGASCII" + "A" * (100 * 1024 - 13)
    try:
        create_sandbox(
            sandbox="py-long-ascii",
            key="tenant_21:user_sergio",
            spec=spec,
            url=url,
            caller="analyst-svc",
            token=long_ascii,
        )
    except Exception as exc:  # noqa: BLE001
        text = format_error(exc)
        raw = str(exc)
        _expect_no_token(text, ["LEAKLONGASCII"], "long ASCII create_sandbox")
        _expect_no_token(raw, ["LEAKLONGASCII"], "long ASCII create_sandbox")
        low = (text + " " + raw).lower()
        if "invalid bearer token" in low:
            _fail("100 KiB visible-ASCII token was rejected as invalid")
        if "metadata size exceeds limit" in low or "unauthenticated" in low or "unauth" in low:
            print("ok 100 KiB visible-ASCII token failed cleanly")
            return
        _fail(f"100 KiB visible-ASCII token raised an unexpected error: {text}")
    print("ok 100 KiB visible-ASCII token was accepted end to end")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=None)
    parser.add_argument("--token", default=None)
    parser.add_argument("--spec", default=str(ROOT / "policies" / "memory" / "analyst.yaml"))
    args = parser.parse_args()

    test_resolve_token()

    if args.url:
        token = args.token or os.environ.get("DUCKBOX_TOKEN")
        if not token:
            _fail("a token is required when --url is set")
        os.environ.pop("DUCKBOX_TOKEN", None)
        test_query_wrapper(args.url, token, args.spec)

    print("ok python token sanitization")
    return 0


if __name__ == "__main__":
    sys.exit(main())
