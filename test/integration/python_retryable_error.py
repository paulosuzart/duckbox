#!/usr/bin/env python3
"""Prove retryable Flight errors on the wire for pyarrow and, when present, ADBC.

The C++ suite starts an in-process Duckbox Flight SQL server and passes --url.
This script never treats tenant-facing errors as an oracle for secret values.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import pyarrow.flight as flight

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "examples" / "python"))
sys.path.insert(0, str(ROOT / "test" / "schema"))

from flight_metadata_pyarrow import command_statement_query  # noqa: E402


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def _extra_info(exc: BaseException) -> Any:
    raw = getattr(exc, "extra_info", b"")
    if raw is None:
        return {}
    if isinstance(raw, bytes):
        if not raw:
            return {}
        raw = raw.decode("utf-8")
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc_json:
        _fail(f"extra_info is not JSON: {exc_json}")
    return {}


def _check_prefix(text: str, prefix: str, what: str) -> None:
    if not text.startswith(prefix) and prefix not in text:
        _fail(f"{what} message does not contain {prefix!r}: {text}")


def _pyarrow_get_flight_info(url: str, sandbox: str, sql: str) -> None:
    client = flight.FlightClient(url)
    opt = flight.FlightCallOptions(
        headers=[
            (b"x-duckbox-sandbox", sandbox.encode()),
            (b"x-duckbox-caller", b"local"),
        ]
    )
    desc = flight.FlightDescriptor.for_command(command_statement_query(sql))
    client.get_flight_info(desc, opt)


def _expect_unavailable(
    url: str,
    sandbox: str,
    sql: str,
    prefix: str,
    extra_code: str,
    owner: str,
    address: str,
    what: str,
) -> None:
    try:
        _pyarrow_get_flight_info(url, sandbox, sql)
    except flight.FlightUnavailableError as exc:
        text = str(exc)
        _check_prefix(text, prefix, what)
        extra = _extra_info(exc)
        if extra.get("code") != extra_code:
            _fail(f"{what} extra_info code: {extra!r}")
        if owner:
            if owner not in text:
                _fail(f"{what} message does not name owner {owner}: {text}")
            if extra.get("owner") != owner:
                _fail(f"{what} extra_info owner: {extra!r}")
        elif "owner" in extra:
            _fail(f"{what} extra_info must omit owner: {extra!r}")
        if address:
            if address not in text:
                _fail(f"{what} message does not name address {address}: {text}")
            if extra.get("address") != address:
                _fail(f"{what} extra_info address: {extra!r}")
        elif "address" in extra:
            _fail(f"{what} extra_info must omit address: {extra!r}")
        print(f"ok pyarrow FlightUnavailableError {what}")
        return
    except flight.FlightError as exc:
        _fail(f"{what} raised {type(exc).__name__}, not FlightUnavailableError: {exc}")
    _fail(f"{what} did not fail")


def _expect_policy(url: str, sandbox: str, sql: str) -> None:
    try:
        _pyarrow_get_flight_info(url, sandbox, sql)
    except flight.FlightUnavailableError as exc:
        _fail(f"policy violation must not be FlightUnavailableError: {exc}")
    except Exception as exc:  # noqa: BLE001 — ArrowInvalid / FlightError both prove unchanged status
        name = type(exc).__name__
        if "Unavailable" in name:
            _fail(f"policy violation must not be {name}: {exc}")
        print(f"ok pyarrow policy violation keeps a non-Unavailable status ({name})")
        return
    _fail("policy violation did not fail")


def _adbc_query(url: str, sandbox: str, sql: str) -> None:
    from duckbox_client import query

    query(sql, sandbox=sandbox, url=url, key="tenant_21:user_sergio")


def _adbc_expect_unavailable(url: str, sandbox: str, sql: str, prefix: str, what: str) -> None:
    try:
        import adbc_driver_flightsql  # noqa: F401
        from adbc_driver_manager import AdbcStatusCode
    except ImportError:
        print(f"skip ADBC {what} (adbc_driver_flightsql not installed)")
        return
    try:
        _adbc_query(url, sandbox, sql)
    except Exception as exc:  # noqa: BLE001
        text = str(exc)
        status = getattr(exc, "status_code", None)
        if prefix not in text:
            _fail(f"ADBC {what} message does not contain {prefix!r}: {text}")
        if "(Unavailable;" not in text:
            _fail(f"ADBC {what} message does not contain '(Unavailable;': {text}")
        if status != AdbcStatusCode.IO:
            _fail(f"ADBC {what} status_code is {status!r}, want AdbcStatusCode.IO: {text}")
        print(f"ok ADBC {what}")
        return
    _fail(f"ADBC {what} did not fail")


def _adbc_expect_policy(url: str, sandbox: str, sql: str) -> None:
    try:
        import adbc_driver_flightsql  # noqa: F401
    except ImportError:
        print("skip ADBC policy (adbc_driver_flightsql not installed)")
        return
    try:
        _adbc_query(url, sandbox, sql)
    except Exception as exc:  # noqa: BLE001
        text = str(exc)
        if "(Unavailable;" in text or "no_owner:" in text or "owner_moved:" in text:
            _fail(f"ADBC policy violation looks retryable/Unavailable: {text}")
        print("ok ADBC policy violation keeps a non-retryable status")
        return
    _fail("ADBC policy violation did not fail")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--sandbox", required=True)
    parser.add_argument(
        "--expect",
        required=True,
        choices=("no_owner", "owner_moved", "owner_moved_anon", "policy"),
    )
    parser.add_argument("--sql", required=True)
    parser.add_argument("--owner", default="")
    parser.add_argument("--address", default="")
    args = parser.parse_args()

    if args.expect == "no_owner":
        _expect_unavailable(
            args.url, args.sandbox, args.sql, "no_owner:", "no_owner", "", "", "no_owner GetFlightInfo"
        )
        _adbc_expect_unavailable(args.url, args.sandbox, args.sql, "no_owner:", "no_owner")
    elif args.expect == "owner_moved":
        _expect_unavailable(
            args.url,
            args.sandbox,
            args.sql,
            "owner_moved:",
            "owner_moved",
            args.owner,
            args.address,
            "owner_moved GetFlightInfo",
        )
        _adbc_expect_unavailable(args.url, args.sandbox, args.sql, "owner_moved:", "owner_moved")
    elif args.expect == "owner_moved_anon":
        _expect_unavailable(
            args.url,
            args.sandbox,
            args.sql,
            "owner_moved:",
            "owner_moved",
            "",
            "",
            "owner_moved without owner",
        )
        _adbc_expect_unavailable(
            args.url, args.sandbox, args.sql, "owner_moved:", "owner_moved without owner"
        )
    else:
        _expect_policy(args.url, args.sandbox, args.sql)
        _adbc_expect_policy(args.url, args.sandbox, args.sql)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
