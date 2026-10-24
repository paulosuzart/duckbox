#!/usr/bin/env python3
"""Non-C++ Flight SQL client: pyarrow + ADBC read metadata streams.

Inspects String/Binary offset-buffer alignment on GetCatalogs, GetDbSchemas,
GetTables (with include_schema), and GetTableTypes. Does not set
IpcReadOptions.ensure_alignment — the server must send 4/8-byte-aligned
offsets so third-party readers (pyarrow, ADBC, Go) are safe.
"""

from __future__ import annotations

import argparse
import os
import sys

import pyarrow as pa
import pyarrow.flight as flight


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        bits = n & 0x7F
        n >>= 7
        out.append(bits | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _tag(field: int, wire: int) -> bytes:
    return _varint((field << 3) | wire)


def _len_field(field: int, payload: bytes) -> bytes:
    return _tag(field, 2) + _varint(len(payload)) + payload


def encode_any(type_url: str, value: bytes = b"") -> bytes:
    """google.protobuf.Any used as a Flight SQL command body."""
    return _len_field(1, type_url.encode("utf-8")) + _len_field(2, value)


def command_get_catalogs() -> bytes:
    return encode_any("type.googleapis.com/arrow.flight.protocol.sql.CommandGetCatalogs")


def command_get_db_schemas() -> bytes:
    return encode_any("type.googleapis.com/arrow.flight.protocol.sql.CommandGetDbSchemas")


def command_get_table_types() -> bytes:
    return encode_any("type.googleapis.com/arrow.flight.protocol.sql.CommandGetTableTypes")


def command_get_tables(*, include_schema: bool, table_name: str | None = None) -> bytes:
    body = b""
    if table_name:
        body += _len_field(3, table_name.encode("utf-8"))
    if include_schema:
        body += _tag(5, 0) + _varint(1)
    return encode_any("type.googleapis.com/arrow.flight.protocol.sql.CommandGetTables", body)


def command_statement_query(sql: str) -> bytes:
    return encode_any(
        "type.googleapis.com/arrow.flight.protocol.sql.CommandStatementQuery",
        _len_field(1, sql.encode("utf-8")),
    )


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def _align(addr: int) -> int:
    return addr % 8


def expect_offset_aligned(table: pa.Table, label: str) -> None:
    """Require 4-byte (and prefer 8-byte) alignment on string/binary offsets."""
    for col in table.columns:
        for i, chunk in enumerate(col.chunks):
            if not pa.types.is_string(chunk.type) and not pa.types.is_binary(chunk.type):
                continue
            bufs = chunk.buffers()
            if len(bufs) < 2 or bufs[1] is None:
                continue
            addr = bufs[1].address
            if addr % 4 != 0:
                _fail(
                    f"{label} {col._name} chunk {i} offsets at {addr:#x} "
                    f"align={_align(addr)} (need 4/8)"
                )
            # Reading values is the ARM64 SIGSEGV path when offsets are unaligned.
            _ = chunk.to_pylist()
    print(f"ok {label} rows={table.num_rows} cols={table.num_columns} offsets aligned")


def do_command(client: flight.FlightClient, options: flight.FlightCallOptions, cmd: bytes) -> pa.Table:
    desc = flight.FlightDescriptor.for_command(cmd)
    info = client.get_flight_info(desc, options)
    if not info.endpoints:
        _fail("command returned no ticket")
    reader = client.do_get(info.endpoints[0].ticket, options)
    return reader.read_all()


def run_adbc(url: str, sandbox: str, key: str, caller: str) -> None:
    from adbc_driver_flightsql import dbapi

    kwargs = {
        "adbc.flight.sql.rpc.call_header.x-duckbox-sandbox": sandbox,
        "adbc.flight.sql.rpc.call_header.x-duckbox-caller": caller,
    }
    if key:
        kwargs["adbc.flight.sql.rpc.call_header.x-duckbox-key"] = key
    with dbapi.connect(url, db_kwargs=kwargs) as conn:
        objects = conn.adbc_get_objects()
        if hasattr(objects, "read_all"):
            objects = objects.read_all()
        if objects is None or objects.num_rows < 1:
            _fail("ADBC get_objects returned no rows")
        expect_offset_aligned(objects, "ADBC get_objects")
        target = "nested_t"
        try:
            schema = conn.adbc_get_table_schema(target)
        except Exception:  # noqa: BLE001
            schema = conn.adbc_get_table_schema("deals")
            target = "deals"
        if schema is None or len(schema) < 1:
            _fail(f"ADBC get_table_schema({target}) empty")
        print(f"ok ADBC get_table_schema({target}) fields={len(schema)}")
        if target == "nested_t":
            ids = {f.name: f.type for f in schema}
            checks = (
                ("lst", pa.types.is_list),
                ("st", pa.types.is_struct),
                ("mp", pa.types.is_map),
            )
            for col, pred in checks:
                if col in ids and not pred(ids[col]):
                    _fail(f"ADBC include_schema {col} is {ids[col]}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=os.environ.get("DUCKBOX_URL", "grpc://127.0.0.1:4747"))
    parser.add_argument("--sandbox", default=os.environ.get("DUCKBOX_SANDBOX", "acme-analyst"))
    parser.add_argument("--key", default=os.environ.get("DUCKBOX_KEY", "tenant_21:user_sergio"))
    parser.add_argument("--caller", default=os.environ.get("DUCKBOX_CALLER", "local"))
    args = parser.parse_args()

    headers = [
        (b"x-duckbox-sandbox", args.sandbox.encode()),
        (b"x-duckbox-caller", args.caller.encode()),
    ]
    if args.key:
        headers.append((b"x-duckbox-key", args.key.encode()))
    options = flight.FlightCallOptions(headers=headers)
    client = flight.FlightClient(args.url)

    catalogs = do_command(client, options, command_get_catalogs())
    expect_offset_aligned(catalogs, "pyarrow GetCatalogs")
    schemas = do_command(client, options, command_get_db_schemas())
    expect_offset_aligned(schemas, "pyarrow GetDbSchemas")
    types = do_command(client, options, command_get_table_types())
    expect_offset_aligned(types, "pyarrow GetTableTypes")
    tables = do_command(client, options, command_get_tables(include_schema=False))
    expect_offset_aligned(tables, "pyarrow GetTables")

    include = do_command(client, options, command_get_tables(include_schema=True, table_name="nested_t"))
    if include.num_rows < 1:
        include = do_command(client, options, command_get_tables(include_schema=True))
    expect_offset_aligned(include, "pyarrow GetTables include_schema")
    if "table_name" in include.column_names:
        names = include.column("table_name").to_pylist()
        if "nested_t" in names:
            q = do_command(client, options, command_statement_query("SELECT lst, st, mp FROM nested_t"))
            if q.num_rows < 1:
                _fail("nested_t query returned no rows")
            print(f"ok pyarrow nested query rows={q.num_rows}")

    run_adbc(args.url, args.sandbox, args.key, args.caller)
    print("ok pyarrow/ADBC metadata alignment")
    return 0


if __name__ == "__main__":
    sys.exit(main())
