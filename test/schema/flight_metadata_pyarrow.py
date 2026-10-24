#!/usr/bin/env python3
"""Document Flight SQL metadata offset alignment for third-party clients.

gRPC zero-copy can deliver String/Binary offset buffers misaligned.
That is not a server-side guarantee. pyarrow / ADBC / JDBC must set
IpcReadOptions.ensure_alignment = DataTypeSpecific on the reader.

This script asserts the aligned reader path. The option-off path is
logged only (alignment without the option is environment-dependent).
"""

from __future__ import annotations

import argparse
import os
import sys

import pyarrow as pa
import pyarrow.flight as flight
import pyarrow.ipc as ipc


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


def offset_addrs(table: pa.Table) -> list[tuple[str, int, int]]:
    """(column, chunk_index, offset_buffer_address) for string/binary columns."""
    out: list[tuple[str, int, int]] = []
    for col in table.columns:
        for i, chunk in enumerate(col.chunks):
            if not pa.types.is_string(chunk.type) and not pa.types.is_binary(chunk.type):
                continue
            bufs = chunk.buffers()
            if len(bufs) < 2 or bufs[1] is None:
                continue
            out.append((col._name, i, bufs[1].address))
    return out


def report_offsets(table: pa.Table, label: str) -> list[tuple[str, int, int]]:
    addrs = offset_addrs(table)
    for name, i, addr in addrs:
        print(f"{label} {name} chunk {i} offsets at {addr:#x} align={_align(addr)}")
    return addrs


def expect_offset_aligned(table: pa.Table, label: str) -> None:
    """Require 4-byte alignment on string/binary offsets, then read values."""
    for name, i, addr in offset_addrs(table):
        if addr % 4 != 0:
            _fail(
                f"{label} {name} chunk {i} offsets at {addr:#x} "
                f"align={_align(addr)} (need 4/8 after ensure_alignment)"
            )
        # Reading values is the ARM64 SIGSEGV path when offsets are unaligned.
    for col in table.columns:
        for chunk in col.chunks:
            if pa.types.is_string(chunk.type) or pa.types.is_binary(chunk.type):
                _ = chunk.to_pylist()
    print(f"ok {label} rows={table.num_rows} cols={table.num_columns} offsets aligned")


def log_offset_alignment(table: pa.Table, label: str) -> None:
    """Log the no-option path. Do not assert: hosts may already align."""
    addrs = report_offsets(table, label)
    if not addrs:
        print(f"note {label} has no string/binary offset buffers to inspect")
        return
    mis = [(name, i, addr) for name, i, addr in addrs if addr % 4 != 0]
    print(
        f"note {label} buffers={len(addrs)} misaligned={len(mis)} "
        "(logged only; enable ensure_alignment on the reader)"
    )


def do_command(client: flight.FlightClient, options: flight.FlightCallOptions, cmd: bytes) -> pa.Table:
    desc = flight.FlightDescriptor.for_command(cmd)
    info = client.get_flight_info(desc, options)
    if not info.endpoints:
        _fail("command returned no ticket")
    reader = client.do_get(info.endpoints[0].ticket, options)
    return reader.read_all()


def alignment_option():
    # pyarrow 26: Alignment.DataTypeSpecific. Older names kept as fallbacks.
    align = getattr(ipc, "Alignment", None)
    if align is not None:
        for name in ("DataTypeSpecific", "DATA_TYPE_SPECIFIC", "kDataTypeSpecificAlignment"):
            if hasattr(align, name):
                return getattr(align, name)
    return -3


def call_options(headers: list[tuple[bytes, bytes]], *, ensure: bool) -> flight.FlightCallOptions:
    if not ensure:
        return flight.FlightCallOptions(headers=headers)
    read = ipc.IpcReadOptions(ensure_alignment=alignment_option())
    return flight.FlightCallOptions(headers=headers, read_options=read)


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
        addrs = report_offsets(objects, "ADBC get_objects (no reader alignment option)")
        mis = sum(1 for _, _, addr in addrs if addr % 4 != 0)
        print(
            f"ok ADBC get_objects rows={objects.num_rows} "
            f"misaligned_buffers={mis} (enable reader alignment on ADBC/JDBC)"
        )
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
    raw = call_options(headers, ensure=False)
    aligned = call_options(headers, ensure=True)
    client = flight.FlightClient(args.url)

    include_cmd = command_get_tables(include_schema=True, table_name="nested_t")
    include_raw = do_command(client, raw, include_cmd)
    if include_raw.num_rows < 1:
        include_cmd = command_get_tables(include_schema=True)
        include_raw = do_command(client, raw, include_cmd)
    log_offset_alignment(include_raw, "pyarrow GetTables include_schema (no ensure_alignment)")

    include_ok = do_command(client, aligned, include_cmd)
    expect_offset_aligned(include_ok, "pyarrow GetTables include_schema (ensure_alignment)")

    for label, cmd in (
        ("pyarrow GetCatalogs", command_get_catalogs()),
        ("pyarrow GetDbSchemas", command_get_db_schemas()),
        ("pyarrow GetTableTypes", command_get_table_types()),
        ("pyarrow GetTables", command_get_tables(include_schema=False)),
    ):
        expect_offset_aligned(do_command(client, aligned, cmd), f"{label} (ensure_alignment)")

    if "table_name" in include_ok.column_names:
        names = include_ok.column("table_name").to_pylist()
        if "nested_t" in names:
            q = do_command(client, aligned, command_statement_query("SELECT lst, st, mp FROM nested_t"))
            if q.num_rows < 1:
                _fail("nested_t query returned no rows")
            print(f"ok pyarrow nested query rows={q.num_rows}")

    run_adbc(args.url, args.sandbox, args.key, args.caller)
    print("ok pyarrow documents metadata alignment (client ensure_alignment required)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
