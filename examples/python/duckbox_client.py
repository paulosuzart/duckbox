"""Tiny ADBC Flight SQL helper. Typical use is three or four lines:

    from duckbox_client import connect
    db = connect()  # tenant_21, localhost, bundled spec
    print(db.query("SELECT id, title, amount FROM deals"))
"""

from __future__ import annotations

import base64
import os
import time
from pathlib import Path
from typing import Any, Optional, Sequence, Union

import pandas as pd
from adbc_driver_flightsql import dbapi

PathLike = Union[str, Path]

DEFAULT_URL = "grpc://127.0.0.1:4747"
DEFAULT_KEY = "tenant_21:user_sergio"


def repo_root() -> Path:
    here = Path(__file__).resolve().parent
    return here.parent.parent


def default_spec_path() -> Path:
    override = os.environ.get("DUCKBOX_SPEC")
    if override:
        return Path(override)
    return repo_root() / "policies" / "ducklake" / "analyst.yaml"


def encode_spec(yaml_text: str) -> str:
    # gRPC metadata cannot contain newlines; send base64url(YAML).
    return base64.urlsafe_b64encode(yaml_text.encode("utf-8")).decode("ascii")


def format_error(exc: BaseException) -> str:
    """Strip ADBC/Flight wrapping so the sandbox reason is readable."""
    msg = str(exc)
    for marker in ("Invalid Error: ", "[FlightSQL] ", "INVALID_ARGUMENT: "):
        if marker in msg:
            msg = msg.split(marker)[-1]
    msg = msg.split("(InvalidArgument")[0].split("(IO:")[0].strip()
    msg = msg.rstrip(" )")
    return msg or str(exc)


class Duckbox:
    """One tenant connection. `.query()` returns a pandas DataFrame."""

    def __init__(self, conn: Any, key: str, spec_path: Path):
        self._conn = conn
        self.key = key
        self.spec_path = spec_path

    def query(self, sql: str, params: Optional[Sequence[Any]] = None) -> pd.DataFrame:
        with self._conn.cursor() as cur:
            if params is None:
                cur.execute(sql)
            else:
                cur.execute(sql, tuple(params))
            table = cur.fetch_arrow_table()
        return table.to_pandas()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Duckbox":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def connect(
    key: str = DEFAULT_KEY,
    spec: Optional[PathLike] = None,
    url: Optional[str] = None,
    init_sql: str = "",
    retries: int = 20,
) -> Duckbox:
    url = url or os.environ.get("DUCKBOX_URL", DEFAULT_URL)
    spec_path = Path(spec) if spec else default_spec_path()
    if not spec_path.is_file():
        raise FileNotFoundError(f"sandbox spec not found: {spec_path}")
    spec_yaml = spec_path.read_text()
    kwargs = {
        "adbc.flight.sql.rpc.call_header.x-duckbox-key": key,
        "adbc.flight.sql.rpc.call_header.x-duckbox-spec": encode_spec(spec_yaml),
        "adbc.flight.sql.rpc.call_header.x-duckbox-spec-dir": str(spec_path.resolve().parent),
    }
    if init_sql:
        kwargs["adbc.flight.sql.rpc.call_header.x-duckbox-init-sql"] = init_sql

    last: Optional[BaseException] = None
    for _ in range(max(retries, 1)):
        try:
            conn = dbapi.connect(url, db_kwargs=kwargs)
            return Duckbox(conn, key, spec_path)
        except Exception as exc:  # noqa: BLE001
            text = str(exc).lower()
            if "connection refused" in text or "failed to connect" in text or "unavailable" in text:
                last = exc
                time.sleep(0.5)
                continue
            raise
    hint = "./build/duckbox serve --daemon ./daemons/ducklake.yaml"
    raise ConnectionError(f"duckbox is not listening on {url}. Start it with: {hint}") from last


def query(
    sql: str,
    params: Optional[Sequence[Any]] = None,
    key: str = DEFAULT_KEY,
    spec: Optional[PathLike] = None,
    url: Optional[str] = None,
) -> pd.DataFrame:
    with connect(key=key, spec=spec, url=url) as db:
        return db.query(sql, params)
