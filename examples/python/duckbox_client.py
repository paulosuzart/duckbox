"""Tiny ADBC Flight SQL helper. Typical use is three or four lines:

    from duckbox_client import connect
    db = connect()  # named sandbox acme-analyst, localhost
    print(db.query("SELECT id, title, amount FROM deals"))
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Optional, Sequence, Union

import pandas as pd
from adbc_driver_flightsql import dbapi

PathLike = Union[str, Path]

DEFAULT_URL = "grpc://127.0.0.1:4747"
DEFAULT_SANDBOX = "acme-analyst"
DEFAULT_KEY = "tenant_21:user_sergio"


def repo_root() -> Path:
    """Repository root (examples/python/../..). Used to find default specs."""
    here = Path(__file__).resolve().parent
    return here.parent.parent


def default_spec_path() -> Path:
    """DUCKBOX_SPEC or policies/ducklake/analyst.yaml under the repo root."""
    override = os.environ.get("DUCKBOX_SPEC")
    if override:
        return Path(override)
    return repo_root() / "policies" / "ducklake" / "analyst.yaml"


def format_error(exc: BaseException) -> str:
    """Strip ADBC/Flight wrapping so the sandbox reason is readable."""
    msg = str(exc)
    for marker in ("Invalid Error: ", "[FlightSQL] ", "INVALID_ARGUMENT: ", "Already Exists: ", "Key error: "):
        if marker in msg:
            msg = msg.split(marker)[-1]
    msg = msg.split("(InvalidArgument")[0].split("(IO:")[0].strip()
    msg = msg.rstrip(" )")
    return msg or str(exc)


class Duckbox:
    """One named-sandbox connection. `.query()` returns a pandas DataFrame."""

    def __init__(self, conn: Any, sandbox: str, key: str, url: str = DEFAULT_URL):
        """Wrap an ADBC connection already opened against `sandbox`."""
        self._conn = conn
        self.sandbox = sandbox
        self.key = key
        self.url = url

    def query(self, sql: str, params: Optional[Sequence[Any]] = None) -> pd.DataFrame:
        """Run one SELECT against this named sandbox. Optional `?` params are bound, not interpolated.

        Talk only to `url` (the load-balancer / public listener). Non-owner nodes proxy
        to the owner over the internal peer channel; clients never see peer addresses.
        """
        return self._execute(sql, params)

    def _execute(self, sql: str, params: Optional[Sequence[Any]] = None) -> pd.DataFrame:
        with self._conn.cursor() as cur:
            if params is None:
                cur.execute(sql)
            else:
                cur.execute(sql, tuple(params))
            table = cur.fetch_arrow_table()
        return table.to_pandas()

    def close(self) -> None:
        """Close the underlying ADBC connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "Duckbox":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _flight_headers(sandbox: str, key: str = "", caller: str = "local") -> list[tuple[str, str]]:
    """Per-RPC headers. There is no x-duckbox-spec-dir; bootstrap SQL is inlined in the spec body."""
    headers = [
        ("x-duckbox-sandbox", sandbox),
        ("x-duckbox-caller", caller),
    ]
    if key:
        headers.append(("x-duckbox-key", key))
    return headers


def create_sandbox(
    sandbox: str = DEFAULT_SANDBOX,
    key: str = DEFAULT_KEY,
    spec: Optional[PathLike] = None,
    url: Optional[str] = None,
    caller: str = "local",
) -> str:
    """Trusted-caller CreateSandbox (Flight DoAction). Idempotent if content matches."""
    import pyarrow.flight as flight

    url = url or os.environ.get("DUCKBOX_URL", DEFAULT_URL)
    spec_path = Path(spec) if spec else default_spec_path()
    yaml_text = spec_path.read_text()
    if not yaml_text.startswith("id:"):
        yaml_text = f"id: {sandbox}\nkey: {key}\n" + yaml_text
    # Inline relative lake.bootstrap_sql so the daemon never reads host files.
    for line in yaml_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("bootstrap_sql:") and "bootstrap_sql_inline" not in yaml_text:
            raw = stripped.split(":", 1)[1].strip().strip('"').strip("'")
            if raw and not raw.startswith("CREATE") and "\n" not in raw:
                boot = (spec_path.parent / raw).resolve()
                if boot.is_file():
                    indented = "\n".join("  " + ln for ln in boot.read_text().splitlines())
                    yaml_text += "\nbootstrap_sql_inline: |\n" + indented + "\n"
            break
    client = flight.FlightClient(url)
    options = flight.FlightCallOptions(
        headers=[(k.encode(), v.encode()) for k, v in _flight_headers(sandbox, key, caller)]
    )
    action = flight.Action("CreateSandbox", yaml_text.encode("utf-8"))
    chunks = list(client.do_action(action, options))
    return chunks[0].body.to_pybytes().decode("utf-8") if chunks else "{}"


def connect(
    sandbox: str = DEFAULT_SANDBOX,
    key: str = "",
    url: Optional[str] = None,
    retries: int = 20,
) -> Duckbox:
    """ADBC Flight SQL connection to a named sandbox. Retries only connection-refused."""
    url = url or os.environ.get("DUCKBOX_URL", DEFAULT_URL)
    sandbox = os.environ.get("DUCKBOX_SANDBOX", sandbox)
    kwargs = {
        "adbc.flight.sql.rpc.call_header.x-duckbox-sandbox": sandbox,
        "adbc.flight.sql.rpc.call_header.x-duckbox-caller": "local",
    }
    if key:
        kwargs["adbc.flight.sql.rpc.call_header.x-duckbox-key"] = key

    last: Optional[BaseException] = None
    for _ in range(max(retries, 1)):
        try:
            conn = dbapi.connect(url, db_kwargs=kwargs)
            return Duckbox(conn, sandbox, key, url=url)
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
    sandbox: str = DEFAULT_SANDBOX,
    key: str = "",
    url: Optional[str] = None,
) -> pd.DataFrame:
    """One-shot connect + SELECT. Prefer `connect()` when issuing several queries."""
    with connect(sandbox=sandbox, key=key, url=url) as db:
        return db.query(sql, params)
