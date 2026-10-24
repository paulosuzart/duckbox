#!/usr/bin/env python3
"""Create a small DuckLake (Postgres catalog, Parquet on RustFS) with two tenants."""

from __future__ import annotations

import argparse
import time

import boto3
import duckdb
from botocore.config import Config
from botocore.exceptions import ClientError


DEALS = [
    (21, 1, "alpha deal", 100, False),
    (21, 2, "alpha deleted", 1, True),
    (22, 3, "bravo deal", 500, False),
    (22, 4, "bravo two", 50, False),
]
# DuckLake inlines small inserts in the catalog. More than 1000 extra rows
# (or DATA_INLINING_ROW_LIMIT 0) forces Parquet on S3 so duckbox reads files
# written by the seed engine. Tenant 99 is invisible to the e2e rewriter checks.
FILLER = [(99, 1000 + i, f"filler {i}", i, False) for i in range(1100)]


def wait_s3(endpoint: str, key: str, secret: str) -> None:
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=key,
        aws_secret_access_key=secret,
        region_name="us-east-1",
        config=Config(s3={"addressing_style": "path"}),
    )
    deadline = time.time() + 60
    last = None
    while time.time() < deadline:
        try:
            client.list_buckets()
            return
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(1)
    raise SystemExit(f"RustFS not reachable at {endpoint}: {last}")


def ensure_bucket(endpoint: str, key: str, secret: str, bucket: str) -> None:
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=key,
        aws_secret_access_key=secret,
        region_name="us-east-1",
        config=Config(s3={"addressing_style": "path"}),
    )
    try:
        client.create_bucket(Bucket=bucket)
        print(f"created bucket {bucket}")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise
        print(f"bucket {bucket} already exists")


def list_parquet(endpoint: str, key: str, secret: str, bucket: str) -> list[str]:
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=key,
        aws_secret_access_key=secret,
        region_name="us-east-1",
        config=Config(s3={"addressing_style": "path"}),
    )
    found: list[str] = []
    token = None
    while True:
        kwargs = {"Bucket": bucket, "Prefix": "data/"}
        if token:
            kwargs["ContinuationToken"] = token
        resp = client.list_objects_v2(**kwargs)
        for obj in resp.get("Contents") or []:
            name = obj.get("Key") or ""
            if name.endswith(".parquet"):
                found.append(name)
        if not resp.get("IsTruncated"):
            break
        token = resp.get("NextContinuationToken")
        if not token:
            break
    return found


def seed(args: argparse.Namespace) -> None:
    wait_s3(args.s3_endpoint, args.s3_key, args.s3_secret)
    ensure_bucket(args.s3_endpoint, args.s3_key, args.s3_secret, args.bucket)
    ensure_bucket(args.s3_endpoint, args.s3_key, args.s3_secret, args.control_bucket)

    host = args.s3_endpoint.replace("http://", "").replace("https://", "")
    use_ssl = args.s3_endpoint.startswith("https://")
    con = duckdb.connect()
    print(f"seed duckdb_version={duckdb.__version__}")
    con.execute("INSTALL httpfs; LOAD httpfs;")
    con.execute("INSTALL postgres; LOAD postgres;")
    con.execute("INSTALL ducklake; LOAD ducklake;")
    con.execute(
        f"""
        CREATE OR REPLACE SECRET duckbox_s3 (
            TYPE s3, PROVIDER config,
            KEY_ID '{args.s3_key}',
            SECRET '{args.s3_secret}',
            ENDPOINT '{host}',
            URL_STYLE 'path',
            USE_SSL {str(use_ssl).lower()},
            REGION 'us-east-1',
            SCOPE 's3://'
        )
        """
    )
    catalog = (
        f"ducklake:postgres:dbname={args.pg_db} host={args.pg_host} "
        f"port={args.pg_port} user={args.pg_user} password={args.pg_password}"
    )
    data_path = f"s3://{args.bucket}/data/"
    try:
        con.execute("SET ducklake_default_data_inlining_row_limit = 0")
    except Exception as exc:  # noqa: BLE001
        print(f"ducklake_default_data_inlining_row_limit unsettable: {exc}")
    try:
        con.execute(
            f"ATTACH '{catalog}' AS lake (DATA_PATH '{data_path}', DATA_INLINING_ROW_LIMIT 0)"
        )
        print("attached with DATA_INLINING_ROW_LIMIT 0")
    except Exception as exc:  # noqa: BLE001
        print(f"DATA_INLINING_ROW_LIMIT not usable ({exc}); attaching without it")
        con.execute(f"ATTACH '{catalog}' AS lake (DATA_PATH '{data_path}')")
    con.execute("USE lake")
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS deals (
            tenant_id INTEGER,
            id INTEGER,
            title VARCHAR,
            amount INTEGER,
            _deleted BOOLEAN
        )
        """
    )
    count = con.execute("SELECT count(*) FROM deals").fetchone()[0]
    if count == 0:
        con.executemany("INSERT INTO deals VALUES (?, ?, ?, ?, ?)", DEALS)
        con.executemany("INSERT INTO deals VALUES (?, ?, ?, ?, ?)", FILLER)
        print(f"inserted {len(DEALS)} tenant deals and {len(FILLER)} filler rows")
    else:
        print(f"deals already has {count} rows; leaving as-is")
    print(
        con.execute(
            "SELECT tenant_id, id, title, amount, _deleted FROM deals "
            "WHERE tenant_id IN (21, 22) ORDER BY id"
        ).fetchall()
    )
    try:
        snaps = con.execute("SELECT * FROM ducklake_snapshots('lake') LIMIT 3").fetchall()
        print(f"ducklake_snapshots={snaps}")
    except Exception as exc:  # noqa: BLE001
        print(f"ducklake_snapshots unavailable: {exc}")
    parquet = list_parquet(args.s3_endpoint, args.s3_key, args.s3_secret, args.bucket)
    if not parquet:
        raise SystemExit(
            "seed wrote no Parquet under s3://{}/data/ (still inlined in the catalog)".format(
                args.bucket
            )
        )
    print(f"parquet_objects={len(parquet)} first={parquet[0]}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--s3-endpoint", default="http://127.0.0.1:9000")
    parser.add_argument("--s3-key", default="rustfsadmin")
    parser.add_argument("--s3-secret", default="rustfsadmin")
    parser.add_argument("--bucket", default="duckbox-lake")
    parser.add_argument("--control-bucket", default="duckbox-control")
    parser.add_argument("--pg-host", default="127.0.0.1")
    parser.add_argument("--pg-port", default="5432")
    parser.add_argument("--pg-user", default="duckbox")
    parser.add_argument("--pg-password", default="duckbox")
    parser.add_argument("--pg-db", default="ducklake")
    seed(parser.parse_args())


if __name__ == "__main__":
    main()
