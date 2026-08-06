#!/usr/bin/env python3
"""Fetch seen/neighboring WiFi from a UniFi controller into SQLite."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
VENV_PYTHON = ROOT / ".venv" / "bin" / "python3"
VENV_MARKER = "_UNIFI_SNOOPER_VENV"


def ensure_venv() -> None:
    """Re-exec under the project .venv if we are not already using it."""
    if os.environ.get(VENV_MARKER):
        return
    expected = str(ROOT / ".venv")
    if Path(sys.prefix).resolve() == Path(expected).resolve():
        return
    if not VENV_PYTHON.is_file():
        sys.exit(
            f"Project venv not found at {ROOT / '.venv'}. "
            f"Create it with: python3 -m venv .venv && "
            f".venv/bin/pip install -r requirements.txt"
        )
    os.environ[VENV_MARKER] = "1"
    os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), *sys.argv])


ensure_venv()

try:
    import requests
    import urllib3
except ImportError:
    sys.exit(
        "Missing dependency 'requests'. Install with:\n"
        f"  {ROOT / '.venv' / 'bin' / 'pip'} install -r {ROOT / 'requirements.txt'}"
    )

from wifi_db import (  # noqa: E402
    ensure_networks_populated,
    log_collection_run,
    open_db,
    refresh_networks_for_keys,
)

# UniFi controllers typically use a self-signed cert (same as curl -k).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def normalize_security(raw: str | None) -> str:
    if raw is None or raw == "":
        return "Other: "
    text = str(raw)
    upper = text.upper()
    if "WPA" in upper:
        return "WPA"
    if "WEP" in upper:
        return "WEP"
    if upper == "OPEN" or upper.startswith("OPEN"):
        return "Open"
    return f"Other: {text}"


def normalize_record(raw: dict[str, Any], fetched_at: int) -> dict[str, Any] | None:
    bssid = raw.get("bssid")
    ap_mac = raw.get("ap_mac")
    last_seen = raw.get("last_seen")
    if bssid is None or ap_mac is None or last_seen is None:
        return None
    essid = raw.get("essid")
    if essid is None:
        essid = ""
    return {
        "essid": str(essid),
        "bssid": str(bssid).lower(),
        "last_seen": int(last_seen),
        "report_time": int(raw["report_time"]) if raw.get("report_time") is not None else None,
        "channel": int(raw["channel"]) if raw.get("channel") is not None else None,
        "band": raw.get("band"),
        "bw": int(raw["bw"]) if raw.get("bw") is not None else None,
        "security": normalize_security(raw.get("security")),
        "signal": int(raw["signal"]) if raw.get("signal") is not None else None,
        "ap_mac": str(ap_mac).lower(),
        "is_ubnt": 1 if raw.get("is_ubnt") else 0,
        "fetched_at": fetched_at,
    }


def load_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        sys.exit(
            f"Config not found: {path}\n"
            f"Copy connection.json.example to connection.json and fill in credentials."
        )
    with path.open() as f:
        cfg = json.load(f)
    for key in ("address", "username", "password", "site"):
        if key not in cfg or cfg[key] in (None, ""):
            sys.exit(f"connection.json missing required field: {key}")
    return cfg


def login(session: requests.Session, base: str, username: str, password: str) -> str:
    url = f"{base}/api/auth/login"
    resp = session.post(
        url,
        json={"username": username, "password": password},
        headers={"Content-Type": "application/json"},
        verify=False,
        timeout=30,
    )
    if resp.status_code != 200:
        sys.exit(f"Login failed: HTTP {resp.status_code} {resp.text[:200]}")
    csrf = (
        resp.headers.get("X-CSRF-Token")
        or resp.headers.get("x-csrf-token")
        or resp.headers.get("X-CSRF-TOKEN")
    )
    if not csrf:
        sys.exit("Login succeeded but no X-CSRF-Token header was returned")
    return csrf


def fetch_rogueaps(
    session: requests.Session,
    base: str,
    site: str,
    csrf: str,
    within: int,
) -> list[dict[str, Any]]:
    url = f"{base}/proxy/network/api/s/{site}/stat/rogueap"
    resp = session.post(
        url,
        json={"within": within},
        headers={
            "Content-Type": "application/json",
            "X-CSRF-Token": csrf,
        },
        verify=False,
        timeout=60,
    )
    if resp.status_code != 200:
        sys.exit(f"rogueap fetch failed: HTTP {resp.status_code} {resp.text[:200]}")
    payload = resp.json()
    meta = payload.get("meta") or {}
    if meta.get("rc") != "ok":
        sys.exit(f"rogueap API error: {meta}")
    data = payload.get("data")
    if not isinstance(data, list):
        sys.exit("rogueap response missing data list")
    return data


def format_ts(unix: int) -> str:
    return datetime.fromtimestamp(unix, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def store_records(
    conn: sqlite3.Connection,
    records: list[dict[str, Any]],
    verbose: bool,
) -> tuple[int, int, set[tuple[str, str]]]:
    new_count = 0
    existing_count = 0
    touched: set[tuple[str, str]] = set()
    insert_sql = """
        INSERT OR IGNORE INTO seen_wifi (
            essid, bssid, last_seen, report_time, channel, band, bw,
            security, signal, ap_mac, is_ubnt, fetched_at
        ) VALUES (
            :essid, :bssid, :last_seen, :report_time, :channel, :band, :bw,
            :security, :signal, :ap_mac, :is_ubnt, :fetched_at
        )
    """
    for rec in records:
        cur = conn.execute(insert_sql, rec)
        is_new = cur.rowcount == 1
        if is_new:
            new_count += 1
            label = "NEW"
            touched.add((rec["essid"], rec["bssid"]))
        else:
            existing_count += 1
            label = "EXISTING"
        if verbose:
            print(
                f"{label}  {rec['essid'] or '(hidden)'}  "
                f"{rec['bssid']}  {format_ts(rec['last_seen'])}"
            )
    conn.commit()
    return new_count, existing_count, touched


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Download UniFi seen WiFi (rogueap) into a local SQLite database."
    )
    p.add_argument(
        "--within",
        type=int,
        default=24,
        metavar="HOURS",
        help="Fetch APs seen within this many hours (default: 24)",
    )
    p.add_argument(
        "--config",
        type=Path,
        default=ROOT / "connection.json",
        help="Path to connection.json (default: ./connection.json)",
    )
    p.add_argument(
        "--db",
        type=Path,
        default=ROOT / "seen_wifi.db",
        help="SQLite database path (default: ./seen_wifi.db)",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="List each record as NEW or EXISTING",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.within < 1:
        sys.exit("--within must be at least 1")

    started_at = int(datetime.now(tz=timezone.utc).timestamp())
    cfg = load_config(args.config)
    base = f"https://{cfg['address']}"
    fetched_at = started_at

    session = requests.Session()
    csrf = login(session, base, cfg["username"], cfg["password"])
    raw_rows = fetch_rogueaps(session, base, cfg["site"], csrf, args.within)

    records: list[dict[str, Any]] = []
    for raw in raw_rows:
        rec = normalize_record(raw, fetched_at)
        if rec is not None:
            records.append(rec)

    conn = open_db(args.db)
    try:
        ensure_networks_populated(conn)
        new_count, existing_count, touched = store_records(conn, records, args.verbose)
        if touched:
            refresh_networks_for_keys(conn, touched)
        finished_at = int(datetime.now(tz=timezone.utc).timestamp())
        log_collection_run(
            conn,
            started_at=started_at,
            finished_at=finished_at,
            new_count=new_count,
            existing_count=existing_count,
            within_hours=args.within,
            fetched_rows=len(records),
        )
    finally:
        conn.close()

    print(f"{new_count} new records ({existing_count} already present)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
