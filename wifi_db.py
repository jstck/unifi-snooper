"""Shared SQLite helpers for UniFi seen-WiFi collection and scoring."""

from __future__ import annotations

import math
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

SCHEMA = """
CREATE TABLE IF NOT EXISTS seen_wifi (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    essid TEXT NOT NULL,
    bssid TEXT NOT NULL,
    last_seen INTEGER NOT NULL,
    report_time INTEGER,
    channel INTEGER,
    band TEXT,
    bw INTEGER,
    security TEXT,
    signal INTEGER,
    ap_mac TEXT NOT NULL,
    is_ubnt INTEGER NOT NULL DEFAULT 0,
    fetched_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_seen_wifi_identity
    ON seen_wifi (bssid, essid, ap_mac, last_seen);

CREATE TABLE IF NOT EXISTS collection_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at INTEGER NOT NULL,
    finished_at INTEGER NOT NULL,
    new_count INTEGER NOT NULL,
    existing_count INTEGER NOT NULL,
    within_hours INTEGER,
    fetched_rows INTEGER
);

CREATE TABLE IF NOT EXISTS networks (
    essid TEXT NOT NULL,
    bssid TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    times_seen INTEGER NOT NULL,
    days_seen INTEGER NOT NULL,
    ap_count INTEGER NOT NULL DEFAULT 0,
    last_security TEXT,
    last_channel INTEGER,
    last_band TEXT,
    last_signal INTEGER,
    PRIMARY KEY (essid, bssid)
);

CREATE TABLE IF NOT EXISTS ssid_name_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    pattern TEXT NOT NULL,
    item_score REAL NOT NULL DEFAULT 1.0,
    enabled INTEGER NOT NULL DEFAULT 1,
    notes TEXT
);
"""

DEFAULT_SSID_NAME_RULES: list[dict[str, Any]] = [
    {
        "label": "chromecast_fallback",
        "pattern": r"^.+\.[A-Za-z],$",
        "item_score": 1.0,
        "notes": "Chromecast setup hotspot when device cannot reach WiFi",
    },
    {
        "label": "dlink_default",
        "pattern": r"(?i)^dlink",
        "item_score": 1.0,
        "notes": "Typical D-Link default SSID",
    },
]


@dataclass
class ScoreWeights:
    """Tweakable weights for stationary confidence scoring."""

    days_seen: float = 0.35
    times_seen: float = 0.15
    span_days: float = 0.25
    ap_count: float = 0.15
    name_rules: float = 1.0  # multiplies matched rule item_score sum


DEFAULT_SCORE_WEIGHTS = ScoreWeights()


@dataclass
class NameRule:
    label: str
    pattern: str
    item_score: float
    notes: str | None = None

    def matches(self, essid: str) -> bool:
        return re.search(self.pattern, essid) is not None


@dataclass
class NetworkFeatures:
    essid: str
    bssid: str
    first_seen: int
    last_seen: int
    times_seen: int
    days_seen: int
    ap_count: int = 0
    last_security: str | None = None
    last_channel: int | None = None
    last_band: str | None = None
    last_signal: int | None = None


@dataclass
class ScoreResult:
    score: float
    features: NetworkFeatures
    matched_rules: list[str]
    components: dict[str, float]


def open_db(path: Path | str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    ensure_schema(conn)
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    seed_ssid_name_rules(conn)
    conn.commit()


def seed_ssid_name_rules(conn: sqlite3.Connection) -> None:
    count = conn.execute("SELECT COUNT(*) FROM ssid_name_rules").fetchone()[0]
    if count:
        return
    conn.executemany(
        """
        INSERT INTO ssid_name_rules (label, pattern, item_score, enabled, notes)
        VALUES (:label, :pattern, :item_score, 1, :notes)
        """,
        DEFAULT_SSID_NAME_RULES,
    )


def utc_day_key(unix_ts: int) -> str:
    return datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime("%Y-%m-%d")


def days_seen_from_timestamps(timestamps: Sequence[int]) -> int:
    """Count calendar-day changes walking timestamps in chronological order."""
    if not timestamps:
        return 0
    ordered = sorted(timestamps)
    days = 1
    prev_day = utc_day_key(ordered[0])
    for ts in ordered[1:]:
        day = utc_day_key(ts)
        if day != prev_day:
            days += 1
            prev_day = day
    return days


def rebuild_networks(conn: sqlite3.Connection) -> int:
    """Rebuild networks aggregates from all seen_wifi rows. Returns network count."""
    conn.execute("DELETE FROM networks")
    rows = conn.execute(
        """
        SELECT essid, bssid, last_seen, ap_mac, security, channel, band, signal
        FROM seen_wifi
        ORDER BY essid, bssid, last_seen
        """
    ).fetchall()

    current_key: tuple[str, str] | None = None
    stamps: list[int] = []
    aps: set[str] = set()
    first_seen = 0
    last_seen = 0
    last_security: str | None = None
    last_channel: int | None = None
    last_band: str | None = None
    last_signal: int | None = None
    inserted = 0

    def flush() -> None:
        nonlocal inserted
        if current_key is None:
            return
        essid, bssid = current_key
        conn.execute(
            """
            INSERT INTO networks (
                essid, bssid, first_seen, last_seen, times_seen, days_seen,
                ap_count, last_security, last_channel, last_band, last_signal
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                essid,
                bssid,
                first_seen,
                last_seen,
                len(stamps),
                days_seen_from_timestamps(stamps),
                len(aps),
                last_security,
                last_channel,
                last_band,
                last_signal,
            ),
        )
        inserted += 1

    for row in rows:
        key = (row["essid"], row["bssid"])
        if key != current_key:
            flush()
            current_key = key
            stamps = []
            aps = set()
            first_seen = int(row["last_seen"])
            last_seen = first_seen
            last_security = row["security"]
            last_channel = row["channel"]
            last_band = row["band"]
            last_signal = row["signal"]
        stamps.append(int(row["last_seen"]))
        last_seen = int(row["last_seen"])
        if row["ap_mac"]:
            aps.add(row["ap_mac"])
        last_security = row["security"]
        last_channel = row["channel"]
        last_band = row["band"]
        last_signal = row["signal"]
    flush()
    conn.commit()
    return inserted


def ensure_networks_populated(conn: sqlite3.Connection) -> None:
    count = conn.execute("SELECT COUNT(*) FROM networks").fetchone()[0]
    raw = conn.execute("SELECT COUNT(*) FROM seen_wifi").fetchone()[0]
    if raw and not count:
        rebuild_networks(conn)


def refresh_networks_for_keys(
    conn: sqlite3.Connection,
    keys: Iterable[tuple[str, str]],
) -> None:
    """Recompute aggregate rows for the given (essid, bssid) keys."""
    unique_keys = sorted({(e, b) for e, b in keys})
    for essid, bssid in unique_keys:
        rows = conn.execute(
            """
            SELECT last_seen, ap_mac, security, channel, band, signal
            FROM seen_wifi
            WHERE essid = ? AND bssid = ?
            ORDER BY last_seen
            """,
            (essid, bssid),
        ).fetchall()
        if not rows:
            conn.execute(
                "DELETE FROM networks WHERE essid = ? AND bssid = ?",
                (essid, bssid),
            )
            continue
        stamps = [int(r["last_seen"]) for r in rows]
        aps = {r["ap_mac"] for r in rows if r["ap_mac"]}
        last = rows[-1]
        conn.execute(
            """
            INSERT INTO networks (
                essid, bssid, first_seen, last_seen, times_seen, days_seen,
                ap_count, last_security, last_channel, last_band, last_signal
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(essid, bssid) DO UPDATE SET
                first_seen = excluded.first_seen,
                last_seen = excluded.last_seen,
                times_seen = excluded.times_seen,
                days_seen = excluded.days_seen,
                ap_count = excluded.ap_count,
                last_security = excluded.last_security,
                last_channel = excluded.last_channel,
                last_band = excluded.last_band,
                last_signal = excluded.last_signal
            """,
            (
                essid,
                bssid,
                stamps[0],
                stamps[-1],
                len(stamps),
                days_seen_from_timestamps(stamps),
                len(aps),
                last["security"],
                last["channel"],
                last["band"],
                last["signal"],
            ),
        )
    conn.commit()


def log_collection_run(
    conn: sqlite3.Connection,
    *,
    started_at: int,
    finished_at: int,
    new_count: int,
    existing_count: int,
    within_hours: int | None = None,
    fetched_rows: int | None = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO collection_runs (
            started_at, finished_at, new_count, existing_count,
            within_hours, fetched_rows
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (started_at, finished_at, new_count, existing_count, within_hours, fetched_rows),
    )
    conn.commit()
    return int(cur.lastrowid)


def load_ssid_name_rules(conn: sqlite3.Connection, *, enabled_only: bool = True) -> list[NameRule]:
    sql = "SELECT label, pattern, item_score, notes FROM ssid_name_rules"
    if enabled_only:
        sql += " WHERE enabled = 1"
    sql += " ORDER BY id"
    return [
        NameRule(
            label=row["label"],
            pattern=row["pattern"],
            item_score=float(row["item_score"]),
            notes=row["notes"],
        )
        for row in conn.execute(sql)
    ]


def _squash(value: float, scale: float) -> float:
    """Map non-negative value into (0, 1) with diminishing returns."""
    if value <= 0 or scale <= 0:
        return 0.0
    return 1.0 - math.exp(-value / scale)


def score_stationary(
    features: NetworkFeatures,
    rules: Sequence[NameRule],
    weights: ScoreWeights | None = None,
) -> ScoreResult:
    """Compute a stationary-confidence score without writing it to the DB."""
    w = weights or DEFAULT_SCORE_WEIGHTS
    span_days = max(0.0, (features.last_seen - features.first_seen) / 86400.0)

    matched = [r.label for r in rules if r.matches(features.essid)]
    rule_score = sum(r.item_score for r in rules if r.matches(features.essid))

    components = {
        "days_seen": w.days_seen * _squash(float(features.days_seen), scale=5.0),
        "times_seen": w.times_seen * _squash(float(features.times_seen), scale=20.0),
        "span_days": w.span_days * _squash(span_days, scale=14.0),
        "ap_count": w.ap_count * _squash(float(features.ap_count), scale=2.0),
        "name_rules": w.name_rules * rule_score,
    }
    score = sum(components.values())
    return ScoreResult(
        score=score,
        features=features,
        matched_rules=matched,
        components=components,
    )


def load_network_features(conn: sqlite3.Connection) -> list[NetworkFeatures]:
    ensure_networks_populated(conn)
    rows = conn.execute(
        """
        SELECT essid, bssid, first_seen, last_seen, times_seen, days_seen,
               ap_count, last_security, last_channel, last_band, last_signal
        FROM networks
        """
    ).fetchall()
    return [
        NetworkFeatures(
            essid=row["essid"],
            bssid=row["bssid"],
            first_seen=int(row["first_seen"]),
            last_seen=int(row["last_seen"]),
            times_seen=int(row["times_seen"]),
            days_seen=int(row["days_seen"]),
            ap_count=int(row["ap_count"] or 0),
            last_security=row["last_security"],
            last_channel=row["last_channel"],
            last_band=row["last_band"],
            last_signal=row["last_signal"],
        )
        for row in rows
    ]
