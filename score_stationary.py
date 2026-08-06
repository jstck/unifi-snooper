#!/usr/bin/env python3
"""Score networks for how likely they are stationary WiFi."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

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

from wifi_db import (  # noqa: E402
    DEFAULT_SCORE_WEIGHTS,
    ScoreResult,
    load_network_features,
    load_ssid_name_rules,
    open_db,
    score_stationary,
)

SORT_CHOICES = (
    "confidence",
    "confidence_asc",
    "last_seen",
    "first_seen",
    "essid",
    "times_seen",
    "days_seen",
)


def format_ts(unix: int) -> str:
    return datetime.fromtimestamp(unix, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Score aggregated WiFi networks for stationary confidence. "
            "Weights are defined in wifi_db.ScoreWeights / DEFAULT_SCORE_WEIGHTS."
        )
    )
    p.add_argument(
        "--db",
        type=Path,
        default=ROOT / "seen_wifi.db",
        help="SQLite database path (default: ./seen_wifi.db)",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=50,
        metavar="N",
        help="Show first N results (default: 50)",
    )
    p.add_argument(
        "--sort",
        choices=SORT_CHOICES,
        default="confidence",
        help="Sort order (default: confidence descending)",
    )
    p.add_argument(
        "--min-score",
        type=float,
        default=None,
        help="Only show results with score >= this value",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Include per-component score breakdown",
    )
    return p.parse_args(argv)


def sort_key(result: ScoreResult, sort: str):
    f = result.features
    if sort == "confidence":
        return (-result.score, f.essid.lower(), f.bssid)
    if sort == "confidence_asc":
        return (result.score, f.essid.lower(), f.bssid)
    if sort == "last_seen":
        return (-f.last_seen, f.essid.lower(), f.bssid)
    if sort == "first_seen":
        return (-f.first_seen, f.essid.lower(), f.bssid)
    if sort == "essid":
        return (f.essid.lower(), f.bssid)
    if sort == "times_seen":
        return (-f.times_seen, f.essid.lower(), f.bssid)
    if sort == "days_seen":
        return (-f.days_seen, f.essid.lower(), f.bssid)
    raise ValueError(f"unknown sort: {sort}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.limit < 1:
        sys.exit("--limit must be at least 1")

    weights = DEFAULT_SCORE_WEIGHTS
    conn = open_db(args.db)
    try:
        rules = load_ssid_name_rules(conn)
        features = load_network_features(conn)
    finally:
        conn.close()

    results = [score_stationary(f, rules, weights) for f in features]
    if args.min_score is not None:
        results = [r for r in results if r.score >= args.min_score]
    results.sort(key=lambda r: sort_key(r, args.sort))
    results = results[: args.limit]

    print(
        f"{'SCORE':>7}  {'DAYS':>4}  {'TIMES':>5}  {'APS':>3}  "
        f"{'FIRST_SEEN':<20}  {'LAST_SEEN':<20}  ESSID  BSSID  RULES"
    )
    for r in results:
        f = r.features
        essid = f.essid or "(hidden)"
        rules_s = ",".join(r.matched_rules) if r.matched_rules else "-"
        print(
            f"{r.score:7.3f}  {f.days_seen:4d}  {f.times_seen:5d}  {f.ap_count:3d}  "
            f"{format_ts(f.first_seen):<20}  {format_ts(f.last_seen):<20}  "
            f"{essid}  {f.bssid}  {rules_s}"
        )
        if args.verbose:
            parts = " ".join(f"{k}={v:.3f}" for k, v in r.components.items())
            print(f"         components: {parts}")

    print(f"\nShowing {len(results)} of scored networks (sort={args.sort})")
    print(
        "Weights: "
        f"days_seen={weights.days_seen} times_seen={weights.times_seen} "
        f"span_days={weights.span_days} ap_count={weights.ap_count} "
        f"name_rules={weights.name_rules}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
