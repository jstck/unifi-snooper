# UniFi seen-WiFi logger

Hourly-friendly Python tool that logs into a UniFi controller, downloads neighboring/seen WiFi networks (`stat/rogueap`), and stores them in a local SQLite database for later analysis.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp connection.json.example connection.json
# edit connection.json with your controller address and credentials
```

`connection.json` is gitignored (it contains login details). Use the API site key `default` unless you know otherwise:

```json
{
  "site": "default",
  "address": "10.10.1.102",
  "username": "your-username",
  "password": "your-password"
}
```

The script always runs under the project `.venv` (it re-execs into it if needed).

## Usage

```bash
./fetch_seen_wifi.py
./fetch_seen_wifi.py -v
./fetch_seen_wifi.py --within 24 --db seen_wifi.db
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--within HOURS` | `24` | Fetch APs seen in the last N hours |
| `--config PATH` | `./connection.json` | Controller credentials |
| `--db PATH` | `./seen_wifi.db` | SQLite database file |
| `-v` / `--verbose` | off | List each record as `NEW` or `EXISTING` |

Normal output:

```text
7 new records (123 already present)
```

With `-v`, each fetched row is printed first (essid / bssid / `last_seen` UTC), then the summary line.

## Cron

```cron
0 * * * * cd /path/to/unifi-snooper && ./fetch_seen_wifi.py
```

Each run logs in fresh (no CSRF/session reuse). Overlapping windows are fine: rows are de-duplicated on `(bssid, essid, ap_mac, last_seen)`.

## Database

`seen_wifi.db` is created on first run and is gitignored. Stored fields: essid, bssid, last_seen, report_time, channel, band, bw, security (`Open` / `WEP` / `WPA` / `Other: …`), signal, ap_mac, is_ubnt, fetched_at.

## API reference

Uses the classic UniFi OS endpoints documented in the [community API wiki](https://www.ubntwiki.com/products/software/unifi-controller/api):

- `POST /api/auth/login`
- `POST /proxy/network/api/s/{site}/stat/rogueap` with `{"within": N}`
