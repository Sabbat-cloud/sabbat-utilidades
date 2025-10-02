README_en.md
# 📊 sabbat-analizalogs — Advanced Log Analyzer

> *“Your logs have a story to tell. sabbat-analizalogs deciphers it for you.”*

`sabbat-analizalogs` is a production-ready Python 3 log analyzer. It reads standard or compressed logs (`.gz`), supports streaming from `stdin`, and outputs rich statistics, security signals, and JSON reports.

---

## 🌍 Language

- Auto-detects console language (`LC_ALL`, `LC_MESSAGES`, `LANGUAGE`, `LANG`).
- Force with `--lang {auto|en|es}` (default: `auto`).

---

## ✨ Highlights

**Security & Correctness**
- ✅ **Safe output confinement**: `--output` is restricted to the current working directory (CWD).  
  Use `--unsafe-output` to allow writing outside CWD; `--force` to overwrite.
- ✅ **ANSI sanitization** (default) to prevent terminal escape injection.
- ✅ **Hardened regex** for SQLi, path traversal, and XSS.
- ✅ **Bias-free caps** for `--max-ips` / `--max-errors` (existing keys keep counting).
- ✅ **UTC time filtering** with robust ISO/Apache parsing and TZ normalization.

**Usability**
- ✅ Bilingual help & output (`--lang` + auto-detect).
- ✅ Two layouts: columns (default) and list (`--list-view`).
- ✅ Tunable tops: `--top-urls`, `--top-uas`, `--top-ips`.
- ✅ JSON enriched with `schema_version`, selected `lang`, and `parameters_used`.

---

## Requirements

- Python 3.8+ (3.7 supported with limited `fromisoformat` behavior).
- Dependencies:
  ```txt
  geoip2>=4.6.0


Optional GeoIP DB: GeoLite2-Country.mmdb (e.g., /var/lib/GeoIP/), or set --geoip-db.

Installation
git clone https://github.com/sabbat-cloud/sabbat-utilidades
cd sabbat-utilidades
pip install -r requirements.txt
# or: pip install .


If installed via pip install ., the CLI entrypoint sabbat-analizalogs is available on your PATH.

Usage
# Full analysis (columns)
sabbat-analizalogs access.log

# List view
sabbat-analizalogs access.log --list-view

# Pattern search (first 50 matches)
sabbat-analizalogs error.log -p "Timeout" -c 50

# JSON output
sabbat-analizalogs app.log --json

# Save JSON to file (confined to CWD)
sabbat-analizalogs app.log --json --output reports/result.json

# Time filter (interpreted as UTC)
sabbat-analizalogs access.log --since 2024-01-01 --until "2024-01-31 23:59:59"

# Pipeline
zcat access.log.gz | sabbat-analizalogs - --json

# Force English UI
sabbat-analizalogs access.log --lang en

Options
Option	Description
file	Log file (.gz or - for stdin)
--lang {auto,en,es}	Interface language (default: auto)
-p, --pattern REGEX	Regex to search for
-c, --count N	Number of matched lines to show (default: 10)
--json	Output JSON
--output PATH	Save results (confined to CWD unless --unsafe-output)
--force	Overwrite existing output file
--unsafe-output	Allow writing outside CWD (dangerous)
--list-view	List layout
--since DATETIME	Filter from this UTC datetime
--until DATETIME	Filter up to this UTC datetime
--max-ips N	Cap number of unique IPs tracked
--max-errors N	Cap number of unique errors tracked
--geoip-db PATH	Alternate GeoIP DB path
-v, --verbose	Verbose logging
--no-sanitize-ansi	Do not strip ANSI escapes
--top-urls N	Top URLs to display (default: 5)
--top-uas N	Top User-Agents to display (default: 5)
--top-ips N	Top IPs to display (default: 20)
Example Output (columns)
=== LOG STATISTICS ===
Total lines: 123,456
Errors: 120 | Warnings: 45
Period: From 2024-01-01 00:00:00 to 2024-01-31 23:59:59

Detected Security Alerts:
SQL Injection (5) | Xss Attempt (2)

--------------------------------------------------------------------------------
HTTP Status Codes:
  - Code 200: 102345 times
  - Code 404: 1234 times
  Summary by range:
    - 2xx: 102345 requests
    - 4xx: 1234 requests

Top 5 Requested URLs:
  - (5000) /index.html
  - (4000) /login

Top 10 IPs with Geolocation:
COUNT   IP                 COUNTRY
-----   ------------------ ---------------
234     203.0.113.5        United States
...

JSON Schema (excerpt)
{
  "schema_version": "1.2.0",
  "generated_at": "2025-10-02T12:34:56Z",
  "lang": "en",
  "summary": {
    "file": "access.log",
    "total_lines": 123456,
    "total_errors": 120,
    "total_warnings": 45,
    "period": { "from": "2024-01-01 00:00:00", "to": "2024-01-31 23:59:59" }
  },
  "parameters_used": {
    "max_ips": null,
    "max_errors": null,
    "top_urls": 5,
    "top_uas": 5,
    "top_ips": 20
  },
  "security_alerts": { "sql_injection": 5, "xss_attempt": 2 }
}

Security Hardening

Output confinement (prevents ../../ tricks) unless --unsafe-output is set.

ANSI sanitization by default.

Hardened patterns for SQLi / traversal / XSS.

UTC normalization for reliable time filtering.

License

MIT
