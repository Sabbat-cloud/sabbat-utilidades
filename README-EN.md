```markdown
# 📊 sabbat-analizalogs – Advanced Log Analyzer

*"Your logs have a story to tell. sabbat-analizalogs deciphers it for you."*

`sabbat-analizalogs` is an advanced log analyzer written in Python 3. It processes standard and compressed log files (.gz), providing powerful statistics and insights, such as:

- Error and warning counts.
- Top IPs with geolocation (requires a GeoIP database).
- Most frequent HTTP methods and status codes.
- Most requested URLs.
- Main User-Agents.
- Detection of suspicious activity (SQL Injection, XSS, Path Traversal).
- Time range of log events.
- Exportable results in text or JSON format.

---

## Features

- **Compressed log support**: Analyze `.gz` log files seamlessly.
- **Read from stdin**: Use `-` as input to process logs in UNIX pipelines.
- **Time filters**: Filter logs with `--since` and `--until` (by date/time).
- **Column or list view**: Display results in columns (default) or list view via `--list-view`.
- **JSON output**: Integrate with other tools using `--json`.
- **Export to file**: Save reports to disk with `--output`.
- **Basic attack detection**: Detects common web attack patterns.
- **Optional GeoIP2 geolocation**: Geolocate IPs if the geoip2 library and database are available.

---

## Requirements

- Python 3.7 or higher.
- Required libraries:
  ```
  pip install -r requirements.txt
  ```
- GeoIP database (e.g., `GeoLite2-Country.mmdb` from MaxMind) in `/var/lib/GeoIP/` or set its location with `--geoip-db`.

---

## Installation

```
git clone https://github.com/sabbat-cloud/sabbat-utilidades
cd sabbat-utilidades
pip install -r requirements.txt
```

---

## Usage

### Basic Examples

```
# Full analysis (columns view)
python3 sabbat-analizalogs access.log

# Full analysis (list view)
python3 sabbat-analizalogs access.log --list-view

# Search for a specific pattern
python3 sabbat-analizalogs error.log -p "Timeout" -c 50

# JSON output
python3 sabbat-analizalogs app.log --json

# Save output as JSON file
python3 sabbat-analizalogs app.log --json --output result.json

# Filter logs by date
python3 sabbat-analizalogs access.log --since 2024-01-01 --until "2024-01-31 23:59:59"

# Use in a pipeline (read from stdin)
zcat access.log.gz | python3 sabbat-analizalogs - --json
```

---

## Available Options

| Option              | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| archivo             | Log file to analyze (accepts .gz or `-` for stdin)                          |
| -p, --pattern       | Specific pattern to search for                                              |
| -c, --count         | Number of results to display (default: 10)                                  |
| --json              | Output in JSON format                                                       |
| --output            | Output file to save results                                                 |
| --list-view         | Show results in list form instead of columns                                |
| --since             | Filter logs from this date (YYYY-MM-DD or 'YYYY-MM-DD HH:MM:SS')            |
| --until             | Filter logs up to this date (YYYY-MM-DD or 'YYYY-MM-DD HH:MM:SS')           |
| --max-ips           | Optional limit of unique IPs to track                                       |
| --max-errors        | Optional limit of unique errors to track                                    |
| --geoip-db          | Alternate path to GeoIP database                                            |
| -v, --verbose       | Enable verbose logging for debugging                                        |

---

## Example Output

### Column View

```
=== LOG STATISTICS ===
Total lines: 123,456
Errors: 120 | Warnings: 45
Period: From 2024-01-01 00:00:00 to 2024-01-31 23:59:59

Detected Security Alerts:
SQL Injection (5) | XSS Attempt (2)

--------------------------------------------------------------------------------
HTTP Status Codes:
  - Code 200: 102,345 times
  - Code 404: 1,234 times
  Summary by range:
    - 2xx: 102,345 requests
    - 4xx: 1,234 requests

Top 5 Requested URLs:
  - (/index.html)
  - (/login)

Top 10 IPs with Geolocation:
COUNT   IP                 COUNTRY
-----   ------------------ -------
234     203.0.113.5        United States
...
```

### JSON Output

```
{
  "generated_at": "2024-02-01T10:30:00Z",
  "summary": {
    "file": "access.log",
    "total_lines": 123456,
    "total_errors": 120,
    "total_warnings": 45,
    "period": {
      "from": "2024-01-01 00:00:00",
      "to": "2024-01-31 23:59:59"
    }
  },
  "security_alerts": {"sql_injection": 5, "xss_attempt": 2},
  "http_methods": {"GET": 100000, "POST": 20000},
  "http_status_codes": {"200": 102345, "404": 1234},
  "top_urls": [["/index.html", 5000], ["/login", 4000]],
  "top_user_agents": [["Mozilla/5.0 ...", 60000]],
  "top_errors": [["Timeout <NUM>", 50]],
  "top_ips": [{"ip": "203.0.113.5", "count": 234, "country": "United States"}]
}
```

---

## requirements.txt

The repository provides a sample `requirements.txt` for required dependencies:

```
geoip2>=4.6.0
```

(Optional: Add `pytest` or other libraries if you want to develop or run additional tests/utilities.)

---

## License

This project is distributed under the MIT License.

---

### Additional Notes

- **Extensible**: Easily adaptable to your organization’s log formats and security policies.
- **Integration-Ready**: JSON output allows effortless integration with SIEM, dashboards, and alerting pipelines.
- **Performance**: Designed for large-scale logs, with memory optimization options (`--max-ips`, `--max-errors`).
- **Security**: Helps detect potential attacks via pattern recognition.

_For full documentation and latest updates, see the GitHub repository: [https://github.com/sabbat-cloud/sabbat-utilidades](https://github.com/sabbat-cloud/sabbat-utilidades)_
```

[1](https://www.makeareadme.com)
[2](https://realpython.com/readme-python-project/)
[3](https://github.com/othneildrew/Best-README-Template)
[4](https://www.youtube.com/watch?v=12trn2NKw5I)
[5](https://www.pyopensci.org/python-package-guide/tutorials/add-readme.html)
[6](https://packaging.python.org/guides/making-a-pypi-friendly-readme/)
[7](https://www.reddit.com/r/opensource/comments/txl9zq/next_level_readme/)
[8](https://gitlab.com/ton1czech/project-readme-template)
