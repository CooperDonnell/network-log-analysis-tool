# Network Log Analysis Tool

A dependency-free Python command-line tool for analyzing Linux authentication and UFW firewall logs. It identifies repeated invalid-user login attempts and correlates their source IPs with addresses blocked by UFW.

## Analysis workflow

1. Read current and rotated `auth.log*` and `ufw.log*` files, including gzip-compressed rotations.
2. Extract invalid usernames and source IPs from OpenSSH authentication events.
3. Extract source IPs from `[UFW BLOCK]` firewall events.
4. Intersect the two IP sets to highlight hosts associated with both authentication attacks and blocked network traffic.

An overlapping address is an investigation lead, not proof by itself that the host is malicious. Validate the result against timestamps, destination ports, successful logons, asset context, and other telemetry.

## Requirements

- Python 3.9 or later
- No third-party packages

## Run the tool

Clone the repository and place logs in the included `logs` directory:

```bash
git clone https://github.com/CooperDonnell/network-log-analysis-tool.git
cd network-log-analysis-tool
python3 log_analysis.py --logs-dir logs
```

Supported names include:

```text
logs/auth.log
logs/auth.log.1
logs/auth.log.2.gz
logs/ufw.log
logs/ufw.log.1
logs/ufw.log.2.gz
```

Query authentication timestamps associated with one username:

```bash
python3 log_analysis.py --logs-dir logs --user tmoore
```

Produce machine-readable output:

```bash
python3 log_analysis.py --logs-dir logs --json
```

See all options:

```bash
python3 log_analysis.py --help
```

## Output

The summary reports the files processed, invalid-user attempt totals, unique usernames and source IPs, UFW-blocked IPs, addresses present in both sources, and the most frequently attempted usernames.

The original eight-file project dataset produced:

```text
Invalid login attempts: 19,037
Unique invalid usernames: 3,652
Unique UFW blocked IPs: 15,838
Unique overlap IPs: 51
```

The original logs are not redistributed because they are large and may contain environment-specific data. Place authorized Linux logs in `logs/` to reproduce the analysis on another dataset.

## Use as a Python module

```python
from log_analysis import analyze_logs, compare_invalid_ips, get_invalid_logins

result = analyze_logs("logs")
print(result.invalid_login_attempts)
print(compare_invalid_ips("logs"))
print(get_invalid_logins("logs"))
```

The original `compare_invalid_IPs()` spelling remains available as a backward-compatible alias.

## Tests

The tests exercise parsing, correlation, rotated gzip logs, JSON output, and error handling:

```bash
python3 -m unittest discover -s tests -v
```

## Limitations and next steps

- The parser targets common OpenSSH `Invalid user ... from ...` and UFW `[UFW BLOCK] ... SRC=...` formats.
- IP overlap is not time-windowed, so events far apart in time may be correlated.
- The tool performs batch analysis rather than real-time monitoring.
- Future improvements could add timestamp normalization, destination-port analysis, successful-login correlation, allowlists, CSV export, and alert scoring.
