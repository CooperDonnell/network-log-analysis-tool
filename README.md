Copy and paste this as the complete `README.md`:

````markdown
# Linux Authentication and Firewall Log Analyzer

A dependency-free Python threat-hunting CLI that analyzes Linux OpenSSH and UFW logs, identifies repeated invalid-user login attempts, and correlates source IPs across authentication and firewall activity.

## Project results

I applied the tool to eight Linux authentication and firewall log files and identified:

- **19,037** invalid-user login attempts
- **3,652** unique usernames targeted
- **15,838** unique IP addresses blocked by UFW
- **51** source IPs observed in both invalid login attempts and firewall blocks

Cross-source correlation narrowed 15,838 UFW-blocked addresses to 51 higher-priority investigation leads also associated with invalid-user authentication attempts.

An overlapping address is not automatically malicious, but activity in both sources provides stronger justification for additional investigation.

## What I built

- A command-line interface that analyzes every supported log file in a supplied directory
- OpenSSH invalid-username and source-IP extraction
- UFW blocked-source extraction
- Cross-log IP correlation using set intersection
- Support for current, rotated, and gzip-compressed logs
- Human-readable and JSON output
- Username-specific authentication timestamp searches
- Automated tests covering parsing, correlation, compressed logs, CLI output, and error handling

## Analysis workflow

1. Discover every `auth.log*` and `ufw.log*` file in the selected directory.
2. Parse OpenSSH `Invalid user` events and extract usernames and source IPs.
3. Parse `[UFW BLOCK]` events and extract blocked source IPs.
4. Identify addresses present in both authentication and firewall activity.
5. Report totals, top targeted usernames, and correlated IP addresses.

## Requirements

- Python 3.9 or later
- No third-party packages

## Run the tool

Clone the repository:

```bash
git clone https://github.com/CooperDonnell/network-log-analysis-tool.git
cd network-log-analysis-tool
```

Place supported logs in the `logs` directory:

```text
logs/
├── auth.log
├── auth.log.1
├── auth.log.2.gz
├── ufw.log
├── ufw.log.1
└── ufw.log.2.gz
```

The CLI processes every supported file in the directory. It is not limited to eight files; eight was the size of the original project dataset.

Run the analysis:

```bash
python3 log_analysis.py --logs-dir logs
```

Request JSON output:

```bash
python3 log_analysis.py --logs-dir logs --json
```

Search for authentication timestamps associated with one username:

```bash
python3 log_analysis.py --logs-dir logs --user tmoore
```

Control the number of top targeted usernames displayed:

```bash
python3 log_analysis.py --logs-dir logs --top 20
```

View every option:

```bash
python3 log_analysis.py --help
```

## Output

The analysis reports:

- Number of authentication and firewall files processed
- Total invalid-user login attempts
- Number of unique invalid usernames
- Unique source IPs associated with invalid login attempts
- Unique source IPs blocked by UFW
- Source IPs present in both log sources
- Most frequently attempted invalid usernames

The original logs are not included because they are large and may contain environment-specific information. Authorized Linux logs can be placed in the `logs` directory to perform the same analysis on another dataset.

## Use as a Python module

The analysis functions can also be imported into another Python program:

```python
from log_analysis import analyze_logs, compare_invalid_ips, get_invalid_logins

result = analyze_logs("logs")

print(result.invalid_login_attempts)
print(result.unique_invalid_usernames)
print(compare_invalid_ips("logs"))
print(get_invalid_logins("logs"))
```

## Testing

The automated test suite creates isolated sample logs and validates:

- Invalid-user parsing
- Username counting
- IPv4 and IPv6 extraction
- Cross-source IP correlation
- Rotated gzip log support
- Username timestamp searches
- JSON output
- Missing-directory error handling

Run the tests:

```bash
python3 -m unittest discover -s tests -v
```

## Technical decisions

- **Standard library only:** The tool runs without installing external dependencies.
- **Regular expressions:** OpenSSH and UFW fields are extracted from common syslog formats.
- **Set intersection:** Unique IP sets provide efficient cross-source correlation.
- **Line-oriented processing:** Files are read line by line instead of loading entire log files into memory.
- **Structured results:** Results can be consumed as terminal text, JSON, or imported Python objects.
- **Defensive error handling:** Missing directories and invalid options produce clear messages.

## Interpretation and limitations

The 51 overlapping IP addresses are investigation leads, not confirmed malicious hosts. A complete investigation should also consider:

- Event timestamps and frequency
- Destination ports and targeted services
- Successful logons following failed attempts
- Known scanners, allowlists, and trusted infrastructure
- Geographic and threat-intelligence context
- Related activity from the same accounts on other systems

Current limitations include:

- The parser targets common OpenSSH `Invalid user ... from ...` and UFW `[UFW BLOCK] ... SRC=...` formats.
- Correlation is not restricted to a configurable time window.
- The tool performs batch analysis rather than real-time monitoring.
- The original dataset cannot be redistributed through this repository.

Potential improvements include:

- Timestamp normalization and time-window correlation
- Destination-port and protocol analysis
- Successful-login correlation
- IP allowlists and threat-intelligence enrichment
- CSV report export
- Risk scoring and alert prioritization

## Skills demonstrated

Python · Linux logging · OpenSSH · UFW · Log parsing · Threat hunting · Cross-source correlation · CLI design · JSON reporting · Automated testing
````
