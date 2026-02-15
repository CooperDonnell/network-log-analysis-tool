# Network Log Analysis Tool (Python)

## Overview
Parses Linux authentication and firewall logs to identify failed login attempts, invalid usernames, and IPs associated with scanning activity.

## What it does
- Extracts login timestamps for a given username from auth.log files
- Counts invalid user login attempts (Invalid user ...)
- Finds IPs that appear in both failed login attempts and UFW blocked scans

## How to run
1. Put your log files in a folder like:
project-1-network-log-analysis-CooperDonnell/log/

2. Run:
python3 loganalysis.py

## Key functions
- get_user_auth_times(user_id)
- get_invalid_logins()
- compare_invalid_IPs()

## Skills demonstrated
Python, log parsing, Linux auth logging, basic threat hunting
