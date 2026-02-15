# Network Log Analysis Tool (Python)

## Overview
Parses Linux authentication and firewall logs to identify failed login attempts, invalid usernames, and IPs associated with scanning activity.

## What it does
- Extracts login timestamps for a given username from auth.log files
- Counts invalid user login attempts (Invalid user ...)
- Finds IPs that appear in both failed login attempts and UFW blocked scans

## How to run

1. Clone the repository

git clone https://github.com/yourusername/network-log-analysis-tool

cd network-log-analysis-tool

2. Place your log files inside the `logs` folder

Example files:
- auth.log
- auth.log.1
- ufw.log

3. Run the script

python3 loganalysis.py

## Key functions
- get_user_auth_times(user_id)
- get_invalid_logins()
- compare_invalid_IPs()

## Skills demonstrated
Python, log parsing, Linux auth logging, basic threat hunting

## Example output
Unique scanning IPs: 15838
Unique overlap IPs (invalid login + scan): 51
Top 10 overlap IPs: ['104.248.168.145', '106.12.222.80', '107.189.31.191', '128.199.13.112', '129.244.0.252', '139.135.229.24', '141.98.10.179', '141.98.10.202', '141.98.10.206', '141.98.10.81']
