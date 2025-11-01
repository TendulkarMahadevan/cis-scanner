# CIS Benchmark Compliance Scanner

A lightweight shell script to deploy a Python-based CIS compliance scanner for Linux servers.  
It automates security checks, runs as a systemd service, and stores results in local logs.

## Features
- Creates system directories for logs and data
- Installs a systemd service + 24-hour timer
- Runs as a non-root user
- Generates compliance JSON reports

## Usage
```bash
chmod +x deploy_cis_scanner.sh
sudo ./deploy_cis_scanner.sh

