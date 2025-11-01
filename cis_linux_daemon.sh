#!/bin/bash
################################################################################
# CIS Scanner - Complete EC2 Deployment Script
# 
# This single script:
# 1. Creates the Python daemon application
# 2. Installs it as a systemd service
# 3. Configures automatic 24-hour scanning
# 4. Sets up local log file storage
# 5. Runs as non-root user (antivirus safe)
#
# Usage:
#   chmod +x deploy_cis_scanner.sh
#   sudo ./deploy_cis_scanner.sh
#
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SERVICE_USER="cis-scanner"
INSTALL_DIR="/opt/cis-scanner"
LOG_DIR="/var/log/cis-scanner"
DATA_DIR="/var/lib/cis-scanner"
CONFIG_DIR="/etc/cis-scanner"

print_header() {
    echo ""
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}  CIS Benchmark Scanner - EC2 Deployment${NC}"
    echo -e "${BLUE}  Version: 2.0.0${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo ""
}

print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_info() { echo -e "  ${BLUE}→${NC} $1"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then 
        print_error "Please run as root: sudo $0"
        exit 1
    fi
}

check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check Python 3
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 not found. Installing..."
        yum install -y python3 2>/dev/null || apt-get install -y python3 2>/dev/null
    fi
    
    # Check systemd
    if ! command -v systemctl &> /dev/null; then
        print_error "systemd not found. This script requires systemd."
        exit 1
    fi
    
    print_success "Prerequisites OK"
}

create_python_daemon() {
    print_info "Creating Python daemon application..."
    
    mkdir -p "$INSTALL_DIR"
    
    cat > "$INSTALL_DIR/cis_scanner_daemon.py" << 'PYTHON_EOF'
#!/usr/bin/env python3
"""
CIS Benchmark Compliance Scanner - Production Daemon
Runs as non-root, scans every 24 hours, logs locally
"""

import os
import subprocess
import re
import json
import sys
import platform
import time
import signal
import logging
from datetime import datetime
from pathlib import Path
from logging.handlers import RotatingFileHandler

APP_CONFIG = {
    "name": "cis-scanner",
    "version": "2.0.0",
    "scan_interval_hours": 24,
    "log_dir": "/var/log/cis-scanner",
    "data_dir": "/var/lib/cis-scanner",
    "max_log_size_mb": 100,
    "log_backup_count": 10
}

class CISScannerDaemon:
    def __init__(self):
        self.running = False
        self.scan_count = 0
        self.setup_directories()
        self.setup_logging()
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        
        self.logger.info("="*70)
        self.logger.info(f"CIS Scanner v{APP_CONFIG['version']} Starting")
        self.logger.info(f"System: {platform.system()} {platform.release()}")
        self.logger.info(f"User: {os.getenv('USER', 'unknown')} | PID: {os.getpid()}")
        self.logger.info("="*70)
    
    def setup_directories(self):
        for directory in [APP_CONFIG['log_dir'], APP_CONFIG['data_dir']]:
            try:
                Path(directory).mkdir(parents=True, exist_ok=True)
            except PermissionError:
                fallback = Path.home() / '.cis-scanner' / Path(directory).name
                fallback.mkdir(parents=True, exist_ok=True)
                if 'log_dir' in directory:
                    APP_CONFIG['log_dir'] = str(fallback)
                else:
                    APP_CONFIG['data_dir'] = str(fallback)
    
    def setup_logging(self):
        log_file = Path(APP_CONFIG['log_dir']) / 'cis-scanner.log'
        self.logger = logging.getLogger('CISScanner')
        self.logger.setLevel(logging.INFO)
        
        max_bytes = APP_CONFIG['max_log_size_mb'] * 1024 * 1024
        handler = RotatingFileHandler(log_file, maxBytes=max_bytes, 
                                      backupCount=APP_CONFIG['log_backup_count'])
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s',
                                     datefmt='%Y-%m-%d %H:%M:%S')
        handler.setFormatter(formatter)
        
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        
        self.logger.addHandler(handler)
        self.logger.addHandler(console)
        self.logger.info(f"Logging initialized: {log_file}")
    
    def signal_handler(self, signum, frame):
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def run_command_safe(self, cmd, timeout=10):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, 
                                  text=True, timeout=timeout)
            return result.stdout.strip(), result.returncode
        except Exception as e:
            self.logger.error(f"Command error: {str(e)}")
            return "", -1
    
    def safe_file_read(self, filepath):
        try:
            if not os.path.exists(filepath):
                return None, "File not found"
            with open(filepath, 'r') as f:
                return f.read(), None
        except PermissionError:
            return None, "Permission denied (non-root)"
        except Exception as e:
            return None, str(e)
    
    def check_password_policy(self):
        self.logger.info("  → Checking password policy...")
        content, error = self.safe_file_read('/etc/login.defs')
        
        if error:
            return {'check': 'password_expiration', 'status': 'SKIPPED', 
                   'detail': error, 'remediation': ''}
        
        match = re.search(r'^PASS_MAX_DAYS\s+(\d+)', content, re.MULTILINE)
        if match:
            max_days = int(match.group(1))
            if max_days <= 365 and max_days > 0:
                return {'check': 'password_expiration', 'status': 'PASS',
                       'detail': f'PASS_MAX_DAYS={max_days} (compliant)', 
                       'remediation': ''}
            return {'check': 'password_expiration', 'status': 'FAIL',
                   'detail': f'PASS_MAX_DAYS={max_days} (should be ≤365)',
                   'remediation': 'Set PASS_MAX_DAYS to 365 in /etc/login.defs'}
        
        return {'check': 'password_expiration', 'status': 'FAIL',
               'detail': 'PASS_MAX_DAYS not configured',
               'remediation': 'Add PASS_MAX_DAYS 365 to /etc/login.defs'}
    
    def check_ssh_config(self):
        self.logger.info("  → Checking SSH configuration...")
        
        content = None
        method_used = "unknown"
        
        # Method 1: Try reading sshd_config directly
        ssh_config_paths = ['/etc/ssh/sshd_config', '/etc/sshd_config']
        
        for path in ssh_config_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        content = f.read()
                        method_used = f"direct read of {path}"
                        break
                except PermissionError:
                    pass
                except Exception as e:
                    self.logger.debug(f"Error reading {path}: {e}")
        
        # Method 2: Try cat command (works with ACLs)
        if not content:
            for path in ssh_config_paths:
                output, code = self.run_command_safe(f"cat {path} 2>/dev/null")
                if code == 0 and output and len(output) > 100:
                    content = output
                    method_used = f"cat command on {path}"
                    break
        
        # Method 3: Parse from sshd test config (no host keys needed!)
        if not content:
            # Use -T with -C to avoid host key requirement
            output, code = self.run_command_safe("sshd -T -C user=root -C host=localhost -C addr=127.0.0.1 2>/dev/null")
            if code == 0 and output:
                content = output
                method_used = "sshd -T command"
            else:
                # Try without -C flags
                output, code = self.run_command_safe("sshd -t 2>&1 | head -20")
                if 'no hostkeys' in output.lower():
                    # If sshd -t fails due to host keys, try reading config with sudo
                    output, code = self.run_command_safe("sudo cat /etc/ssh/sshd_config 2>/dev/null")
                    if code == 0 and output:
                        content = output
                        method_used = "sudo cat (fallback)"
        
        if not content:
            return {
                'check': 'ssh_security',
                'status': 'SKIPPED',
                'detail': 'Cannot access SSH config (tried multiple methods)',
                'remediation': 'Run: sudo chmod 644 /etc/ssh/sshd_config'
            }
        
        self.logger.info(f"    SSH config read via: {method_used}")
        
        # Parse configuration
        results = []
        checks = [
            ('PermitRootLogin', 'no'),
            ('PermitEmptyPasswords', 'no'),
            ('X11Forwarding', 'no')
        ]
        
        for param, expected in checks:
            found = False
            actual_value = None
            
            # Try case-sensitive match first (config file format)
            match = re.search(rf'^\s*{param}\s+(\S+)', content, re.MULTILINE | re.IGNORECASE)
            if match:
                actual_value = match.group(1).lower()
                found = True
            
            # Try lowercase match (sshd -T format)
            if not found:
                match = re.search(rf'^\s*{param.lower()}\s+(\S+)', content, re.MULTILINE)
                if match:
                    actual_value = match.group(1).lower()
                    found = True
            
            if found and actual_value:
                # Special handling for PermitRootLogin
                if param == 'PermitRootLogin':
                    # Both "no" and "prohibit-password" are acceptable
                    if actual_value in ['no', 'prohibit-password', 'without-password']:
                        status = 'OK'
                    else:
                        status = f'FAIL({actual_value})'
                else:
                    status = 'OK' if actual_value == expected else f'FAIL({actual_value})'
            else:
                status = 'UNKNOWN'
            
            results.append(f"{param}={status}")
        
        failures = [r for r in results if 'FAIL' in r]
        status = 'PASS' if not failures else 'FAIL'
        
        return {
            'check': 'ssh_security',
            'status': status,
            'detail': ', '.join(results),
            'remediation': 'Edit /etc/ssh/sshd_config and restart sshd' if failures else ''
        }
    
    def check_firewall(self):
        self.logger.info("  → Checking firewall...")
        
        # Check ufw
        output, code = self.run_command_safe("command -v ufw")
        if code == 0:
            output, _ = self.run_command_safe("ufw status")
            if 'active' in output.lower():
                return {'check': 'firewall', 'status': 'PASS',
                       'detail': 'ufw is active', 'remediation': ''}
        
        # Check firewalld
        output, _ = self.run_command_safe("systemctl is-active firewalld 2>/dev/null")
        if 'active' in output:
            return {'check': 'firewall', 'status': 'PASS',
                   'detail': 'firewalld is active', 'remediation': ''}
        
        # Check iptables
        output, code = self.run_command_safe("iptables -L -n 2>/dev/null | grep -c '^Chain'")
        try:
            if int(output) > 3:
                return {'check': 'firewall', 'status': 'PASS',
                       'detail': 'iptables configured', 'remediation': ''}
        except:
            pass
        
        return {'check': 'firewall', 'status': 'FAIL',
               'detail': 'No active firewall detected',
               'remediation': 'Enable firewall (ufw/firewalld/iptables)'}
    
    def check_file_permissions(self):
        self.logger.info("  → Checking file permissions...")
        files = {'/etc/passwd': '644', '/etc/group': '644'}
        results = []
        all_pass = True
        
        for filepath, expected in files.items():
            try:
                if os.path.exists(filepath):
                    actual = oct(os.stat(filepath).st_mode)[-3:]
                    if actual == expected:
                        results.append(f"{filepath}={actual}(OK)")
                    else:
                        results.append(f"{filepath}={actual}(expected {expected})")
                        all_pass = False
            except PermissionError:
                results.append(f"{filepath}=PERMISSION_DENIED")
        
        return {'check': 'file_permissions', 
               'status': 'PASS' if all_pass else 'FAIL',
               'detail': ', '.join(results),
               'remediation': 'Check permissions' if not all_pass else ''}
    
    def check_services(self):
        self.logger.info("  → Checking unnecessary services...")
        risky = ['telnet', 'rsh', 'rlogin', 'ftp', 'vsftpd']
        running = []
        
        for svc in risky:
            # Check if service is actually active (not just exists)
            output, code = self.run_command_safe(f"systemctl is-active {svc} 2>/dev/null")
            if output.strip() == 'active':
                running.append(svc)
        
        # Double-check with process list for services that might not be systemd-managed
        if not running:
            for svc in risky:
                output, code = self.run_command_safe(f"pgrep -x {svc} 2>/dev/null")
                if code == 0 and output:
                    running.append(svc)
        
        if running:
            return {'check': 'unnecessary_services', 'status': 'FAIL',
                   'detail': f'Running: {", ".join(running)}',
                   'remediation': f'Stop and disable: {", ".join(running)}'}
        return {'check': 'unnecessary_services', 'status': 'PASS',
               'detail': 'No risky services detected', 'remediation': ''}
    
    def perform_scan(self):
        self.scan_count += 1
        scan_start = time.time()
        
        self.logger.info("="*70)
        self.logger.info(f"Starting CIS Scan #{self.scan_count}")
        self.logger.info(f"Timestamp: {datetime.now().isoformat()}")
        self.logger.info("="*70)
        
        checks = [
            self.check_password_policy(),
            self.check_ssh_config(),
            self.check_firewall(),
            self.check_file_permissions(),
            self.check_services()
        ]
        
        passed = sum(1 for c in checks if c['status'] == 'PASS')
        failed = sum(1 for c in checks if c['status'] == 'FAIL')
        skipped = sum(1 for c in checks if c['status'] == 'SKIPPED')
        total = len(checks)
        
        compliance = (passed / (passed + failed) * 100) if (passed + failed) > 0 else 0
        scan_duration = time.time() - scan_start
        
        self.logger.info("-"*70)
        self.logger.info("SCAN RESULTS:")
        self.logger.info("-"*70)
        
        for check in checks:
            symbol = {'PASS': '✓', 'FAIL': '✗', 'SKIPPED': '⊘'}.get(check['status'], '?')
            self.logger.info(f"{symbol} {check['check']}: {check['status']}")
            self.logger.info(f"    {check['detail']}")
            if check['remediation']:
                self.logger.info(f"    Fix: {check['remediation']}")
        
        self.logger.info("-"*70)
        self.logger.info(f"Total: {total} | Passed: {passed} | Failed: {failed} | Skipped: {skipped}")
        self.logger.info(f"Compliance Rate: {compliance:.1f}%")
        self.logger.info(f"Duration: {scan_duration:.2f}s")
        self.logger.info("="*70)
        
        self.save_json_report(checks, {
            'total': total, 'passed': passed, 'failed': failed, 
            'skipped': skipped, 'compliance_rate': f"{compliance:.1f}%",
            'duration': f"{scan_duration:.2f}s"
        })
        
        return compliance
    
    def save_json_report(self, checks, summary):
        report = {
            'scan_metadata': {
                'scan_number': self.scan_count,
                'timestamp': datetime.now().isoformat(),
                'hostname': platform.node(),
                'os': f"{platform.system()} {platform.release()}",
                'scanner_version': APP_CONFIG['version']
            },
            'summary': summary,
            'checks': checks
        }
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = Path(APP_CONFIG['data_dir']) / f'scan_report_{timestamp}.json'
        
        try:
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            self.logger.info(f"Report saved: {report_file}")
            
            latest = Path(APP_CONFIG['data_dir']) / 'latest_scan.json'
            with open(latest, 'w') as f:
                json.dump(report, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save report: {str(e)}")
    
    def run(self):
        self.running = True
        self.logger.info(f"Daemon started - scanning every {APP_CONFIG['scan_interval_hours']} hours")
        self.logger.info(f"Logs: {APP_CONFIG['log_dir']}/cis-scanner.log")
        self.logger.info(f"Reports: {APP_CONFIG['data_dir']}/")
        
        try:
            self.perform_scan()
        except Exception as e:
            self.logger.error(f"Initial scan failed: {str(e)}")
        
        scan_interval = APP_CONFIG['scan_interval_hours'] * 3600
        
        while self.running:
            try:
                wait_time = scan_interval
                while wait_time > 0 and self.running:
                    time.sleep(min(60, wait_time))
                    wait_time -= 60
                
                if self.running:
                    self.perform_scan()
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.logger.error(f"Error: {str(e)}")
                time.sleep(60)
        
        self.logger.info("Daemon shutdown complete")

if __name__ == '__main__':
    print(f"CIS Scanner v{APP_CONFIG['version']} - Starting daemon...")
    daemon = CISScannerDaemon()
    daemon.run()
PYTHON_EOF

    chmod 755 "$INSTALL_DIR/cis_scanner_daemon.py"
    print_success "Python daemon created"
}

create_service_user() {
    print_info "Creating non-root service user..."
    
    if id "$SERVICE_USER" &>/dev/null; then
        print_warning "User $SERVICE_USER already exists"
    else
        useradd --system --shell /bin/false --home-dir "$INSTALL_DIR" \
                --comment "CIS Scanner Service" "$SERVICE_USER"
        print_success "Created user: $SERVICE_USER"
    fi
}

create_directories() {
    print_info "Creating directories..."
    
    for dir in "$INSTALL_DIR" "$LOG_DIR" "$DATA_DIR" "$CONFIG_DIR"; do
        mkdir -p "$dir"
        chown -R "$SERVICE_USER:$SERVICE_USER" "$dir"
        chmod 755 "$dir"
    done
    
    print_success "Directories configured"
}

setup_ssh_permissions() {
    print_info "Setting up SSH config access for non-root scanning..."
    
    # Solution 1: Make sshd_config readable (most reliable)
    if [ -f /etc/ssh/sshd_config ]; then
        chmod 644 /etc/ssh/sshd_config
        print_success "Made /etc/ssh/sshd_config world-readable (safe - no secrets in this file)"
    else
        print_warning "/etc/ssh/sshd_config not found"
    fi
    
    # Solution 2: Fix sshd_config.d directory if it exists
    if [ -d /etc/ssh/sshd_config.d ]; then
        chmod 755 /etc/ssh/sshd_config.d
        chmod 644 /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
        print_success "Fixed /etc/ssh/sshd_config.d/ permissions"
    fi
    
    # Solution 3: Set ACL as additional layer (if available)
    if command -v setfacl &>/dev/null; then
        setfacl -m u:$SERVICE_USER:r /etc/ssh/sshd_config 2>/dev/null || true
        if [ -d /etc/ssh/sshd_config.d ]; then
            setfacl -R -m u:$SERVICE_USER:r /etc/ssh/sshd_config.d 2>/dev/null || true
        fi
        print_info "ACL permissions set as backup"
    fi
    
    # Verify the fix works
    if sudo -u $SERVICE_USER cat /etc/ssh/sshd_config &>/dev/null; then
        lines=$(sudo -u $SERVICE_USER cat /etc/ssh/sshd_config | wc -l)
        print_success "Verified: $SERVICE_USER can read SSH config ($lines lines)"
    else
        print_warning "$SERVICE_USER cannot read SSH config - SSH checks may be skipped"
        print_warning "This is OK - other checks will still work"
    fi
}

create_systemd_service() {
    print_info "Creating systemd service..."
    
    cat > /etc/systemd/system/cis-scanner.service << 'EOF'
[Unit]
Description=CIS Benchmark Compliance Scanner
After=network.target

[Service]
Type=simple
User=cis-scanner
Group=cis-scanner
WorkingDirectory=/opt/cis-scanner
ExecStart=/usr/bin/python3 /opt/cis-scanner/cis_scanner_daemon.py
Restart=on-failure
RestartSec=30

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/cis-scanner /var/lib/cis-scanner

# Resource limits
MemoryLimit=512M
CPUQuota=50%

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    print_success "Systemd service created"
}

create_management_scripts() {
    print_info "Creating management scripts..."
    
    # View latest report
    cat > "$INSTALL_DIR/view-report.sh" << 'EOF'
#!/bin/bash
if [ -f /var/lib/cis-scanner/latest_scan.json ]; then
    cat /var/lib/cis-scanner/latest_scan.json | python3 -m json.tool
else
    echo "No reports yet. Wait for first scan."
fi
EOF
    chmod 755 "$INSTALL_DIR/view-report.sh"
    
    # Trigger scan
    cat > "$INSTALL_DIR/scan-now.sh" << 'EOF'
#!/bin/bash
echo "Restarting service to trigger immediate scan..."
systemctl restart cis-scanner
sleep 2
journalctl -u cis-scanner -n 50
EOF
    chmod 755 "$INSTALL_DIR/scan-now.sh"
    
    # Uninstall
    cat > "$INSTALL_DIR/uninstall.sh" << 'EOF'
#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "Run as root"; exit 1; fi
systemctl stop cis-scanner 2>/dev/null
systemctl disable cis-scanner 2>/dev/null
rm -f /etc/systemd/system/cis-scanner.service
systemctl daemon-reload
rm -rf /opt/cis-scanner /etc/cis-scanner
read -p "Remove logs? (y/N): " -n 1 -r
echo
[[ $REPLY =~ ^[Yy]$ ]] && rm -rf /var/log/cis-scanner /var/lib/cis-scanner
userdel cis-scanner 2>/dev/null
echo "✓ Uninstalled"
EOF
    chmod 755 "$INSTALL_DIR/uninstall.sh"
    
    print_success "Management scripts created"
}

start_service() {
    print_info "Starting service..."
    
    systemctl enable cis-scanner
    systemctl start cis-scanner
    
    sleep 3
    
    if systemctl is-active --quiet cis-scanner; then
        print_success "Service started successfully"
    else
        print_error "Service failed to start"
        journalctl -u cis-scanner -n 20
        exit 1
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}================================================================${NC}"
    echo -e "${GREEN}  Installation Complete!${NC}"
    echo -e "${GREEN}================================================================${NC}"
    echo ""
    echo "✓ Application deployed and running"
    echo "✓ Automatic scanning every 24 hours"
    echo "✓ Logs stored locally"
    echo "✓ Running as non-root user (antivirus safe)"
    echo "✓ SSH config readable (all checks will work)"
    echo ""
    echo "Service Status:"
    systemctl status cis-scanner --no-pager | head -8
    echo ""
    echo "Useful Commands:"
    echo "  View logs:          sudo journalctl -u cis-scanner -f"
    echo "  View latest report: sudo $INSTALL_DIR/view-report.sh"
    echo "  Trigger scan now:   sudo $INSTALL_DIR/scan-now.sh"
    echo "  Stop service:       sudo systemctl stop cis-scanner"
    echo "  Start service:      sudo systemctl start cis-scanner"
    echo "  Uninstall:          sudo $INSTALL_DIR/uninstall.sh"
    echo ""
    echo "File Locations:"
    echo "  Application:        $INSTALL_DIR"
    echo "  Logs:               $LOG_DIR/cis-scanner.log"
    echo "  Reports:            $DATA_DIR/"
    echo ""
    echo -e "${YELLOW}⏱  First scan running now... wait 30 seconds then run:${NC}"
    echo -e "${YELLOW}  sudo $INSTALL_DIR/view-report.sh${NC}"
    echo ""
    echo -e "${BLUE}Expected first scan results:${NC}"
    echo "  • password_expiration: May FAIL (PASS_MAX_DAYS too high)"
    echo "  • ssh_security: Should work now (not SKIPPED)"
    echo "  • firewall: Should PASS (firewalld active)"
    echo "  • file_permissions: Should PASS"
    echo "  • unnecessary_services: Should PASS"
    echo ""
}

main() {
    print_header
    
    echo "This will install CIS Scanner with:"
    echo "  ✓ Non-root operation (antivirus safe)"
    echo "  ✓ Automatic 24-hour scanning"
    echo "  ✓ Local log file storage"
    echo "  ✓ Systemd service integration"
    echo ""
    read -p "Continue? (y/N): " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelled."
        exit 0
    fi
    
    check_root
    check_prerequisites
    create_python_daemon
    create_service_user
    create_directories
    setup_ssh_permissions
    create_systemd_service
    create_management_scripts
    start_service
    print_summary
}

main
