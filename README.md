# NMAP-Black-Python

![NMAP Black Python by Volkan Sah](nmap-blackpython.png)

**Automated network reconnaissance tool using Nmap and Python for ethical penetration testing.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

---

## ⚠️ LEGAL DISCLAIMER

**READ THIS BEFORE USING THIS TOOL**

### You are legally responsible for your actions

Unauthorized network scanning is **ILLEGAL** in most jurisdictions and may result in:

**United States:** Computer Fraud and Abuse Act (CFAA) violations — **up to 10 years imprisonment**  
**European Union:** Computer Misuse Act violations, GDPR breaches — **criminal prosecution**  
**Germany:** StGB §202a/b (unauthorized data access) — **up to 3 years imprisonment**  
**UK:** Computer Misuse Act 1990 — **up to 2 years imprisonment**

### Required before scanning ANY network

1. **Written authorization** from the network owner
2. **Defined scope** (IP ranges, ports, timeframe)
3. **Signed liability waiver**
4. **Compliance** with local laws and regulations

### This tool is ONLY for

✅ Your own networks and devices  
✅ Authorized penetration testing engagements  
✅ Bug bounty programs with explicit permission  
✅ Educational lab environments (isolated VMs)  
✅ Capture The Flag (CTF) competitions

### By using this tool you agree

- You have **explicit written permission** to scan target networks
- You understand the **legal consequences** of unauthorized scanning
- You will **not hold the author liable** for any misuse
- You accept **full responsibility** for your actions

**If you cannot provide written authorization, DO NOT USE THIS TOOL.**

---

## What It Does

NMAP-Black-Python automates network reconnaissance by:

- Reading target domains/IPs from a text file
- Executing optimized Nmap scans with configurable options
- Parsing XML output for open ports and service detection
- Generating structured CSV reports for analysis
- Providing secure, injection-proof command execution

**Built for:** Security researchers, penetration testers, red teams, and students learning network security in controlled environments.

---

## Features

- **Secure execution** — no shell injection vulnerabilities
- **Configurable scans** — adjust ports, timing, and detection methods
- **Batch processing** — scan multiple targets from a file
- **Structured output** — CSV reports for easy analysis
- **Error handling** — graceful failures with detailed logging
- **Timeout protection** — prevents hanging scans
- **Rate limiting** — avoid overwhelming targets

---

## Requirements

### System dependencies
```bash
# Debian/Ubuntu
sudo apt update && sudo apt install nmap python3 python3-pip

# RHEL/CentOS/Rocky
sudo yum install nmap python3 python3-pip

# macOS (Homebrew)
brew install nmap python3

# Arch Linux
sudo pacman -S nmap python
```

### Python version
- Python 3.8 or higher

### Python packages
None required — uses standard library only (`subprocess`, `csv`, `xml.etree.ElementTree`, `shlex`)

---

## Installation

```bash
# Clone repository
git clone https://github.com/VolkanSah/NMAP-Black-Python.git
cd NMAP-Black-Python

# Verify Nmap installation
nmap --version

# Test Python
python3 --version
```

---

## Usage

### 1. Create target list

Create `targets.txt` with one target per line:

```
192.168.1.1
example.com
10.0.0.0/24
testphp.vulnweb.com
```

**⚠️ Only include targets you have permission to scan!**

### 2. Run the scanner

```bash
python3 nmap_scanner.py
```

### 3. Review results

Output files will be created:
- `target_name.xml` — Full Nmap XML output
- `target_name.csv` — Structured CSV report

---

## Configuration

Edit the script to customize scan behavior:

```python
# Port ranges (default: common ports only)
PORTS = '21-23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443'

# Scan timing (0=paranoid, 5=insane)
TIMING = 'T4'  # Aggressive but reasonable

# Service detection
SERVICE_DETECTION = True  # Enable -sV flag

# OS detection (requires root)
OS_DETECTION = False  # Enable -O flag

# Timeout per target (seconds)
TIMEOUT = 600  # 10 minutes
```

### Scan presets

**Quick scan (Top 100 ports):**
```python
PORTS = '--top-ports 100'
TIMING = 'T5'
```

**Comprehensive scan (All ports):**
```python
PORTS = '1-65535'
TIMING = 'T3'
TIMEOUT = 3600  # 1 hour
```

**Stealth scan (IDS evasion):**
```python
TIMING = 'T1'
EXTRA_FLAGS = ['-f', '-D', 'RND:10']  # Fragmentation + decoys
```

---

## Code Example

**Secure implementation with injection prevention:**

```python
#!/usr/bin/env python3
import subprocess
import csv
import xml.etree.ElementTree as ET
import shlex
import sys
from pathlib import Path

# Configuration
TARGETS_FILE = 'targets.txt'
PORTS = '21-23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443'
TIMING = 'T4'
TIMEOUT = 600

def read_targets(filename):
    """Read and validate target list"""
    try:
        with open(filename, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        if not targets:
            print(f"[!] No targets found in {filename}")
            sys.exit(1)
        return targets
    except FileNotFoundError:
        print(f"[!] File not found: {filename}")
        sys.exit(1)

def scan_target(target):
    """Execute Nmap scan with security measures"""
    # Sanitize target name for filename
    safe_name = "".join(c for c in target if c.isalnum() or c in ".-_")
    xml_file = f"{safe_name}.xml"
    
    # Build command securely (no shell injection possible)
    cmd = [
        'nmap',
        '-p', PORTS,
        f'-{TIMING}',
        '-sV',  # Service detection
        '--open',  # Only show open ports
        '-oX', xml_file,
        target
    ]
    
    print(f"[*] Scanning {target}...")
    
    try:
        result = subprocess.run(
            cmd,
            check=True,
            timeout=TIMEOUT,
            capture_output=True,
            text=True
        )
        print(f"[+] Scan completed: {target}")
        return xml_file
    
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout exceeded for {target}")
        return None
    except subprocess.CalledProcessError as e:
        print(f"[!] Scan failed for {target}: {e}")
        return None
    except FileNotFoundError:
        print("[!] Nmap not found. Install with: sudo apt install nmap")
        sys.exit(1)

def parse_results(xml_file):
    """Extract open ports and services from XML"""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        results = {
            'target': '',
            'open_ports': [],
            'services': []
        }
        
        # Extract target info
        host = root.find('host')
        if host is None:
            return results
            
        addr = host.find('address')
        if addr is not None:
            results['target'] = addr.get('addr', 'Unknown')
        
        # Extract open ports and services
        for port in host.findall('.//port'):
            port_id = port.get('portid')
            protocol = port.get('protocol')
            state = port.find('state')
            
            if state is not None and state.get('state') == 'open':
                results['open_ports'].append(f"{port_id}/{protocol}")
                
                service = port.find('service')
                if service is not None:
                    svc_name = service.get('name', 'unknown')
                    svc_version = service.get('version', '')
                    service_str = f"{port_id}: {svc_name} {svc_version}".strip()
                    results['services'].append(service_str)
        
        return results
        
    except ET.ParseError as e:
        print(f"[!] XML parsing error: {e}")
        return None
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return None

def write_csv(target, results):
    """Write results to CSV file"""
    safe_name = "".join(c for c in target if c.isalnum() or c in ".-_")
    csv_file = f"{safe_name}.csv"
    
    try:
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Target', 'Open Ports', 'Services'])
            writer.writerow([
                results['target'],
                ', '.join(results['open_ports']) if results['open_ports'] else 'None',
                ' | '.join(results['services']) if results['services'] else 'None'
            ])
        print(f"[+] Results saved: {csv_file}")
    except Exception as e:
        print(f"[!] CSV write error: {e}")

def main():
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║           NMAP-Black-Python Scanner                   ║
    ║  ⚠️  Only scan networks you have permission to access ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    
    # Read targets
    targets = read_targets(TARGETS_FILE)
    print(f"[*] Loaded {len(targets)} target(s)")
    
    # Scan each target
    for target in targets:
        xml_file = scan_target(target)
        if xml_file and Path(xml_file).exists():
            results = parse_results(xml_file)
            if results:
                write_csv(target, results)
    
    print("\n[+] All scans completed")

if __name__ == '__main__':
    main()
```

---

## Output Format

### CSV Structure
```csv
Target,Open Ports,Services
192.168.1.1,"22/tcp, 80/tcp, 443/tcp","22: ssh OpenSSH 8.2 | 80: http Apache 2.4.41 | 443: https Apache 2.4.41"
```

### XML Format
Complete Nmap XML output preserved for advanced analysis with tools like:
- `xsltproc` (convert to HTML)
- Metasploit Framework (`db_import`)
- NmaptoCSV converters
- Custom parsing scripts

---

## Security Best Practices

### Input validation
```python
# Validate IP addresses
import ipaddress
try:
    ipaddress.ip_address(target)
except ValueError:
    print(f"[!] Invalid IP: {target}")
```

### Rate limiting
```python
import time
time.sleep(5)  # 5 second delay between scans
```

### Logging
```python
import logging
logging.basicConfig(filename='scan.log', level=logging.INFO)
logging.info(f"Scanned {target} at {time.ctime()}")
```

---

## Common Issues

### "Permission denied" errors
```bash
# Some scans require root privileges
sudo python3 nmap_scanner.py
```

### Slow scans
```python
# Adjust timing template
TIMING = 'T5'  # Faster but more detectable
```

### Firewall blocking
```python
# Add firewall evasion flags
EXTRA_FLAGS = ['-Pn', '--source-port', '53']
```

### XML parsing fails
```bash
# Verify Nmap output manually
nmap -p 80 target.com -oX test.xml
cat test.xml
```

---

## Educational Setup (Safe Testing Environment)

### 1. Install VirtualBox
```bash
# Download from https://www.virtualbox.org/
```

### 2. Download vulnerable VMs
- **Metasploitable2** — Classic vulnerable Linux
- **DVWA** — Damn Vulnerable Web Application
- **VulnHub images** — https://www.vulnhub.com/

### 3. Configure network
- Set VMs to "Host-Only" network
- Scan only `192.168.56.0/24` range
- Never expose VMs to internet

### 4. Practice safely
```bash
# Create safe target list
echo "192.168.56.101" > targets.txt
python3 nmap_scanner.py
```

---

## Contributing

Found bugs? Want to add features?

1. Fork the repository
2. Create feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push to branch (`git push origin feature/improvement`)
5. Open Pull Request

**Please include:**
- Description of changes
- Test results
- Security considerations

## Resources

### Official documentation
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Nmap Scripting Engine (NSE)](https://nmap.org/nsedoc/)

### Learning materials
- [Nmap Network Scanning Book](https://nmap.org/book/)
- [Offensive Security OSCP](https://www.offensive-security.com/pwk-oscp/)
- [HackTheBox](https://www.hackthebox.com/)

### Legal resources
- [US CFAA Overview](https://www.justice.gov/criminal-ccips/computer-fraud-and-abuse-act)
- [EU Cybersecurity Laws](https://digital-strategy.ec.europa.eu/en/policies/cybersecurity-policies)

---

## Support & Sponsorship

If this tool helped you in your security research or studies:

- ⭐ **Star this repository**
- 🐛 **Report bugs** via Issues
- 💡 **Suggest features** via Discussions
- 💖 **[Become a Sponsor](https://github.com/sponsors/volkansah)**

---

## Author

**Volkan Sah**

- GitHub: [@volkansah](https://github.com/volkansah)
- Website: [volkansah.github.io](https://volkansah.github.io)

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) file.

### MIT License Summary

✅ Commercial use  
✅ Modification  
✅ Distribution  
✅ Private use  

⚠️ **No warranty provided**  
⚠️ **Author not liable for misuse**

---

## Final Warning

```
┌─────────────────────────────────────────────────────────┐
│  🚨 UNAUTHORIZED SCANNING IS A CRIME 🚨                 │
│                                                         │
│  Before running ANY scan, ask yourself:                 │
│  1. Do I have WRITTEN permission?                       │
│  2. Am I within the authorized scope?                   │
│  3. Am I complying with local laws?                     │
│                                                         │
│  If you answered NO to any question:                    │
│  ❌ STOP IMMEDIATELY                                    │
│                                                         │
│  Ignorance of the law is not a defense.                 │
│  You WILL be held accountable.                          │
└─────────────────────────────────────────────────────────┘
```

**Use responsibly. Stay legal. Stay ethical.**

---

> **Last updated:** 2025/12  
> **Version:** 2.0  
Y **Status:** Production-ready
