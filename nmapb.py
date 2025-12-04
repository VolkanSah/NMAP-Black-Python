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
