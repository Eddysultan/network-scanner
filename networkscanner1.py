import socket
import ipaddress
import concurrent.futures
import argparse
from datetime import datetime
import sys
from typing import List, Tuple, Dict, Optional
import json
import csv
import os
import struct
import platform
from contextlib import closing
import time
import ssl
import requests
import re
import hashlib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from urllib.parse import urlparse
import threading
import queue
import html

@dataclass
class Vulnerability:
    name: str
    description: str
    severity: str
    recommendation: str
    references: List[str]
    cve_id: Optional[str] = None

class VulnerabilityScanner:
    """Handles vulnerability scanning for various services."""
    
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.vulns_db = self._load_vulns_db()
    
    def _load_vulns_db(self) -> Dict:
        """Load vulnerability database from JSON file."""
        # This would typically load from a file, but for this example we'll define some common vulnerabilities
        return {
            "ssl": {
                "weak_ciphers": Vulnerability(
                    name="Weak SSL/TLS Configuration",
                    description="Server supports weak cipher suites or protocols",
                    severity="High",
                    recommendation="Disable weak protocols (SSLv2, SSLv3) and weak cipher suites",
                    references=["https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet"],
                    cve_id=None
                ),
                "heartbleed": Vulnerability(
                    name="Heartbleed Vulnerability",
                    description="OpenSSL TLS/DTLS heartbeat information disclosure",
                    severity="Critical",
                    recommendation="Upgrade OpenSSL to version 1.0.1g or later",
                    references=["https://heartbleed.com/"],
                    cve_id="CVE-2014-0160"
                )
            },
            "http": {
                "directory_listing": Vulnerability(
                    name="Directory Listing Enabled",
                    description="Web server directory listing is enabled",
                    severity="Medium",
                    recommendation="Disable directory listing in web server configuration",
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_for_Directory_Traversal"],
                    cve_id=None
                )
            },
            "ssh": {
                "weak_algorithms": Vulnerability(
                    name="Weak SSH Algorithms",
                    description="SSH server supports weak encryption algorithms",
                    severity="High",
                    recommendation="Configure SSH to use only strong encryption algorithms",
                    references=["https://www.ssh.com/ssh/security-guidelines"],
                    cve_id=None
                )
            }
        }

class EnhancedNetworkScanner:
    """Enhanced network scanner with vulnerability checking and detailed reporting."""
    
    COMMON_PORTS = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
    }
    
    def __init__(self, timeout: float = 1.0, aggressive: bool = False, vuln_scan: bool = False):
        self.timeout = timeout
        self.aggressive = aggressive
        self.vuln_scan = vuln_scan
        self.vulnerability_scanner = VulnerabilityScanner(timeout) if vuln_scan else None
        self.results_queue = queue.Queue()
    
    def scan_host(self, ip: str, ports: List[int]) -> Dict:
        """Scan a single host for open ports and vulnerabilities."""
        result = {
            "ip": ip,
            "status": "down",
            "os_guess": "Unknown",
            "ports": []
        }
        
        # Check if host is up with a simple ping-like TCP connection
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                # Try to connect to port 80 first, then 443
                for test_port in [80, 443]:
                    if s.connect_ex((ip, test_port)) == 0:
                        result["status"] = "up"
                        break
        except:
            pass
        
        # If host appears down, try one more time with ICMP ping if possible
        if result["status"] == "down" and platform.system().lower() == "linux":
            try:
                if os.system(f"ping -c 1 -W {self.timeout} {ip} > /dev/null 2>&1") == 0:
                    result["status"] = "up"
            except:
                pass
        
        # If host is up or we're scanning aggressively, proceed with port scanning
        if result["status"] == "up" or self.aggressive:
            # Try to guess OS if aggressive scanning is enabled
            if self.aggressive:
                result["os_guess"] = self._guess_os(ip)
            
            # Scan all specified ports
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_port = {
                    executor.submit(self.scan_port, ip, port): port 
                    for port in ports
                }
                
                for future in concurrent.futures.as_completed(future_to_port):
                    port_result = future.result()
                    result["ports"].append(port_result)
        
        return result
    
    def _guess_os(self, ip: str) -> str:
        """Attempt to guess the operating system of the target."""
        try:
            # Try to connect to common ports and analyze TTL
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                for port in [80, 443, 22, 445]:
                    try:
                        s.connect((ip, port))
                        # Get TTL from connection (simplified)
                        ttl = struct.unpack('B', s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1))[0]
                        
                        # Common TTL values:
                        # Linux/Unix: 64
                        # Windows: 128
                        # Network equipment: 255
                        if ttl <= 64:
                            return "Linux/Unix"
                        elif ttl <= 128:
                            return "Windows"
                        else:
                            return "Network Device"
                    except:
                        continue
        except:
            pass
        return "Unknown"

    def grab_banner(self, ip: str, port: int) -> Optional[str]:
        """Attempt to grab service banner from the specified port."""
        banner = None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                
                # Send different requests based on the port
                if port == 80:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 443:
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        with context.wrap_socket(s) as ssock:
                            ssock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                            banner = ssock.recv(1024).decode('utf-8', errors='ignore')
                            return banner
                    except:
                        return None
                
                banner = s.recv(1024).decode('utf-8', errors='ignore')
        except:
            pass
        return banner
    
    def check_ssl_vulnerability(self, ip: str, port: int) -> List[Vulnerability]:
        """Check for SSL/TLS vulnerabilities."""
        vulnerabilities = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check for weak protocols
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        vulnerabilities.append(self.vulnerability_scanner.vulns_db['ssl']['weak_ciphers'])
                    
                    # Check for Heartbleed (simplified check)
                    if self._check_heartbleed(ip, port):
                        vulnerabilities.append(self.vulnerability_scanner.vulns_db['ssl']['heartbleed'])
        except:
            pass
        
        return vulnerabilities
    
    def _check_heartbleed(self, ip: str, port: int) -> bool:
        """Simplified Heartbleed check (for demonstration - in reality, you'd want a more thorough check)"""
        # This is a simplified check - in a real scanner, you'd implement the actual Heartbleed test
        return False
    
    def check_http_vulnerability(self, ip: str, port: int) -> List[Vulnerability]:
        """Check for HTTP vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Check for directory listing
            response = requests.get(f"http://{ip}:{port}/", timeout=self.timeout)
            if "Index of /" in response.text:
                vulnerabilities.append(self.vulnerability_scanner.vulns_db['http']['directory_listing'])
            
            # Add more HTTP vulnerability checks here
            
        except:
            pass
        
        return vulnerabilities
    
    def check_ssh_vulnerability(self, ip: str, port: int) -> List[Vulnerability]:
        """Check for SSH vulnerabilities."""
        vulnerabilities = []
        
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                banner = sock.recv(1024).decode()
                
                # Check for weak algorithms (simplified)
                if 'SSH-1' in banner or 'SSH-2.0-OpenSSH_4' in banner:
                    vulnerabilities.append(self.vulnerability_scanner.vulns_db['ssh']['weak_algorithms'])
        except:
            pass
        
        return vulnerabilities

    def scan_port(self, ip: str, port: int) -> Dict:
        """Enhanced port scanning with vulnerability checking."""
        result = {
            "port": port,
            "state": "closed",
            "service": "unknown",
            "banner": None,
            "vulnerabilities": []
        }
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                if s.connect_ex((ip, port)) == 0:
                    result["state"] = "open"
                    
                    # Get service name
                    try:
                        result["service"] = socket.getservbyport(port)
                    except:
                        result["service"] = self.COMMON_PORTS.get(port, "unknown")
                    
                    # Get banner if aggressive scanning is enabled
                    if self.aggressive:
                        result["banner"] = self.grab_banner(ip, port)
                    
                    # Check for vulnerabilities if enabled
                    if self.vuln_scan:
                        if result["service"] == "https" or port == 443:
                            result["vulnerabilities"].extend(self.check_ssl_vulnerability(ip, port))
                        elif result["service"] == "http" or port == 80:
                            result["vulnerabilities"].extend(self.check_http_vulnerability(ip, port))
                        elif result["service"] == "ssh" or port == 22:
                            result["vulnerabilities"].extend(self.check_ssh_vulnerability(ip, port))
        except:
            result["state"] = "filtered"
            
        return result

    def generate_html_report(self, results: List[Dict], filename: str):
        """Generate a detailed HTML report."""
        html_template = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Scan Report</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    margin: 20px; 
                    background-color: #f5f5f5;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background-color: white;
                    padding: 20px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    border-radius: 5px;
                }
                .host { 
                    margin-bottom: 30px; 
                    border: 1px solid #ccc; 
                    padding: 15px; 
                    background-color: white;
                    border-radius: 5px;
                }
                .vuln { 
                    margin: 10px 0; 
                    padding: 10px; 
                    border-left: 4px solid #ff4444; 
                    background-color: #fff;
                }
                .vuln.Critical { 
                    border-color: #ff0000; 
                    background-color: #fff0f0; 
                }
                .vuln.High { 
                    border-color: #ff4444; 
                    background-color: #fff4f4; 
                }
                .vuln.Medium { 
                    border-color: #ffaa00; 
                    background-color: #fffaf0; 
                }
                .vuln.Low { 
                    border-color: #ffff00; 
                    background-color: #fffff0; 
                }
                .port { 
                    margin: 10px 0;
                    padding: 10px;
                    background-color: #f8f9fa;
                    border-radius: 3px;
                }
                .summary { 
                    margin-bottom: 20px;
                    padding: 15px;
                    background-color: white;
                    border-radius: 5px;
                    box-shadow: 0 0 5px rgba(0,0,0,0.05);
                }
                table { 
                    border-collapse: collapse; 
                    width: 100%;
                    margin: 10px 0;
                }
                th, td { 
                    border: 1px solid #ddd; 
                    padding: 12px 8px;
                    text-align: left;
                }
                th { 
                    background-color: #f5f5f5;
                    font-weight: bold;
                }
                h1, h2, h3, h4 { 
                    color: #333;
                    margin-top: 20px;
                }
                .reference-link {
                    color: #0066cc;
                    text-decoration: none;
                }
                .reference-link:hover {
                    text-decoration: underline;
                }
                .status-badge {
                    display: inline-block;
                    padding: 4px 8px;
                    border-radius: 3px;
                    font-size: 0.9em;
                    font-weight: bold;
                }
                .status-up {
                    background-color: #d4edda;
                    color: #155724;
                }
                .status-down {
                    background-color: #f8d7da;
                    color: #721c24;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Network Scan Report</h1>
                <div class="summary">
                    <h2>Scan Summary</h2>
                    <table>
                        <tr><th>Total Hosts</th><td>{total_hosts}</td></tr>
                        <tr><th>Hosts Up</th><td>{hosts_up}</td></tr>
                        <tr><th>Total Open Ports</th><td>{total_open_ports}</td></tr>
                        <tr><th>Total Vulnerabilities</th><td>{total_vulns}</td></tr>
                        <tr><th>Scan Date</th><td>{scan_date}</td></tr>
                    </table>
                </div>
                
                <h2>Detailed Results</h2>
                {host_results}
            </div>
        </body>
        </html>
        '''
        
        host_template = '''
        <div class="host">
            <h3>Host: {ip}</h3>
            <p>
                Status: <span class="status-badge status-{status_class}">{status}</span>
            </p>
            <p>OS Guess: {os_guess}</p>
            
            <h4>Open Ports:</h4>
            {port_results}
            
            <h4>Vulnerabilities:</h4>
            {vuln_results}
        </div>
        '''
        
        # Calculate summary statistics
        total_hosts = len(results)
        hosts_up = len([r for r in results if r['status'] == 'up'])
        total_open_ports = sum(len([p for p in r['ports'] if p['state'] == 'open']) for r in results)
        total_vulns = sum(len([v for p in r['ports'] for v in p.get('vulnerabilities', [])]) for r in results)
        
        # Generate host results
        host_results = []
        for host in results:
            open_ports = [p for p in host['ports'] if p['state'] == 'open']
            
            # Generate port results
            port_results = []
            for port in open_ports:
                banner_html = f"<br>Banner: {html.escape(port['banner'])}" if port.get('banner') else ""
                port_str = f'''
                    <div class="port">
                        <strong>Port {port['port']}/{port['service']}</strong>
                        {banner_html}
                    </div>
                '''
                port_results.append(port_str)
            
            # Generate vulnerability results
            vuln_results = []
            for port in open_ports:
                for vuln in port.get('vulnerabilities', []):
                    vuln_str = f'''
                        <div class="vuln {vuln.severity}">
                            <h4>{html.escape(vuln.name)}</h4>
                            <p>Severity: {vuln.severity}</p>
                            <p>Description: {html.escape(vuln.description)}</p>
                            <p>Recommendation: {html.escape(vuln.recommendation)}</p>
                            <p>References:</p>
                            <ul>
                                {"".join(f'<li><a href="{ref}" class="reference-link" target="_blank">{html.escape(ref)}</a></li>' for ref in vuln.references)}
                            </ul>
                            {f"<p>CVE: {vuln.cve_id}</p>" if vuln.cve_id else ""}
                        </div>
                    '''
                    vuln_results.append(vuln_str)
            
            # Generate host result using template
            host_results.append(host_template.format(
                ip=host['ip'],
                status=host['status'],
                status_class='up' if host['status'] == 'up' else 'down',
                os_guess=host['os_guess'],
                port_results="\n".join(port_results) if port_results else "<p>No open ports found</p>",
                vuln_results="\n".join(vuln_results) if vuln_results else "<p>No vulnerabilities found</p>"
            ))
        
        # Generate final report
        report = html_template.format(
            total_hosts=total_hosts,
            hosts_up=hosts_up,
            total_open_ports=total_open_ports,
            total_vulns=total_vulns,
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            host_results="\n".join(host_results)
        )
        
        # Write report to file
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)

def main():
    parser = argparse.ArgumentParser(description="Enhanced Network Scanner with Vulnerability Checking")
    parser.add_argument("network", help="Network to scan (CIDR notation, e.g., 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", 
                       help="Ports to scan (comma-separated, ranges allowed e.g., 80,443,8000-8100)",
                       default="21,22,23,25,80,443,3306,3389,8080,8443")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                       help="Timeout in seconds for each connection attempt")
    parser.add_argument("-a", "--aggressive", action="store_true",
                       help="Enable aggressive scanning (banner grabbing, OS detection)")
    parser.add_argument("-v", "--vuln-scan", action="store_true",
                       help="Enable vulnerability scanning")
    parser.add_argument("-o", "--output",
                       help="Output file for results (default: scan_results)")
    parser.add_argument("-f", "--format", choices=['json', 'csv', 'html'], default='html',
                       help="Output format (default: html)")
    
    args = parser.parse_args()
    
    try:
        network = ipaddress.ip_network(args.network)
        scanner = EnhancedNetworkScanner(
            timeout=args.timeout,
            aggressive=args.aggressive,
            vuln_scan=args.vuln_scan
        )
        ports = [int(p) for p in args.ports.split(',')]
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    start_time = datetime.now()
    print(f"\nStarting enhanced scan at {start_time}")
    print(f"Scanning network: {args.network}")
    print(f"Ports to scan: {args.ports}")
    print(f"Aggressive mode: {'enabled' if args.aggressive else 'disabled'}")
    print(f"Vulnerability scanning: {'enabled' if args.vuln_scan else 'disabled'}\n")
    
    # Store all results for export
    all_results = []
    vuln_summary = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0
    }
    
    # Scan each host in the network
    for ip in network.hosts():
        ip_str = str(ip)
        print(f"\nScanning {ip_str}...")
        
        results = scanner.scan_host(ip_str, ports)
        all_results.append(results)
        
        if results["status"] == "up":
            print(f"Host: {ip_str} is up")
            if results.get("os_guess") != "Unknown":
                print(f"OS Guess: {results['os_guess']}")
            
            open_ports = [p for p in results["ports"] if p["state"] == "open"]
            if open_ports:
                print("\nOpen ports:")
                for port_info in open_ports:
                    port_str = f"  {port_info['port']}/tcp - {port_info['service']}"
                    if port_info.get('banner'):
                        port_str += f"\n    Banner: {port_info['banner']}"
                    print(port_str)
                    
                    # Display vulnerabilities if found
                    if port_info.get('vulnerabilities'):
                        print("    Vulnerabilities found:")
                        for vuln in port_info['vulnerabilities']:
                            print(f"      - {vuln.name} (Severity: {vuln.severity})")
                            vuln_summary[vuln.severity] += 1
            else:
                print("No open ports found")
    
    # Generate vulnerability summary
    if args.vuln_scan:
        print("\nVulnerability Summary:")
        print("----------------------")
        for severity, count in vuln_summary.items():
            if count > 0:
                print(f"{severity}: {count} vulnerabilities found")
    
    # Export results based on format
    if args.output:
        if args.format == 'html':
            output_file = f"{args.output}.html"
            scanner.generate_html_report(all_results, output_file)
        elif args.format == 'json':
            output_file = f"{args.output}.json"
            with open(output_file, 'w') as f:
                # Convert Vulnerability objects to dict for JSON serialization
                json_results = []
                for host in all_results:
                    host_copy = host.copy()
                    for port in host_copy['ports']:
                        if 'vulnerabilities' in port:
                            port['vulnerabilities'] = [asdict(v) for v in port['vulnerabilities']]
                    json_results.append(host_copy)
                json.dump(json_results, f, indent=4)
        else:  # CSV format
            output_file = f"{args.output}.csv"
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IP', 'Status', 'OS Guess', 'Port', 'State', 'Service', 
                               'Banner', 'Vulnerability Name', 'Severity', 'Description'])
                
                for host in all_results:
                    for port in host['ports']:
                        if port['state'] == 'open':
                            if port.get('vulnerabilities'):
                                for vuln in port['vulnerabilities']:
                                    writer.writerow([
                                        host['ip'],
                                        host['status'],
                                        host['os_guess'],
                                        port['port'],
                                        port['state'],
                                        port['service'],
                                        port.get('banner', ''),
                                        vuln.name,
                                        vuln.severity,
                                        vuln.description
                                    ])
                            else:
                                writer.writerow([
                                    host['ip'],
                                    host['status'],
                                    host['os_guess'],
                                    port['port'],
                                    port['state'],
                                    port['service'],
                                    port.get('banner', ''),
                                    'None',
                                    'N/A',
                                    'N/A'
                                ])
        
        print(f"\nResults exported to {output_file}")
    
    end_time = datetime.now()
    scan_duration = end_time - start_time
    print(f"\nScan completed in {scan_duration}")
    print("\nScan Statistics:")
    print(f"Total hosts scanned: {len(all_results)}")
    print(f"Hosts found up: {len([r for r in all_results if r['status'] == 'up'])}")
    total_open_ports = sum(len([p for p in r['ports'] if p['state'] == 'open']) for r in all_results)
    print(f"Total open ports: {total_open_ports}")
    if args.vuln_scan:
        total_vulns = sum(vuln_summary.values())
        print(f"Total vulnerabilities found: {total_vulns}")

if __name__ == "__main__":
    main()