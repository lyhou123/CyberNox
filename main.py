#!/usr/bin/env python3
"""
CyberNox - All-in-One Python Cybersecurity Toolkit
Version: 1.0.0
Author: Lyhou Phiv

A comprehensive cybersecurity toolkit for penetration testing, vulnerability assessment,
and security research.
"""

import argparse
import sys
import json
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import core modules
from core.recon import ReconModule
from core.scanner import PortScanner, VulnerabilityScanner
from core.brute import DirectoryBruteforcer
from core.exploit import ExploitModule
from core.vulnscan import VulnerabilityScanner as WebVulnScanner
from core.phishing import PhishingDetector
from core.monitor import NetworkMonitor, BasicNetworkMonitor
from core.report import ReportGenerator

# Import utilities
from utils.logger import setup_logger, logger
from utils.config import config
from utils.fingerprint import ServiceFingerprinter

# Import legacy functions for backward compatibility
from core.recon import whois_lookup, subdomain_enum
from core.scanner import tcp_scan, cve_lookup
from core.brute import dir_brute
from core.exploit import generate_reverse_shell

def setup_cli():
    """Setup command line interface"""
    parser = argparse.ArgumentParser(
        description='CyberNox - All-in-One Cybersecurity Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py recon --whois example.com
  python main.py scan --target 192.168.1.1 --ports 80 443 22
  python main.py vuln --url https://example.com
  python main.py brute --url https://example.com/
  python main.py shell --type bash --lhost 192.168.1.100 --lport 4444
  python main.py phishing --url https://suspicious-site.com
        """
    )
    
    # Global options
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--format', choices=['json', 'xml', 'csv', 'html', 'text'], 
                       default='json', help='Output format')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Reconnaissance
    recon_parser = subparsers.add_parser('recon', help='Reconnaissance and information gathering')
    recon_parser.add_argument('--whois', help='Domain for WHOIS lookup')
    recon_parser.add_argument('--subenum', help='Domain for subdomain enumeration')
    recon_parser.add_argument('--dns', help='Domain for DNS lookup')
    recon_parser.add_argument('--wordlist', help='Custom wordlist for subdomain enumeration')
    
    # Port scanning
    scan_parser = subparsers.add_parser('scan', help='Port scanning')
    scan_parser.add_argument('--target', required=True, help='Target IP or hostname')
    scan_parser.add_argument('--ports', nargs='+', type=int, help='Specific ports to scan')
    scan_parser.add_argument('--threads', type=int, default=50, help='Number of threads')
    
    # Vulnerability scanning
    vuln_parser = subparsers.add_parser('vuln', help='Vulnerability scanning')
    vuln_parser.add_argument('--url', help='Target URL for web vulnerability scan')
    vuln_parser.add_argument('--service', help='Service name for CVE lookup')
    
    # Directory brute force
    brute_parser = subparsers.add_parser('brute', help='Directory brute force')
    brute_parser.add_argument('--url', required=True, help='Target URL')
    brute_parser.add_argument('--wordlist', help='Custom wordlist file')
    brute_parser.add_argument('--extensions', nargs='+', help='File extensions to try')
    brute_parser.add_argument('--threads', type=int, default=10, help='Number of threads')
    
    # Reverse shell generation
    shell_parser = subparsers.add_parser('shell', help='Reverse shell generation')
    shell_parser.add_argument('--type', required=True, 
                             choices=['bash', 'python', 'python3', 'nc', 'powershell', 'php', 'perl', 'ruby'],
                             help='Shell type')
    shell_parser.add_argument('--lhost', required=True, help='Listener IP')
    shell_parser.add_argument('--lport', type=int, required=True, help='Listener Port')
    
    # Phishing detection
    phishing_parser = subparsers.add_parser('phishing', help='Phishing detection and analysis')
    phishing_parser.add_argument('--url', required=True, help='URL to analyze')
    phishing_parser.add_argument('--reputation', action='store_true', help='Check URL reputation')
    
    # Network monitoring
    monitor_parser = subparsers.add_parser('monitor', help='Network monitoring')
    monitor_parser.add_argument('--duration', type=int, default=60, help='Monitoring duration (seconds)')
    monitor_parser.add_argument('--interface', help='Network interface to monitor')
    monitor_parser.add_argument('--portscan-detect', action='store_true', help='Port scan detection mode')
    
    # Fingerprinting
    finger_parser = subparsers.add_parser('finger', help='Service fingerprinting')
    finger_parser.add_argument('--target', required=True, help='Target IP or hostname')
    finger_parser.add_argument('--port', type=int, help='Specific port to fingerprint')
    finger_parser.add_argument('--http', action='store_true', help='HTTP service fingerprinting')
    finger_parser.add_argument('--ssl', action='store_true', help='SSL certificate information')
    
    return parser

def main():
    """Main entry point"""
    parser = setup_cli()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Setup logging
    log_level = 'DEBUG' if args.verbose else 'INFO'
    setup_logger(level=getattr(__import__('logging'), log_level))
    
    # Initialize report generator
    report_gen = ReportGenerator()
    if args.format:
        report_gen.output_format = args.format
    
    results = None
    
    try:
        # Execute commands
        if args.command == 'recon':
            results = handle_recon(args)
        elif args.command == 'scan':
            results = handle_scan(args)
        elif args.command == 'vuln':
            results = handle_vuln(args)
        elif args.command == 'brute':
            results = handle_brute(args)
        elif args.command == 'shell':
            results = handle_shell(args)
        elif args.command == 'phishing':
            results = handle_phishing(args)
        elif args.command == 'monitor':
            results = handle_monitor(args)
        elif args.command == 'finger':
            results = handle_fingerprint(args)
        
        # Output results
        if results:
            if args.output:
                # Generate report file
                if args.format == 'json':
                    with open(args.output, 'w') as f:
                        json.dump(results, f, indent=2)
                else:
                    report_gen.generate_scan_report([results], args.output)
                logger.info(f"Results saved to {args.output}")
            else:
                # Print to console
                if args.format == 'json':
                    print(json.dumps(results, indent=2))
                else:
                    print_results(results)
    
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()

def handle_recon(args):
    """Handle reconnaissance commands"""
    recon = ReconModule()
    
    if args.whois:
        logger.info(f"Starting WHOIS lookup for {args.whois}")
        return recon.whois_lookup(args.whois)
    
    elif args.subenum:
        logger.info(f"Starting subdomain enumeration for {args.subenum}")
        return recon.subdomain_enum(args.subenum, args.wordlist)
    
    elif args.dns:
        logger.info(f"Starting DNS lookup for {args.dns}")
        return recon.dns_lookup(args.dns)

def handle_scan(args):
    """Handle port scanning commands"""
    scanner = PortScanner()
    return scanner.tcp_scan(args.target, args.ports, args.threads)

def handle_vuln(args):
    """Handle vulnerability scanning commands"""
    if args.url:
        vuln_scanner = WebVulnScanner()
        return vuln_scanner.scan_web_vulnerabilities(args.url)
    
    elif args.service:
        cve_scanner = VulnerabilityScanner()
        return cve_scanner.cve_lookup(args.service)

def handle_brute(args):
    """Handle directory brute force commands"""
    bruteforcer = DirectoryBruteforcer()
    return bruteforcer.dir_brute(args.url, args.wordlist, args.extensions, args.threads)

def handle_shell(args):
    """Handle reverse shell generation commands"""
    exploit = ExploitModule()
    return exploit.generate_reverse_shell(args.type, args.lhost, args.lport)

def handle_phishing(args):
    """Handle phishing detection commands"""
    detector = PhishingDetector()
    
    if args.reputation:
        return detector.check_reputation(args.url)
    else:
        return detector.analyze_url(args.url)

def handle_monitor(args):
    """Handle network monitoring commands"""
    try:
        monitor = NetworkMonitor()
        
        if args.portscan_detect:
            return monitor.port_scan_detection(args.interface, args.duration)
        else:
            return monitor.start_monitoring(args.interface, args.duration)
    
    except Exception as e:
        logger.warning(f"Advanced monitoring failed: {e}")
        logger.info("Falling back to basic monitoring")
        basic_monitor = BasicNetworkMonitor()
        return basic_monitor.monitor_connections(args.duration)

def handle_fingerprint(args):
    """Handle service fingerprinting commands"""
    fingerprinter = ServiceFingerprinter()
    
    if args.http:
        url = f"http://{args.target}"
        if args.port and args.port != 80:
            url = f"http://{args.target}:{args.port}"
        return fingerprinter.fingerprint_http(url)
    
    elif args.ssl:
        port = args.port or 443
        return fingerprinter.get_ssl_info(args.target, port)
    
    else:
        port = args.port or 80
        banner = fingerprinter.grab_banner(args.target, port)
        return {"target": args.target, "port": port, "banner": banner}

def print_results(results):
    """Print results in a readable format"""
    if isinstance(results, dict):
        if "error" in results:
            logger.error(results["error"])
            return
        
        # Print based on result type
        if "vulnerabilities" in results:
            print_vulnerability_results(results)
        elif "subdomains" in results:
            print_subdomain_results(results)
        elif "open_ports" in results:
            print_port_scan_results(results)
        else:
            # Generic print
            for key, value in results.items():
                print(f"{key}: {value}")
    elif isinstance(results, list):
        for i, result in enumerate(results):
            print(f"Result {i+1}:")
            print_results(result)
            print("-" * 40)
    else:
        print(results)

def print_vulnerability_results(results):
    """Print vulnerability scan results"""
    print(f"Target: {results.get('target', 'Unknown')}")
    print(f"Vulnerabilities found: {results.get('vulnerabilities_found', 0)}")
    print()
    
    for vuln in results.get('vulnerabilities', []):
        print(f"[{vuln.get('severity', 'Unknown')}] {vuln.get('type', 'Unknown')}")
        print(f"  Description: {vuln.get('description', vuln.get('evidence', 'No description'))}")
        print()

def print_subdomain_results(results):
    """Print subdomain enumeration results"""
    print(f"Domain: {results.get('domain', 'Unknown')}")
    print(f"Subdomains found: {results.get('subdomains_found', 0)}")
    print()
    
    for subdomain in results.get('subdomains', []):
        print(f"  {subdomain['subdomain']} -> {subdomain['ip']}")

def print_port_scan_results(results):
    """Print port scan results"""
    print(f"Target: {results.get('target', 'Unknown')}")
    print(f"Open ports: {len(results.get('open_ports', []))}")
    print()
    
    for port in results.get('open_ports', []):
        print(f"  {port['port']}/{port['protocol']} - {port['state']}")

if __name__ == '__main__':
    main()
