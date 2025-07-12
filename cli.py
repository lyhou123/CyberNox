"""
Professional CLI interface for CyberNox using Click framework
"""

import click
import sys
import json
import time
from pathlib import Path
from datetime import datetime

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
from utils.advanced_config import config_manager
from utils.fingerprint import ServiceFingerprinter

# ASCII Art Banner
BANNER = """
  ╔═╗┬ ┬┌┐ ┌─┐┬─┐╔╗╔┌─┐─┐ ┬
  ║  └┬┘├┴┐├┤ ├┬┘║║║│ │┌┴┬┘
  ╚═╝ ┴ └─┘└─┘┴└─╝╚╝└─┘┴ └─
  
  All-in-One Cybersecurity Toolkit v1.0.0
  Professional Edition
"""

class ColoredFormatter:
    """Colored output formatter"""
    
    @staticmethod
    def success(text):
        return click.style(text, fg='green', bold=True)
    
    @staticmethod
    def error(text):
        return click.style(text, fg='red', bold=True)
    
    @staticmethod
    def warning(text):
        return click.style(text, fg='yellow', bold=True)
    
    @staticmethod
    def info(text):
        return click.style(text, fg='blue', bold=True)
    
    @staticmethod
    def header(text):
        return click.style(text, fg='cyan', bold=True)

def print_banner():
    """Print the application banner"""
    click.echo(click.style(BANNER, fg='cyan', bold=True))

def save_results(results, output_file, format_type):
    """Save results to file with proper formatting"""
    try:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format_type == 'json':
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
        else:
            report_gen = ReportGenerator()
            report_gen.output_format = format_type
            report_gen.generate_scan_report([results], str(output_path.with_suffix('')))
        
        click.echo(ColoredFormatter.success(f"Results saved to: {output_path}"))
        return True
        
    except Exception as e:
        click.echo(ColoredFormatter.error(f"Failed to save results: {e}"))
        return False

def display_results(results, format_type='json'):
    """Display results in the specified format"""
    if not results:
        click.echo(ColoredFormatter.warning("No results to display"))
        return
    
    if isinstance(results, dict) and "error" in results:
        click.echo(ColoredFormatter.error(f"Error: {results['error']}"))
        return
    
    if format_type == 'json':
        click.echo(json.dumps(results, indent=2, ensure_ascii=False))
    elif format_type == 'table':
        display_table_results(results)
    else:
        # For other formats, use JSON as fallback
        click.echo(json.dumps(results, indent=2, ensure_ascii=False))

def display_table_results(results):
    """Display results in table format"""
    if isinstance(results, dict):
        if "vulnerabilities" in results:
            display_vulnerability_table(results)
        elif "subdomains" in results:
            display_subdomain_table(results)
        elif "open_ports" in results:
            display_port_table(results)
        else:
            # Generic display
            for key, value in results.items():
                click.echo(f"{ColoredFormatter.header(key)}: {value}")

def display_vulnerability_table(results):
    """Display vulnerability results in table format"""
    click.echo(ColoredFormatter.header(f"\n🎯 Target: {results.get('target', 'Unknown')}"))
    click.echo(ColoredFormatter.header(f"📊 Vulnerabilities Found: {results.get('vulnerabilities_found', 0)}"))
    click.echo()
    
    for vuln in results.get('vulnerabilities', []):
        severity = vuln.get('severity', 'Unknown')
        if severity.lower() == 'critical':
            severity_color = 'red'
        elif severity.lower() == 'high':
            severity_color = 'yellow'
        elif severity.lower() == 'medium':
            severity_color = 'blue'
        else:
            severity_color = 'green'
        
        click.echo(f"🔍 {click.style(severity, fg=severity_color, bold=True)} - {vuln.get('type', 'Unknown')}")
        click.echo(f"   📝 {vuln.get('description', vuln.get('evidence', 'No description'))}")
        click.echo()

def display_subdomain_table(results):
    """Display subdomain results in table format"""
    click.echo(ColoredFormatter.header(f"\n🌐 Domain: {results.get('domain', 'Unknown')}"))
    click.echo(ColoredFormatter.header(f"📊 Subdomains Found: {results.get('subdomains_found', 0)}"))
    click.echo()
    
    for subdomain in results.get('subdomains', []):
        click.echo(f"🔗 {ColoredFormatter.success(subdomain['subdomain'])} -> {subdomain['ip']}")

def display_port_table(results):
    """Display port scan results in table format"""
    click.echo(ColoredFormatter.header(f"\n🎯 Target: {results.get('target', 'Unknown')}"))
    click.echo(ColoredFormatter.header(f"📊 Open Ports: {len(results.get('open_ports', []))}"))
    click.echo()
    
    for port in results.get('open_ports', []):
        port_str = f"{port['port']}/{port['protocol']}"
        click.echo(f"🔓 {ColoredFormatter.success(port_str)} - {port['state']}")

# Common options
@click.group(invoke_without_command=True)
@click.option('--version', is_flag=True, help='Show version information')
@click.option('--config', help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def cli(ctx, version, config, verbose):
    """CyberNox - Professional Cybersecurity Toolkit"""
    
    if version:
        click.echo("CyberNox Professional Edition v1.0.0")
        click.echo("Copyright (c) 2025 CyberNox Team")
        return
    
    if ctx.invoked_subcommand is None:
        print_banner()
        click.echo("Use --help to see available commands")
        return
    
    # Setup logging
    if verbose:
        setup_logger(level='DEBUG')
    else:
        setup_logger(level='INFO')

# Global options decorator
def common_options(func):
    """Common options for all commands"""
    func = click.option('--output', '-o', help='Output file path')(func)
    func = click.option('--format', type=click.Choice(['json', 'xml', 'csv', 'html', 'text', 'table']), 
                       default='table', help='Output format')(func)
    func = click.option('--timeout', type=int, help='Request timeout in seconds')(func)
    func = click.option('--threads', type=int, help='Number of threads to use')(func)
    return func

@cli.group()
def recon():
    """Reconnaissance and information gathering"""
    pass

@recon.command()
@click.argument('domain')
@common_options
def whois(domain, output, format, timeout, threads):
    """Perform WHOIS lookup for a domain"""
    click.echo(ColoredFormatter.info(f"🔍 Starting WHOIS lookup for {domain}"))
    
    recon_module = ReconModule()
    
    with click.progressbar(length=1, label='Performing WHOIS lookup') as bar:
        results = recon_module.whois_lookup(domain)
        bar.update(1)
    
    if output:
        save_results(results, output, format)
    else:
        display_results(results, format)

@recon.command()
@click.argument('domain')
@click.option('--wordlist', help='Custom wordlist file')
@click.option('--max-threads', type=int, default=50, help='Maximum number of threads')
@common_options
def subdomains(domain, wordlist, max_threads, output, format, timeout, threads):
    """Enumerate subdomains for a domain"""
    click.echo(ColoredFormatter.info(f"🔍 Starting subdomain enumeration for {domain}"))
    
    recon_module = ReconModule()
    
    with click.progressbar(label='Enumerating subdomains') as bar:
        results = recon_module.subdomain_enum(domain, wordlist, max_threads)
        bar.update(1)
    
    if output:
        save_results(results, output, format)
    else:
        display_results(results, format)

@cli.group()
def scan():
    """Port scanning and service detection"""
    pass

@scan.command()
@click.argument('target')
@click.option('--ports', help='Ports to scan (comma-separated or range like 1-1000)')
@click.option('--top-ports', type=int, help='Scan top N most common ports')
@click.option('--max-threads', type=int, default=50, help='Maximum number of threads')
@common_options
def ports(target, ports, top_ports, max_threads, output, format, timeout, threads):
    """Scan ports on a target"""
    click.echo(ColoredFormatter.info(f"🎯 Starting port scan on {target}"))
    
    # Parse ports
    port_list = []
    if ports:
        if '-' in ports:
            start, end = map(int, ports.split('-'))
            port_list = list(range(start, end + 1))
        else:
            port_list = [int(p.strip()) for p in ports.split(',')]
    elif top_ports:
        # Use most common ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
        port_list = common_ports[:top_ports]
    else:
        port_list = [80, 443, 22, 21, 25, 53]
    
    scanner = PortScanner()
    
    with click.progressbar(length=len(port_list), label='Scanning ports') as bar:
        results = scanner.tcp_scan(target, port_list, max_threads)
        bar.update(len(port_list))
    
    if output:
        save_results(results, output, format)
    else:
        display_results(results, format)

@cli.group()
def vuln():
    """Vulnerability scanning and assessment"""
    pass

@vuln.command()
@click.argument('url')
@common_options
def web(url, output, format, timeout, threads):
    """Scan web application for vulnerabilities"""
    click.echo(ColoredFormatter.info(f"🔍 Starting web vulnerability scan on {url}"))
    
    scanner = WebVulnScanner()
    
    with click.progressbar(label='Scanning for vulnerabilities') as bar:
        results = scanner.scan_web_vulnerabilities(url)
        bar.update(1)
    
    if output:
        save_results(results, output, format)
    else:
        display_results(results, format)

@cli.group()
def exploit():
    """Exploitation and payload generation"""
    pass

@exploit.command()
@click.argument('shell_type', type=click.Choice(['bash', 'python', 'python3', 'nc', 'powershell', 'php', 'perl', 'ruby']))
@click.argument('lhost')
@click.argument('lport', type=int)
@click.option('--encode', type=click.Choice(['base64', 'url']), help='Encode the payload')
@common_options
def shell(shell_type, lhost, lport, encode, output, format, timeout, threads):
    """Generate reverse shell payloads"""
    click.echo(ColoredFormatter.info(f"🔧 Generating {shell_type} reverse shell"))
    
    exploit_module = ExploitModule()
    results = exploit_module.generate_reverse_shell(shell_type, lhost, lport)
    
    if encode and 'encoded' in results:
        if encode == 'base64':
            click.echo(ColoredFormatter.header("Base64 Encoded:"))
            click.echo(results['encoded']['base64'])
        elif encode == 'url':
            click.echo(ColoredFormatter.header("URL Encoded:"))
            click.echo(results['encoded']['url'])
    
    if output:
        save_results(results, output, format)
    else:
        if not encode:
            display_results(results, format)

@cli.command()
@click.argument('url')
@click.option('--wordlist', help='Custom wordlist file')
@click.option('--extensions', help='File extensions to try (comma-separated)')
@click.option('--max-threads', type=int, default=10, help='Maximum number of threads')
@common_options
def brute(url, wordlist, extensions, max_threads, output, format, timeout, threads):
    """Brute force directories and files"""
    click.echo(ColoredFormatter.info(f"🔍 Starting directory brute force on {url}"))
    
    ext_list = None
    if extensions:
        ext_list = [f".{ext.strip('.')}" for ext in extensions.split(',')]
    
    bruteforcer = DirectoryBruteforcer()
    
    with click.progressbar(label='Brute forcing directories') as bar:
        results = bruteforcer.dir_brute(url, wordlist, ext_list, max_threads)
        bar.update(1)
    
    if output:
        save_results(results, output, format)
    else:
        display_results(results, format)

@cli.command()
@click.argument('target')
@click.option('--port', type=int, help='Specific port to fingerprint')
@click.option('--http', is_flag=True, help='HTTP service fingerprinting')
@click.option('--ssl', is_flag=True, help='SSL certificate analysis')
@common_options
def finger(target, port, http, ssl, output, format, timeout, threads):
    """Service fingerprinting and banner grabbing"""
    click.echo(ColoredFormatter.info(f"🔍 Fingerprinting services on {target}"))
    
    fingerprinter = ServiceFingerprinter()
    
    if http:
        url = f"http://{target}"
        if port and port != 80:
            url = f"http://{target}:{port}"
        results = fingerprinter.fingerprint_http(url)
    elif ssl:
        port = port or 443
        results = fingerprinter.get_ssl_info(target, port)
    else:
        port = port or 80
        banner = fingerprinter.grab_banner(target, port)
        results = {"target": target, "port": port, "banner": banner}
    
    if output:
        save_results(results, output, format)
    else:
        display_results(results, format)

@cli.command()
@click.option('--duration', type=int, default=60, help='Monitoring duration in seconds')
@click.option('--interface', help='Network interface to monitor')
@click.option('--detect-scans', is_flag=True, help='Port scan detection mode')
@common_options
def monitor(duration, interface, detect_scans, output, format, timeout, threads):
    """Network monitoring and traffic analysis"""
    click.echo(ColoredFormatter.info(f"📡 Starting network monitoring for {duration} seconds"))
    
    try:
        monitor = NetworkMonitor()
        
        with click.progressbar(length=duration, label='Monitoring network') as bar:
            if detect_scans:
                results = monitor.port_scan_detection(interface, duration)
            else:
                results = monitor.start_monitoring(interface, duration)
            
            for i in range(duration):
                time.sleep(1)
                bar.update(1)
    
    except Exception as e:
        click.echo(ColoredFormatter.warning(f"Advanced monitoring failed: {e}"))
        click.echo(ColoredFormatter.info("Falling back to basic monitoring"))
        basic_monitor = BasicNetworkMonitor()
        results = basic_monitor.monitor_connections(duration)
    
    if output:
        save_results(results, output, format)
    else:
        display_results(results, format)

@cli.command()
@click.argument('url')
@click.option('--check-reputation', is_flag=True, help='Check URL reputation')
@common_options
def phishing(url, check_reputation, output, format, timeout, threads):
    """Phishing detection and URL analysis"""
    click.echo(ColoredFormatter.info(f"🎣 Analyzing URL: {url}"))
    
    detector = PhishingDetector()
    
    with click.progressbar(length=1, label='Analyzing URL') as bar:
        if check_reputation:
            results = detector.check_reputation(url)
        else:
            results = detector.analyze_url(url)
        bar.update(1)
    
    if output:
        save_results(results, output, format)
    else:
        display_results(results, format)

@cli.command()
def config():
    """Show current configuration"""
    click.echo(ColoredFormatter.header("🔧 Current Configuration:"))
    click.echo()
    
    config_data = {
        'network': {
            'user_agent': config_manager.network.user_agent,
            'timeout': config_manager.network.timeout,
            'max_retries': config_manager.network.max_retries,
        },
        'scan': {
            'default_threads': config_manager.scan.default_threads,
            'rate_limit': config_manager.scan.rate_limit,
            'stealth_mode': config_manager.scan.stealth_mode,
        },
        'security': {
            'ssl_verify': config_manager.security.ssl_verify,
            'follow_redirects': config_manager.security.follow_redirects,
        }
    }
    
    click.echo(json.dumps(config_data, indent=2))

if __name__ == '__main__':
    cli()
