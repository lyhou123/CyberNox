"""
CLI Utilities and Formatters
Common utilities for the CLI interface
"""

import click
import json
from pathlib import Path
from core.report import ReportGenerator


class ColoredFormatter:
    """Colored output formatter for CLI"""
    
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
    
    @staticmethod
    def critical(text):
        return click.style(text, fg='red', bg='white', bold=True)


def print_banner():
    """Print the application banner"""
    banner = """
  ╔═╗┬ ┬┌┐ ┌─┐┬─┐╔╗╔┌─┐─┐ ┬
  ║  └┬┘├┴┐├┤ ├┬┘║║║│ │┌┴┬┘
  ╚═╝ ┴ └─┘└─┘┴└─╝╚╝└─┘┴ └─
  
  All-in-One Cybersecurity Toolkit v1.0.0
  Professional Edition
"""
    click.echo(click.style(banner, fg='cyan', bold=True))


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
        
        click.echo(ColoredFormatter.success(f"✅ Results saved to: {output_path}"))
        return True
        
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ Failed to save results: {e}"))
        return False


def display_results(results, format_type='json'):
    """Display results in the specified format"""
    if not results:
        click.echo(ColoredFormatter.warning("⚠️  No results to display"))
        return
    
    if isinstance(results, dict) and "error" in results:
        click.echo(ColoredFormatter.error(f"❌ Error: {results['error']}"))
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


def common_options(func):
    """Common options decorator for all commands"""
    func = click.option('--output', '-o', help='Output file path')(func)
    func = click.option('--format', type=click.Choice(['json', 'xml', 'csv', 'html', 'text', 'table']), 
                       default='table', help='Output format')(func)
    func = click.option('--timeout', type=int, help='Request timeout in seconds')(func)
    func = click.option('--threads', type=int, help='Number of threads to use')(func)
    return func


def validate_target(target):
    """Validate target format (IP or domain)"""
    import re
    
    # Basic IP regex
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    
    # Basic domain regex
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    
    if re.match(ip_pattern, target) or re.match(domain_pattern, target):
        return True
    return False


def parse_ports(ports_input):
    """Parse port input string into list of ports"""
    port_list = []
    
    if not ports_input:
        return [80, 443, 22, 21, 25, 53]  # Default common ports
    
    try:
        if '-' in ports_input:
            start, end = map(int, ports_input.split('-'))
            port_list = list(range(start, min(end + 1, 65536)))
        else:
            port_list = [int(p.strip()) for p in ports_input.split(',')]
        
        # Validate port range
        port_list = [p for p in port_list if 1 <= p <= 65535]
        
    except ValueError:
        click.echo(ColoredFormatter.error("❌ Invalid port format. Use comma-separated or range (e.g., 80,443 or 1-1000)"))
        return None
    
    return port_list


def get_common_ports(count=100):
    """Get list of most common ports"""
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 
        1723, 3306, 3389, 5432, 5900, 8080, 8443, 9090, 3000, 5000,
        8000, 8888, 9000, 10000, 1433, 1521, 3690, 5060, 5061, 5432,
        6379, 11211, 27017, 50000, 161, 162, 389, 636, 514, 515, 631,
        873, 1194, 1701, 1723, 4500, 500, 4569, 5004, 5005, 2000, 
        2001, 5432, 1080, 1085, 8082, 8181, 9001, 9002, 9003, 9004,
        1337, 31337, 12345, 54321, 65000, 65301, 1234, 6666, 6667,
        6668, 6669, 7000, 7001, 7002, 8001, 8002, 8003, 8004, 8005,
        9080, 9443, 10080, 12000, 12001, 12002, 15000, 16000, 20000,
        32768, 32769, 32770, 32771, 40193, 49152, 49153, 49154, 49155,
        49156, 49157, 2222, 2323, 3322, 3333, 4444, 5555, 7777, 8888
    ]
    
    return common_ports[:count]
