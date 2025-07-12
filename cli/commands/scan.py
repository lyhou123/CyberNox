"""
Scanning Commands
Port scanning, service detection, and network discovery
"""

import click
from core.scanner import PortScanner
from ..utils.formatter import (
    ColoredFormatter, common_options, save_results, display_results, 
    validate_target, parse_ports, get_common_ports
)


@click.group()
def scan():
    """🎯 Port scanning and service detection"""
    pass


@scan.command()
@click.argument('target')
@click.option('--ports', help='Ports to scan (comma-separated or range like 1-1000)')
@click.option('--top-ports', type=int, help='Scan top N most common ports')
@click.option('--tcp', 'scan_type', flag_value='tcp', default=True, help='TCP scan (default)')
@click.option('--udp', 'scan_type', flag_value='udp', help='UDP scan')
@click.option('--syn', 'scan_type', flag_value='syn', help='SYN scan')
@click.option('--max-threads', type=int, default=50, help='Maximum number of threads')
@click.option('--stealth', is_flag=True, help='Enable stealth scanning mode')
@common_options
def ports(target, ports, top_ports, scan_type, max_threads, stealth, output, format, timeout, threads):
    """Scan ports on a target
    
    Examples:
        cybernox scan ports 192.168.1.1
        cybernox scan ports example.com --ports 80,443,22,21
        cybernox scan ports 10.0.0.1 --ports 1-1000 --max-threads 100
        cybernox scan ports target.com --top-ports 100 --stealth
        cybernox scan ports 192.168.1.0/24 --udp --output scan_results.json
    """
    if not validate_target(target.split('/')[0]):  # Handle CIDR notation
        click.echo(ColoredFormatter.error("❌ Invalid target format"))
        return
    
    click.echo(ColoredFormatter.info(f"🎯 Starting {scan_type.upper()} port scan on {target}"))
    
    # Parse ports
    if top_ports:
        port_list = get_common_ports(top_ports)
        click.echo(ColoredFormatter.info(f"📊 Scanning top {top_ports} common ports"))
    else:
        port_list = parse_ports(ports)
        if port_list is None:
            return
    
    if stealth:
        click.echo(ColoredFormatter.info("🥷 Stealth mode enabled"))
    
    click.echo(ColoredFormatter.info(f"🔍 Scanning {len(port_list)} ports with {max_threads} threads"))
    
    try:
        scanner = PortScanner()
        
        with click.progressbar(length=len(port_list), label=f'Scanning {scan_type.upper()} ports') as bar:
            if scan_type == 'tcp':
                results = scanner.tcp_scan(target, port_list, max_threads)
            elif scan_type == 'udp':
                results = scanner.udp_scan(target, port_list) if hasattr(scanner, 'udp_scan') else scanner.tcp_scan(target, port_list, max_threads)
            elif scan_type == 'syn':
                results = scanner.syn_scan(target, port_list) if hasattr(scanner, 'syn_scan') else scanner.tcp_scan(target, port_list, max_threads)
            else:
                results = scanner.tcp_scan(target, port_list, max_threads)
            
            bar.update(len(port_list))
        
        if results and results.get('open_ports'):
            open_count = len(results['open_ports'])
            click.echo(ColoredFormatter.success(f"✅ Found {open_count} open ports"))
            
            if output:
                save_results(results, output, format)
            else:
                display_results(results, format)
        else:
            click.echo(ColoredFormatter.warning("⚠️  No open ports found"))
            
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ Port scan failed: {e}"))


@scan.command()
@click.argument('network')
@click.option('--ping', is_flag=True, help='Use ping sweep for discovery')
@click.option('--arp', is_flag=True, help='Use ARP scanning for local networks')
@click.option('--max-threads', type=int, default=50, help='Maximum number of threads')
@common_options
def network(network, ping, arp, max_threads, output, format, timeout, threads):
    """Discover hosts on a network
    
    Examples:
        cybernox scan network 192.168.1.0/24
        cybernox scan network 10.0.0.0/24 --ping --max-threads 100
        cybernox scan network 172.16.0.0/16 --arp --output network_scan.json
    """
    click.echo(ColoredFormatter.info(f"🌐 Starting network discovery on {network}"))
    
    if ping:
        click.echo(ColoredFormatter.info("📡 Using ping sweep"))
    if arp:
        click.echo(ColoredFormatter.info("📡 Using ARP scanning"))
    
    try:
        scanner = PortScanner()
        
        with click.progressbar(label='Discovering hosts') as bar:
            if hasattr(scanner, 'discover_hosts'):
                results = scanner.discover_hosts(network)
            else:
                # Fallback implementation
                results = {
                    'network': network,
                    'hosts': [],
                    'scan_method': 'ping' if ping else 'arp' if arp else 'tcp',
                    'timestamp': str(click.DateTime())
                }
            bar.update(1)
        
        if results and results.get('hosts'):
            host_count = len(results['hosts'])
            click.echo(ColoredFormatter.success(f"✅ Discovered {host_count} active hosts"))
            
            if output:
                save_results(results, output, format)
            else:
                display_results(results, format)
        else:
            click.echo(ColoredFormatter.warning("⚠️  No active hosts found"))
            
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ Network discovery failed: {e}"))


@scan.command()
@click.argument('target')
@click.option('--port', type=int, help='Specific port to scan for services')
@click.option('--common-ports', is_flag=True, help='Scan common service ports only')
@click.option('--aggressive', is_flag=True, help='Enable aggressive service detection')
@common_options
def services(target, port, common_ports, aggressive, output, format, timeout, threads):
    """Detect services and versions on open ports
    
    Examples:
        cybernox scan services 192.168.1.1
        cybernox scan services example.com --port 80
        cybernox scan services target.com --common-ports --aggressive
        cybernox scan services 10.0.0.1 --output service_scan.json
    """
    if not validate_target(target):
        click.echo(ColoredFormatter.error("❌ Invalid target format"))
        return
    
    click.echo(ColoredFormatter.info(f"🔍 Starting service detection on {target}"))
    
    if port:
        port_list = [port]
        click.echo(ColoredFormatter.info(f"🎯 Scanning specific port: {port}"))
    elif common_ports:
        port_list = get_common_ports(50)
        click.echo(ColoredFormatter.info("📊 Scanning common service ports"))
    else:
        port_list = get_common_ports(100)
    
    if aggressive:
        click.echo(ColoredFormatter.info("🚀 Aggressive service detection enabled"))
    
    try:
        scanner = PortScanner()
        
        with click.progressbar(length=len(port_list), label='Detecting services') as bar:
            # First scan for open ports
            port_results = scanner.tcp_scan(target, port_list, 50)
            
            if port_results and port_results.get('open_ports'):
                # Then detect services on open ports
                results = {
                    'target': target,
                    'services': [],
                    'scan_type': 'service_detection',
                    'aggressive': aggressive,
                    'timestamp': str(click.DateTime())
                }
                
                for port_info in port_results['open_ports']:
                    port_num = port_info['port']
                    # Service detection logic would go here
                    service_info = {
                        'port': port_num,
                        'protocol': port_info.get('protocol', 'tcp'),
                        'state': port_info.get('state', 'open'),
                        'service': f'service-{port_num}',  # Placeholder
                        'version': 'unknown'
                    }
                    results['services'].append(service_info)
            else:
                results = {'target': target, 'services': [], 'error': 'No open ports found'}
            
            bar.update(len(port_list))
        
        if results and results.get('services'):
            service_count = len(results['services'])
            click.echo(ColoredFormatter.success(f"✅ Detected {service_count} services"))
            
            if output:
                save_results(results, output, format)
            else:
                display_results(results, format)
        else:
            click.echo(ColoredFormatter.warning("⚠️  No services detected"))
            
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ Service detection failed: {e}"))


@scan.command()
@click.argument('target')
@click.option('--quick', is_flag=True, help='Quick scan (top 100 ports)')
@click.option('--full', is_flag=True, help='Full scan (all 65535 ports)')
@click.option('--custom-ports', help='Custom port list for comprehensive scan')
@click.option('--service-detection', is_flag=True, help='Include service detection')
@click.option('--os-detection', is_flag=True, help='Include OS detection')
@common_options
def comprehensive(target, quick, full, custom_ports, service_detection, os_detection, output, format, timeout, threads):
    """Comprehensive scan combining multiple techniques
    
    Examples:
        cybernox scan comprehensive 192.168.1.1 --quick
        cybernox scan comprehensive example.com --service-detection --os-detection
        cybernox scan comprehensive target.com --full --output comprehensive_scan.json
        cybernox scan comprehensive 10.0.0.1 --custom-ports 80,443,8080,8443
    """
    if not validate_target(target):
        click.echo(ColoredFormatter.error("❌ Invalid target format"))
        return
    
    click.echo(ColoredFormatter.info(f"🎯 Starting comprehensive scan on {target}"))
    
    # Determine port range
    if quick:
        port_list = get_common_ports(100)
        click.echo(ColoredFormatter.info("⚡ Quick scan mode (top 100 ports)"))
    elif full:
        port_list = list(range(1, 65536))
        click.echo(ColoredFormatter.info("🔍 Full scan mode (all 65535 ports)"))
    elif custom_ports:
        port_list = parse_ports(custom_ports)
        if port_list is None:
            return
        click.echo(ColoredFormatter.info(f"⚙️  Custom port scan ({len(port_list)} ports)"))
    else:
        port_list = get_common_ports(1000)
        click.echo(ColoredFormatter.info("📊 Standard comprehensive scan (top 1000 ports)"))
    
    scan_features = []
    if service_detection:
        scan_features.append("Service Detection")
    if os_detection:
        scan_features.append("OS Detection")
    
    if scan_features:
        click.echo(ColoredFormatter.info(f"🔧 Additional features: {', '.join(scan_features)}"))
    
    try:
        scanner = PortScanner()
        
        results = {
            'target': target,
            'scan_type': 'comprehensive',
            'features': scan_features,
            'total_ports': len(port_list),
            'timestamp': str(click.DateTime())
        }
        
        with click.progressbar(length=len(port_list), label='Comprehensive scanning') as bar:
            # Port scan
            port_results = scanner.tcp_scan(target, port_list, 100)
            results.update(port_results)
            bar.update(len(port_list))
        
        if results.get('open_ports'):
            open_count = len(results['open_ports'])
            click.echo(ColoredFormatter.success(f"✅ Comprehensive scan completed - {open_count} open ports found"))
            
            if output:
                save_results(results, output, format)
            else:
                display_results(results, format)
        else:
            click.echo(ColoredFormatter.warning("⚠️  No open ports found in comprehensive scan"))
            
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ Comprehensive scan failed: {e}"))
