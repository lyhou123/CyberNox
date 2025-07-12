"""
Monitoring and Surveillance Commands
Network monitoring, traffic analysis, and surveillance tools
"""

import click
from core.monitor import NetworkMonitor
from ..utils.formatter import ColoredFormatter, common_options, save_results, display_results, validate_target, parse_ports


@click.group()
def monitor():
    """📡 Network monitoring and surveillance"""
    pass


@monitor.command()
@click.option('--interface', '-i', help='Network interface to monitor (e.g., eth0, wlan0)')
@click.option('--duration', '-d', type=int, default=60, help='Monitoring duration in seconds')
@click.option('--protocol', type=click.Choice(['tcp', 'udp', 'icmp', 'all']), default='all',
              help='Protocol to monitor')
@click.option('--port', '-p', help='Specific port to monitor (e.g., 80, 443, 22)')
@click.option('--host', help='Specific host to monitor')
@click.option('--save-pcap', help='Save packets to PCAP file')
@click.option('--filter', help='Custom packet filter (BPF syntax)')
@common_options
def traffic(interface, duration, protocol, port, host, save_pcap, filter, output, format, timeout, threads):
    """Monitor network traffic in real-time
    
    Examples:
        cybernox monitor traffic --interface eth0 --duration 120
        cybernox monitor traffic -i wlan0 --protocol tcp --port 80
        cybernox monitor traffic --host 192.168.1.1 --save-pcap capture.pcap
        cybernox monitor traffic --filter "port 22 or port 80" --duration 300
    """
    click.echo(ColoredFormatter.info(f"📡 Starting network traffic monitoring"))
    
    if interface:
        click.echo(ColoredFormatter.info(f"🔌 Interface: {interface}"))
    else:
        click.echo(ColoredFormatter.info("🔌 Using default interface"))
    
    click.echo(ColoredFormatter.info(f"⏱️  Duration: {duration} seconds"))
    click.echo(ColoredFormatter.info(f"🌐 Protocol: {protocol.upper()}"))
    
    if port:
        click.echo(ColoredFormatter.info(f"🚪 Monitoring port: {port}"))
    if host:
        if not validate_target(host):
            click.echo(ColoredFormatter.error("❌ Invalid host format"))
            return
        click.echo(ColoredFormatter.info(f"🎯 Target host: {host}"))
    if save_pcap:
        click.echo(ColoredFormatter.info(f"💾 Saving to: {save_pcap}"))
    if filter:
        click.echo(ColoredFormatter.info(f"🔍 Filter: {filter}"))
    
    try:
        monitor = NetworkMonitor()
        
        with click.progressbar(length=duration, label='Monitoring traffic') as bar:
            results = monitor.capture_traffic(
                interface=interface,
                duration=duration,
                protocol=protocol,
                port=port,
                host=host,
                save_pcap=save_pcap,
                filter_expr=filter
            )
            for i in range(duration):
                bar.update(1)
                # Simulate real-time monitoring
                import time
                time.sleep(1)
        
        if results:
            packet_count = results.get('packet_count', 0)
            click.echo(ColoredFormatter.success(f"✅ Captured {packet_count} packets"))
            
            # Show traffic summary
            if 'protocols' in results:
                click.echo(ColoredFormatter.header("\n📊 Protocol Distribution:"))
                for proto, count in results['protocols'].items():
                    click.echo(f"  {proto.upper()}: {count} packets")
            
            if 'top_hosts' in results:
                click.echo(ColoredFormatter.header("\n🎯 Top Communicating Hosts:"))
                for host_info in results['top_hosts'][:5]:
                    host_ip = host_info.get('ip', 'Unknown')
                    packet_count = host_info.get('packets', 0)
                    click.echo(f"  {host_ip}: {packet_count} packets")
            
            if output:
                save_results(results, output, format)
            else:
                display_results(results, format)
        else:
            click.echo(ColoredFormatter.warning("⚠️  No traffic captured"))
            
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ Traffic monitoring failed: {e}"))


@monitor.command()
@click.argument('target')
@click.option('--interval', '-i', type=int, default=30, help='Check interval in seconds')
@click.option('--duration', '-d', type=int, default=3600, help='Total monitoring duration in seconds')
@click.option('--services', '-s', help='Specific services to monitor (comma-separated)')
@click.option('--alert-threshold', type=int, default=5, help='Alert after N failed checks')
@click.option('--email-alerts', help='Email address for alerts')
@click.option('--webhook', help='Webhook URL for notifications')
@common_options
def uptime(target, interval, duration, services, alert_threshold, email_alerts, webhook, output, format, timeout, threads):
    """Monitor service uptime and availability
    
    Examples:
        cybernox monitor uptime example.com --interval 60 --duration 7200
        cybernox monitor uptime 192.168.1.1 --services "80,443,22" --alert-threshold 3
        cybernox monitor uptime website.com --email-alerts admin@company.com
        cybernox monitor uptime api.service.com --webhook http://alerts.company.com/hook
    """
    if not validate_target(target):
        click.echo(ColoredFormatter.error("❌ Invalid target format"))
        return
    
    click.echo(ColoredFormatter.info(f"⏰ Starting uptime monitoring for {target}"))
    click.echo(ColoredFormatter.info(f"🔄 Check interval: {interval} seconds"))
    click.echo(ColoredFormatter.info(f"⏱️  Total duration: {duration} seconds"))
    click.echo(ColoredFormatter.info(f"🚨 Alert threshold: {alert_threshold} failures"))
    
    if services:
        service_list = [s.strip() for s in services.split(',')]
        click.echo(ColoredFormatter.info(f"🔍 Monitoring services: {', '.join(service_list)}"))
    else:
        service_list = ['80', '443']  # Default HTTP/HTTPS
        click.echo(ColoredFormatter.info("🔍 Monitoring default services: HTTP, HTTPS"))
    
    if email_alerts:
        click.echo(ColoredFormatter.info(f"📧 Email alerts: {email_alerts}"))
    if webhook:
        click.echo(ColoredFormatter.info(f"🔗 Webhook alerts: {webhook}"))
    
    try:
        monitor = NetworkMonitor()
        checks_count = duration // interval
        
        with click.progressbar(length=checks_count, label='Monitoring uptime') as bar:
            results = monitor.monitor_uptime(
                target=target,
                interval=interval,
                duration=duration,
                services=service_list,
                alert_threshold=alert_threshold,
                email_alerts=email_alerts,
                webhook=webhook
            )
            bar.update(checks_count)
        
        if results:
            uptime_percent = results.get('uptime_percentage', 0)
            total_checks = results.get('total_checks', 0)
            failed_checks = results.get('failed_checks', 0)
            
            if uptime_percent >= 99:
                status_color = ColoredFormatter.success
            elif uptime_percent >= 95:
                status_color = ColoredFormatter.warning
            else:
                status_color = ColoredFormatter.error
            
            click.echo(status_color(f"📊 Uptime: {uptime_percent:.2f}%"))
            click.echo(ColoredFormatter.info(f"✅ Successful checks: {total_checks - failed_checks}/{total_checks}"))
            
            if failed_checks > 0:
                click.echo(ColoredFormatter.warning(f"❌ Failed checks: {failed_checks}"))
            
            if 'service_status' in results:
                click.echo(ColoredFormatter.header("\n🔍 Service Status:"))
                for service, status in results['service_status'].items():
                    status_icon = "✅" if status['available'] else "❌"
                    response_time = status.get('response_time', 'N/A')
                    click.echo(f"  {status_icon} Port {service}: {response_time}ms")
            
            if output:
                save_results(results, output, format)
            else:
                display_results(results, format)
        else:
            click.echo(ColoredFormatter.error("❌ No uptime data collected"))
            
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ Uptime monitoring failed: {e}"))


@monitor.command()
@click.argument('target')
@click.option('--threshold', type=float, default=100.0, help='Alert threshold in MB/s')
@click.option('--duration', '-d', type=int, default=300, help='Monitoring duration in seconds')
@click.option('--sample-rate', type=int, default=5, help='Sampling rate in seconds')
@click.option('--direction', type=click.Choice(['in', 'out', 'both']), default='both',
              help='Traffic direction to monitor')
@click.option('--graph', is_flag=True, help='Generate bandwidth usage graph')
@common_options
def bandwidth(target, threshold, duration, sample_rate, direction, graph, output, format, timeout, threads):
    """Monitor bandwidth usage and traffic patterns
    
    Examples:
        cybernox monitor bandwidth 192.168.1.1 --threshold 50.0 --duration 600
        cybernox monitor bandwidth eth0 --direction out --sample-rate 10
        cybernox monitor bandwidth wlan0 --graph --duration 1800
        cybernox monitor bandwidth 10.0.0.1 --threshold 25.5 --output bandwidth.json
    """
    click.echo(ColoredFormatter.info(f"📈 Starting bandwidth monitoring for {target}"))
    click.echo(ColoredFormatter.info(f"🚨 Alert threshold: {threshold} MB/s"))
    click.echo(ColoredFormatter.info(f"⏱️  Duration: {duration} seconds"))
    click.echo(ColoredFormatter.info(f"📊 Sample rate: {sample_rate} seconds"))
    click.echo(ColoredFormatter.info(f"🔄 Direction: {direction.upper()}"))
    
    if graph:
        click.echo(ColoredFormatter.info("📊 Graph generation enabled"))
    
    try:
        monitor = NetworkMonitor()
        samples = duration // sample_rate
        
        with click.progressbar(length=samples, label='Monitoring bandwidth') as bar:
            results = monitor.monitor_bandwidth(
                target=target,
                threshold=threshold,
                duration=duration,
                sample_rate=sample_rate,
                direction=direction,
                generate_graph=graph
            )
            bar.update(samples)
        
        if results:
            avg_bandwidth = results.get('average_bandwidth', 0)
            peak_bandwidth = results.get('peak_bandwidth', 0)
            total_data = results.get('total_data_mb', 0)
            alerts_count = results.get('alerts_triggered', 0)
            
            click.echo(ColoredFormatter.success(f"📊 Average bandwidth: {avg_bandwidth:.2f} MB/s"))
            click.echo(ColoredFormatter.info(f"🔝 Peak bandwidth: {peak_bandwidth:.2f} MB/s"))
            click.echo(ColoredFormatter.info(f"💾 Total data transferred: {total_data:.2f} MB"))
            
            if alerts_count > 0:
                click.echo(ColoredFormatter.warning(f"🚨 Threshold alerts: {alerts_count}"))
            else:
                click.echo(ColoredFormatter.success("✅ No threshold violations"))
            
            if 'usage_by_hour' in results:
                click.echo(ColoredFormatter.header("\n📈 Hourly Usage Pattern:"))
                for hour_data in results['usage_by_hour'][:5]:  # Show first 5 hours
                    hour = hour_data.get('hour', 'Unknown')
                    usage = hour_data.get('usage_mb', 0)
                    click.echo(f"  {hour}: {usage:.2f} MB")
            
            if graph and 'graph_file' in results:
                click.echo(ColoredFormatter.success(f"📊 Graph saved to: {results['graph_file']}"))
            
            if output:
                save_results(results, output, format)
            else:
                display_results(results, format)
        else:
            click.echo(ColoredFormatter.warning("⚠️  No bandwidth data collected"))
            
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ Bandwidth monitoring failed: {e}"))


@monitor.command()
@click.argument('log_file')
@click.option('--patterns', '-p', help='Patterns to watch for (comma-separated)')
@click.option('--ignore-case', is_flag=True, help='Case-insensitive pattern matching')
@click.option('--tail', '-t', is_flag=True, help='Follow log file in real-time (like tail -f)')
@click.option('--alerts', help='Alert patterns (comma-separated)')
@click.option('--email', help='Email address for critical alerts')
@click.option('--max-lines', type=int, default=1000, help='Maximum lines to process')
@common_options
def logs(log_file, patterns, ignore_case, tail, alerts, email, max_lines, output, format, timeout, threads):
    """Monitor and analyze log files for security events
    
    Examples:
        cybernox monitor logs /var/log/auth.log --patterns "failed,error,denied"
        cybernox monitor logs /var/log/nginx/access.log --tail --alerts "404,500"
        cybernox monitor logs /var/log/syslog --ignore-case --email admin@company.com
        cybernox monitor logs app.log --max-lines 5000 --output log_analysis.json
    """
    import os
    
    if not os.path.exists(log_file):
        click.echo(ColoredFormatter.error(f"❌ Log file not found: {log_file}"))
        return
    
    click.echo(ColoredFormatter.info(f"📄 Monitoring log file: {log_file}"))
    
    if patterns:
        pattern_list = [p.strip() for p in patterns.split(',')]
        click.echo(ColoredFormatter.info(f"🔍 Watching patterns: {', '.join(pattern_list)}"))
    else:
        pattern_list = ['error', 'failed', 'denied', 'unauthorized', 'attack']
        click.echo(ColoredFormatter.info("🔍 Using default security patterns"))
    
    if alerts:
        alert_list = [a.strip() for a in alerts.split(',')]
        click.echo(ColoredFormatter.info(f"🚨 Alert patterns: {', '.join(alert_list)}"))
    else:
        alert_list = []
    
    if ignore_case:
        click.echo(ColoredFormatter.info("🔤 Case-insensitive matching enabled"))
    if tail:
        click.echo(ColoredFormatter.info("👁️  Real-time monitoring enabled"))
    if email:
        click.echo(ColoredFormatter.info(f"📧 Alert email: {email}"))
    
    click.echo(ColoredFormatter.info(f"📊 Processing up to {max_lines} lines"))
    
    try:
        monitor = NetworkMonitor()
        
        with click.progressbar(length=max_lines, label='Analyzing logs') as bar:
            results = monitor.analyze_logs(
                log_file=log_file,
                patterns=pattern_list,
                ignore_case=ignore_case,
                follow_tail=tail,
                alert_patterns=alert_list,
                email_alerts=email,
                max_lines=max_lines
            )
            bar.update(max_lines)
        
        if results:
            total_matches = results.get('total_matches', 0)
            total_alerts = results.get('total_alerts', 0)
            lines_processed = results.get('lines_processed', 0)
            
            click.echo(ColoredFormatter.success(f"📊 Processed {lines_processed} lines"))
            click.echo(ColoredFormatter.info(f"🔍 Pattern matches: {total_matches}"))
            
            if total_alerts > 0:
                click.echo(ColoredFormatter.warning(f"🚨 Critical alerts: {total_alerts}"))
            else:
                click.echo(ColoredFormatter.success("✅ No critical alerts"))
            
            if 'pattern_matches' in results:
                click.echo(ColoredFormatter.header("\n🔍 Pattern Analysis:"))
                for pattern, count in results['pattern_matches'].items():
                    if count > 0:
                        click.echo(f"  {pattern}: {count} matches")
            
            if 'recent_events' in results:
                click.echo(ColoredFormatter.header("\n🕒 Recent Security Events:"))
                for event in results['recent_events'][:5]:  # Show last 5 events
                    timestamp = event.get('timestamp', 'Unknown')
                    message = event.get('message', 'No message')[:80] + '...'
                    click.echo(f"  {timestamp}: {message}")
            
            if output:
                save_results(results, output, format)
            else:
                display_results(results, format)
        else:
            click.echo(ColoredFormatter.warning("⚠️  No log data processed"))
            
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ Log monitoring failed: {e}"))
