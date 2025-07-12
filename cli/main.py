"""
CyberNox CLI - Main Command Line Interface
Professional modular CLI for the CyberNox cybersecurity toolkit
"""

import click
from .utils.formatter import ColoredFormatter
from .commands.recon import recon
from .commands.scan import scan
from .commands.vuln import vuln
from .commands.exploit import exploit
from .commands.monitor import monitor
from .commands.phishing import phishing


def print_banner():
    """Display the CyberNox banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                          CyberNox                             ║
    ║                 Advanced Cybersecurity Toolkit               ║
    ║                                                               ║
    ║  🔍 Reconnaissance  🔒 Vulnerability Assessment               ║
    ║  🛡️  Network Security  🎯 Penetration Testing                ║
    ║  📡 Monitoring  🎣 Social Engineering                         ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(ColoredFormatter.header(banner))


def print_help_footer():
    """Display helpful information footer"""
    footer = """
Examples:
  cybernox recon whois example.com
  cybernox scan ports 192.168.1.1
  cybernox vuln web https://target.com
  cybernox exploit shell bash 10.0.0.1 4444
  cybernox monitor traffic --interface eth0
  cybernox phishing site gmail --domain fake-site.com

For detailed help on any command, use: cybernox [COMMAND] --help
Report issues: https://github.com/cybernox/cybernox/issues
    """
    click.echo(ColoredFormatter.info(footer))


@click.group(invoke_without_command=True)
@click.option('--version', is_flag=True, help='Show version information')
@click.option('--banner/--no-banner', default=True, help='Show/hide banner')
@click.pass_context
def cli(ctx, version, banner):
    """
    🛡️ CyberNox - Advanced Cybersecurity Toolkit
    
    A comprehensive suite of cybersecurity tools for penetration testing,
    vulnerability assessment, network monitoring, and security research.
    """
    # Show banner unless explicitly disabled
    if banner and not version:
        print_banner()
    
    # Show version information
    if version:
        click.echo(ColoredFormatter.success("CyberNox v2.0.0"))
        click.echo(ColoredFormatter.info("Professional Cybersecurity Toolkit"))
        click.echo(ColoredFormatter.info("Copyright (c) 2025 Lyhou Phiv"))
        return
    
    # If no command provided, show help
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        print_help_footer()


# Register command groups
cli.add_command(recon)
cli.add_command(scan)
cli.add_command(vuln)
cli.add_command(exploit)
cli.add_command(monitor)
cli.add_command(phishing)


@cli.command()
@click.option('--category', type=click.Choice(['recon', 'scan', 'vuln', 'exploit', 'monitor', 'phishing']),
              help='Show examples for specific category')
def examples(category):
    """Show usage examples for CyberNox commands"""
    
    examples_data = {
        'recon': [
            "cybernox recon whois example.com",
            "cybernox recon subdomains target.com --wordlist custom.txt",
            "cybernox recon dns example.com --record-type ALL",
            "cybernox recon osint john.doe --platform linkedin",
        ],
        'scan': [
            "cybernox scan ports 192.168.1.1 --range 1-1000",
            "cybernox scan network 10.0.0.0/24 --discover",
            "cybernox scan services 192.168.1.100 --ports 80,443,22",
            "cybernox scan comprehensive target.com --stealth",
        ],
        'vuln': [
            "cybernox vuln web https://example.com --check sqli,xss",
            "cybernox vuln network 192.168.1.0/24 --severity high",
            "cybernox vuln database mysql://user:pass@host/db",
            "cybernox vuln assess target.com --framework owasp",
        ],
        'exploit': [
            "cybernox exploit shell bash 192.168.1.100 4444",
            "cybernox exploit brute https://target.com --extensions php,asp",
            "cybernox exploit payload meterpreter --lhost 10.0.0.1 --lport 9999",
        ],
        'monitor': [
            "cybernox monitor traffic --interface eth0 --duration 300",
            "cybernox monitor uptime example.com --interval 60",
            "cybernox monitor bandwidth 192.168.1.1 --threshold 50.0",
            "cybernox monitor logs /var/log/auth.log --patterns failed,denied",
        ],
        'phishing': [
            "cybernox phishing site gmail --domain fake-gmail.com",
            "cybernox phishing email credential_harvest --sender-name 'IT Support'",
            "cybernox phishing campaign targets.csv --test-mode",
            "cybernox phishing track CAMP_123456 --show-details",
        ]
    }
    
    if category:
        if category in examples_data:
            click.echo(ColoredFormatter.header(f"\n📚 {category.upper()} Examples:"))
            for example in examples_data[category]:
                click.echo(f"  {ColoredFormatter.success(example)}")
        else:
            click.echo(ColoredFormatter.error(f"❌ Unknown category: {category}"))
    else:
        click.echo(ColoredFormatter.header("📚 CyberNox Command Examples"))
        for cat, examples_list in examples_data.items():
            click.echo(ColoredFormatter.info(f"\n🔹 {cat.upper()}:"))
            for example in examples_list[:2]:  # Show first 2 examples per category
                click.echo(f"  {example}")
        
        click.echo(ColoredFormatter.info(f"\nFor more examples in a specific category, use:"))
        click.echo(ColoredFormatter.success("  cybernox examples --category [recon|scan|vuln|exploit|monitor|phishing]"))


@cli.command()
def health():
    """Check system health and dependencies"""
    click.echo(ColoredFormatter.info("🏥 Checking CyberNox system health..."))
    
    health_results = {
        'core_modules': True,
        'dependencies': True,
        'permissions': True,
        'network': True
    }
    
    # Check core modules
    try:
        from core import recon, scanner, vulnscan, exploit, monitor, phishing
        click.echo(ColoredFormatter.success("✅ Core modules loaded successfully"))
    except ImportError as e:
        click.echo(ColoredFormatter.error(f"❌ Core module import failed: {e}"))
        health_results['core_modules'] = False
    
    # Check key dependencies
    dependencies = ['requests', 'nmap', 'dnspython', 'beautifulsoup4', 'click']
    missing_deps = []
    
    for dep in dependencies:
        try:
            __import__(dep)
            click.echo(ColoredFormatter.success(f"✅ {dep} available"))
        except ImportError:
            click.echo(ColoredFormatter.error(f"❌ {dep} missing"))
            missing_deps.append(dep)
            health_results['dependencies'] = False
    
    # Check network connectivity
    try:
        import requests
        response = requests.get('https://httpbin.org/ip', timeout=5)
        if response.status_code == 200:
            click.echo(ColoredFormatter.success("✅ Network connectivity OK"))
        else:
            click.echo(ColoredFormatter.warning("⚠️  Network connectivity issues"))
            health_results['network'] = False
    except Exception:
        click.echo(ColoredFormatter.error("❌ Network connectivity failed"))
        health_results['network'] = False
    
    # Overall health status
    all_healthy = all(health_results.values())
    if all_healthy:
        click.echo(ColoredFormatter.success("\n🎉 CyberNox is healthy and ready to use!"))
    else:
        click.echo(ColoredFormatter.warning("\n⚠️  CyberNox has some health issues"))
        if missing_deps:
            click.echo(ColoredFormatter.info(f"Install missing dependencies: pip install {' '.join(missing_deps)}"))


@cli.command()
@click.option('--config-file', default='config.yml', help='Configuration file path')
def config(config_file):
    """Show current configuration and settings"""
    import os
    
    click.echo(ColoredFormatter.info(f"⚙️  CyberNox Configuration"))
    click.echo(ColoredFormatter.info(f"📄 Config file: {config_file}"))
    
    if os.path.exists(config_file):
        click.echo(ColoredFormatter.success("✅ Configuration file found"))
        
        try:
            import yaml
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f)
            
            if config_data:
                click.echo(ColoredFormatter.header("\n📋 Current Settings:"))
                for section, settings in config_data.items():
                    click.echo(ColoredFormatter.info(f"\n[{section}]"))
                    if isinstance(settings, dict):
                        for key, value in settings.items():
                            # Hide sensitive values
                            if any(sensitive in key.lower() for sensitive in ['password', 'key', 'secret', 'token']):
                                value = '*' * len(str(value)) if value else 'Not set'
                            click.echo(f"  {key}: {value}")
                    else:
                        click.echo(f"  {settings}")
            else:
                click.echo(ColoredFormatter.warning("⚠️  Configuration file is empty"))
                
        except Exception as e:
            click.echo(ColoredFormatter.error(f"❌ Failed to read configuration: {e}"))
    else:
        click.echo(ColoredFormatter.warning("⚠️  Configuration file not found"))
        click.echo(ColoredFormatter.info("Creating default configuration..."))
        
        # Create default config
        default_config = {
            'general': {
                'timeout': 30,
                'threads': 10,
                'output_format': 'json'
            },
            'scanning': {
                'default_ports': '22,80,443,8080,8443',
                'max_threads': 50
            },
            'reporting': {
                'save_results': True,
                'output_directory': './results'
            }
        }
        
        try:
            import yaml
            with open(config_file, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
            click.echo(ColoredFormatter.success(f"✅ Default configuration created: {config_file}"))
        except Exception as e:
            click.echo(ColoredFormatter.error(f"❌ Failed to create configuration: {e}"))


if __name__ == '__main__':
    cli()
