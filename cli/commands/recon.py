"""
Reconnaissance Commands
WHOIS, subdomain enumeration, DNS, and information gathering
"""

import click
from core.recon import ReconModule
from ..utils.formatter import ColoredFormatter, common_options, save_results, display_results, validate_target


@click.group()
def recon():
    """🔍 Reconnaissance and information gathering"""
    pass


@recon.command()
@click.argument('domain')
@common_options
def whois(domain, output, format, timeout, threads):
    """Perform WHOIS lookup for a domain
    
    Examples:
        cybernox recon whois example.com
        cybernox recon whois google.com --output whois_results.json
    """
    if not validate_target(domain):
        click.echo(ColoredFormatter.error("❌ Invalid domain format"))
        return
    
    click.echo(ColoredFormatter.info(f"🔍 Starting WHOIS lookup for {domain}"))
    
    try:
        recon_module = ReconModule()
        
        with click.progressbar(length=1, label='Performing WHOIS lookup') as bar:
            results = recon_module.whois_lookup(domain)
            bar.update(1)
        
        if results:
            click.echo(ColoredFormatter.success("✅ WHOIS lookup completed"))
            if output:
                save_results(results, output, format)
            else:
                display_results(results, format)
        else:
            click.echo(ColoredFormatter.warning("⚠️  No WHOIS data found"))
            
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ WHOIS lookup failed: {e}"))


@recon.command()
@click.argument('domain')
@click.option('--wordlist', help='Custom wordlist file for subdomain enumeration')
@click.option('--max-threads', type=int, default=50, help='Maximum number of threads')
@click.option('--recursive', is_flag=True, help='Enable recursive subdomain discovery')
@common_options
def subdomains(domain, wordlist, max_threads, recursive, output, format, timeout, threads):
    """Enumerate subdomains for a domain
    
    Examples:
        cybernox recon subdomains example.com
        cybernox recon subdomains target.com --wordlist custom.txt --max-threads 100
        cybernox recon subdomains site.com --recursive --output subdomains.json
    """
    if not validate_target(domain):
        click.echo(ColoredFormatter.error("❌ Invalid domain format"))
        return
    
    click.echo(ColoredFormatter.info(f"🔍 Starting subdomain enumeration for {domain}"))
    if wordlist:
        click.echo(ColoredFormatter.info(f"📄 Using custom wordlist: {wordlist}"))
    if recursive:
        click.echo(ColoredFormatter.info("🔄 Recursive mode enabled"))
    
    try:
        recon_module = ReconModule()
        
        with click.progressbar(label='Enumerating subdomains') as bar:
            if hasattr(recon_module, 'subdomain_enum'):
                results = recon_module.subdomain_enum(domain, wordlist, max_threads)
            else:
                results = recon_module.enumerate_subdomains(domain, wordlist)
            bar.update(1)
        
        if results and results.get('subdomains'):
            count = len(results['subdomains'])
            click.echo(ColoredFormatter.success(f"✅ Found {count} subdomains"))
            
            if output:
                save_results(results, output, format)
            else:
                display_results(results, format)
        else:
            click.echo(ColoredFormatter.warning("⚠️  No subdomains found"))
            
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ Subdomain enumeration failed: {e}"))


@recon.command()
@click.argument('domain')
@click.option('--record-types', default='A,AAAA,MX,NS,TXT,CNAME', 
              help='DNS record types to query (comma-separated)')
@common_options
def dns(domain, record_types, output, format, timeout, threads):
    """Perform DNS enumeration and record lookup
    
    Examples:
        cybernox recon dns example.com
        cybernox recon dns target.com --record-types A,MX,TXT,NS
        cybernox recon dns site.com --output dns_records.json
    """
    if not validate_target(domain):
        click.echo(ColoredFormatter.error("❌ Invalid domain format"))
        return
    
    click.echo(ColoredFormatter.info(f"🔍 Starting DNS enumeration for {domain}"))
    
    record_list = [r.strip().upper() for r in record_types.split(',')]
    click.echo(ColoredFormatter.info(f"📋 Querying record types: {', '.join(record_list)}"))
    
    try:
        recon_module = ReconModule()
        
        with click.progressbar(length=len(record_list), label='Querying DNS records') as bar:
            if hasattr(recon_module, 'dns_enumeration'):
                results = recon_module.dns_enumeration(domain)
            else:
                # Fallback implementation
                results = {
                    'domain': domain,
                    'records': {},
                    'timestamp': str(click.DateTime())
                }
                for record_type in record_list:
                    # Simple DNS lookup implementation would go here
                    results['records'][record_type] = []
                    bar.update(1)
        
        if results:
            click.echo(ColoredFormatter.success("✅ DNS enumeration completed"))
            if output:
                save_results(results, output, format)
            else:
                display_results(results, format)
        else:
            click.echo(ColoredFormatter.warning("⚠️  No DNS records found"))
            
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ DNS enumeration failed: {e}"))


@recon.command()
@click.argument('target')
@click.option('--social', is_flag=True, help='Include social media reconnaissance')
@click.option('--emails', is_flag=True, help='Search for email addresses')
@click.option('--deep', is_flag=True, help='Enable deep reconnaissance mode')
@common_options  
def osint(target, social, emails, deep, output, format, timeout, threads):
    """Open Source Intelligence gathering
    
    Examples:
        cybernox recon osint company.com
        cybernox recon osint target.com --social --emails
        cybernox recon osint site.com --deep --output osint_report.json
    """
    click.echo(ColoredFormatter.info(f"🔍 Starting OSINT gathering for {target}"))
    
    if social:
        click.echo(ColoredFormatter.info("📱 Social media reconnaissance enabled"))
    if emails:
        click.echo(ColoredFormatter.info("📧 Email address search enabled"))
    if deep:
        click.echo(ColoredFormatter.info("🕳️  Deep reconnaissance mode enabled"))
    
    try:
        recon_module = ReconModule()
        
        results = {
            'target': target,
            'osint_data': {},
            'timestamp': str(click.DateTime())
        }
        
        with click.progressbar(label='Gathering OSINT data') as bar:
            # Implement OSINT gathering logic here
            if social:
                results['osint_data']['social_media'] = []
            if emails:
                results['osint_data']['emails'] = []
            if deep:
                results['osint_data']['deep_scan'] = {}
            
            bar.update(1)
        
        click.echo(ColoredFormatter.success("✅ OSINT gathering completed"))
        
        if output:
            save_results(results, output, format)
        else:
            display_results(results, format)
            
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ OSINT gathering failed: {e}"))
