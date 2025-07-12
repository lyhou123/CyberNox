"""
Phishing Analysis Commands
URL analysis and phishing detection tools
"""

import click
from core.phishing import PhishingDetector
from ..utils.formatter import ColoredFormatter, common_options, save_results, display_results, validate_target


@click.group()
def phishing():
    """🎣 Phishing analysis and detection tools"""
    pass


@phishing.command()
@click.argument('url')
@click.option('--detailed', is_flag=True, help='Show detailed analysis')
@click.option('--check-reputation', is_flag=True, help='Check URL reputation')
@common_options
def analyze(url, detailed, check_reputation, output, format, timeout, threads):
    """Analyze URL for phishing indicators
    
    Examples:
        cybernox phishing analyze http://suspicious-site.com
        cybernox phishing analyze https://fake-bank.net --detailed
        cybernox phishing analyze http://phishing-site.org --check-reputation
        cybernox phishing analyze https://malicious.com --output analysis.json
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    click.echo(ColoredFormatter.info(f"🔍 Analyzing URL: {url}"))
    
    try:
        phishing_detector = PhishingDetector()
        
        with click.progressbar(length=2, label='Analyzing URL') as bar:
            # Main analysis
            results = phishing_detector.analyze_url(url)
            bar.update(1)
            
            # Reputation check if requested
            if check_reputation:
                reputation_results = phishing_detector.check_reputation(url)
                results.update({'reputation': reputation_results})
            bar.update(1)
        
        if results:
            risk_score = results.get('risk_score', 0)
            indicators = results.get('indicators', [])
            
            # Determine risk level
            if risk_score >= 70:
                risk_level = ColoredFormatter.error("🚨 HIGH RISK")
            elif risk_score >= 40:
                risk_level = ColoredFormatter.warning("⚠️  MEDIUM RISK")
            else:
                risk_level = ColoredFormatter.success("✅ LOW RISK")
            
            click.echo(ColoredFormatter.success(f"✅ Analysis completed"))
            click.echo(f"🎯 Risk Level: {risk_level}")
            click.echo(f"📊 Risk Score: {risk_score}/100")
            
            if indicators:
                click.echo(ColoredFormatter.header(f"\n🚩 Phishing Indicators ({len(indicators)} found):"))
                for indicator in indicators[:10]:  # Show first 10 indicators
                    indicator_type = indicator.get('type', 'Unknown')
                    description = indicator.get('description', 'No description')
                    severity = indicator.get('severity', 'medium')
                    
                    severity_icon = {
                        'high': '🔴',
                        'medium': '🟡',
                        'low': '🟢'
                    }.get(severity, '⚪')
                    
                    click.echo(f"  {severity_icon} {indicator_type}: {description}")
            
            if check_reputation and 'reputation' in results:
                rep_data = results['reputation']
                click.echo(ColoredFormatter.header("\n🔍 Reputation Check:"))
                
                if rep_data.get('is_malicious'):
                    click.echo(ColoredFormatter.error("❌ URL flagged as malicious"))
                else:
                    click.echo(ColoredFormatter.success("✅ URL appears clean"))
                
                if 'sources' in rep_data:
                    sources = rep_data['sources']
                    click.echo(f"📋 Checked against {len(sources)} reputation sources")
            
            if output:
                save_results(results, output, format)
            else:
                if detailed:
                    display_results(results, format)
        else:
            click.echo(ColoredFormatter.error("❌ Analysis failed"))
            
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ URL analysis failed: {e}"))


@phishing.command()
@click.argument('url_list', type=click.Path(exists=True))
@click.option('--batch-size', type=int, default=10, help='Number of URLs to process simultaneously')
@click.option('--delay', type=int, default=1, help='Delay between requests in seconds')
@click.option('--min-risk', type=int, default=0, help='Minimum risk score to report')
@common_options
def batch(url_list, batch_size, delay, min_risk, output, format, timeout, threads):
    """Analyze multiple URLs from a file for phishing indicators
    
    Examples:
        cybernox phishing batch urls.txt --batch-size 5
        cybernox phishing batch suspicious_urls.txt --min-risk 50
        cybernox phishing batch url_list.txt --delay 2 --output batch_results.json
    """
    import os
    
    if not os.path.exists(url_list):
        click.echo(ColoredFormatter.error(f"❌ URL list file not found: {url_list}"))
        return
    
    click.echo(ColoredFormatter.info(f"📄 Loading URLs from: {url_list}"))
    
    try:
        # Read URLs from file
        with open(url_list, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        if not urls:
            click.echo(ColoredFormatter.error("❌ No valid URLs found in file"))
            return
        
        click.echo(ColoredFormatter.success(f"✅ Loaded {len(urls)} URLs"))
        click.echo(ColoredFormatter.info(f"🔄 Batch size: {batch_size}"))
        click.echo(ColoredFormatter.info(f"⏱️  Delay: {delay} seconds"))
        click.echo(ColoredFormatter.info(f"🎯 Minimum risk score: {min_risk}"))
        
        phishing_detector = PhishingDetector()
        results = []
        
        with click.progressbar(length=len(urls), label='Analyzing URLs') as bar:
            for i, url in enumerate(urls):
                try:
                    if not url.startswith(('http://', 'https://')):
                        url = 'https://' + url
                    
                    # Analyze URL
                    analysis = phishing_detector.analyze_url(url)
                    analysis['original_url'] = urls[i]
                    
                    # Only include if meets minimum risk threshold
                    risk_score = analysis.get('risk_score', 0)
                    if risk_score >= min_risk:
                        results.append(analysis)
                    
                    bar.update(1)
                    
                    # Add delay between requests
                    if delay > 0 and i < len(urls) - 1:
                        import time
                        time.sleep(delay)
                        
                except Exception as e:
                    click.echo(ColoredFormatter.warning(f"⚠️  Failed to analyze {url}: {e}"))
                    bar.update(1)
        
        if results:
            # Sort by risk score (highest first)
            results.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
            
            high_risk = len([r for r in results if r.get('risk_score', 0) >= 70])
            medium_risk = len([r for r in results if 40 <= r.get('risk_score', 0) < 70])
            low_risk = len([r for r in results if r.get('risk_score', 0) < 40])
            
            click.echo(ColoredFormatter.success(f"✅ Batch analysis completed"))
            click.echo(ColoredFormatter.info(f"📊 Results: {len(results)} URLs above threshold"))
            click.echo(ColoredFormatter.error(f"🚨 High risk: {high_risk}"))
            click.echo(ColoredFormatter.warning(f"⚠️  Medium risk: {medium_risk}"))
            click.echo(ColoredFormatter.success(f"✅ Low risk: {low_risk}"))
            
            # Show top 5 highest risk URLs
            if results:
                click.echo(ColoredFormatter.header("\n🎯 Top Risk URLs:"))
                for result in results[:5]:
                    url = result.get('original_url', 'Unknown')
                    risk_score = result.get('risk_score', 0)
                    indicators_count = len(result.get('indicators', []))
                    
                    if risk_score >= 70:
                        risk_icon = "🚨"
                    elif risk_score >= 40:
                        risk_icon = "⚠️"
                    else:
                        risk_icon = "✅"
                    
                    click.echo(f"  {risk_icon} {url} - Risk: {risk_score}/100 ({indicators_count} indicators)")
            
            batch_results = {
                'total_analyzed': len(urls),
                'results_count': len(results),
                'high_risk_count': high_risk,
                'medium_risk_count': medium_risk,
                'low_risk_count': low_risk,
                'detailed_results': results
            }
            
            if output:
                save_results(batch_results, output, format)
            else:
                display_results(batch_results, format)
        else:
            click.echo(ColoredFormatter.info("📊 No URLs met the minimum risk threshold"))
            
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ Batch analysis failed: {e}"))


@phishing.command()
def info():
    """Show information about phishing detection capabilities"""
    
    click.echo(ColoredFormatter.header("🎣 CyberNox Phishing Detection"))
    click.echo(ColoredFormatter.info("""
The phishing module analyzes URLs for common phishing indicators including:

🔍 Analysis Features:
  • Domain analysis (suspicious TLDs, typosquatting)
  • URL structure analysis (suspicious patterns, encoding)
  • Page content analysis (forms, scripts, redirects)
  • Reputation checking (against known blacklists)
  • Risk scoring (0-100 scale)

🚩 Detection Indicators:
  • Suspicious domain names
  • URL shorteners and redirects
  • Homograph attacks
  • SSL certificate issues
  • Suspicious page content
  • Known malicious patterns

📊 Risk Levels:
  • 🚨 High Risk (70-100): Likely phishing
  • ⚠️  Medium Risk (40-69): Suspicious
  • ✅ Low Risk (0-39): Appears legitimate

💡 Usage Tips:
  • Use 'analyze' for single URL investigation
  • Use 'batch' for processing multiple URLs
  • Check reputation for additional verification
  • Save results for further analysis
    """))
    
    click.echo(ColoredFormatter.success("For help with specific commands, use: cybernox phishing [COMMAND] --help"))
