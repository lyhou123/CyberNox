"""
Phishing and Social Engineering Commands
Email campaign management, phishing site creation, and awareness training
"""

import click
from core.phishing import PhishingDetector
from ..utils.formatter import ColoredFormatter, common_options, save_results, display_results, validate_target


@click.group()
def phishing():
    """🎣 Phishing and social engineering tools"""
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
    
    click.echo(ColoredFormatter.info(f"� Analyzing URL: {url}"))
    
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
                click.echo(ColoredFormatter.header(f"\n� Phishing Indicators ({len(indicators)} found):"))
                for indicator in indicators[:10]:  # Show first 10 indicators
                    indicator_type = indicator.get('type', 'Unknown')
                    description = indicator.get('description', 'No description')
                    severity = indicator.get('severity', 'medium')
                    
                    severity_icon = {
                        'high': '�',
                        'medium': '🟡',
                        'low': '🟢'
                    }.get(severity, '⚪')
                    
                    click.echo(f"  {severity_icon} {indicator_type}: {description}")
            
            if check_reputation and 'reputation' in results:
                rep_data = results['reputation']
                click.echo(ColoredFormatter.header("\n� Reputation Check:"))
                
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
@click.argument('email_type', type=click.Choice([
    'credential_harvest', 'malware_delivery', 'information_gathering',
    'survey', 'urgent_action', 'financial', 'technical_support', 'custom'
]))
@click.option('--sender-name', help='Sender display name')
@click.option('--sender-email', help='Sender email address')
@click.option('--subject', help='Email subject line')
@click.option('--target-company', help='Target company name for customization')
@click.option('--attachment', help='Path to attachment file')
@click.option('--link-url', help='Phishing link URL')
@click.option('--personalization', help='Personalization data file (CSV)')
@common_options
def email(email_type, sender_name, sender_email, subject, target_company, attachment, link_url, personalization, output, format, timeout, threads):
    """Generate phishing email templates
    
    Examples:
        cybernox phishing email credential_harvest --sender-name "IT Support"
        cybernox phishing email malware_delivery --attachment payload.pdf --link-url http://evil.com
        cybernox phishing email financial --target-company "Acme Corp" --subject "Urgent Payment Required"
        cybernox phishing email custom --personalization targets.csv --output emails.json
    """
    click.echo(ColoredFormatter.info(f"📧 Generating {email_type} phishing email"))
    
    if sender_name:
        click.echo(ColoredFormatter.info(f"👤 Sender name: {sender_name}"))
    if sender_email:
        click.echo(ColoredFormatter.info(f"📮 Sender email: {sender_email}"))
    if subject:
        click.echo(ColoredFormatter.info(f"📋 Subject: {subject}"))
    if target_company:
        click.echo(ColoredFormatter.info(f"🏢 Target company: {target_company}"))
    if attachment:
        click.echo(ColoredFormatter.info(f"📎 Attachment: {attachment}"))
    if link_url:
        click.echo(ColoredFormatter.info(f"🔗 Phishing URL: {link_url}"))
    if personalization:
        click.echo(ColoredFormatter.info(f"👥 Personalization file: {personalization}"))
    
    try:
        phishing_module = PhishingModule()
        
        with click.progressbar(length=3, label='Generating email template') as bar:
            # Generate base email template
            results = phishing_module.generate_email_template(
                email_type=email_type,
                sender_name=sender_name,
                sender_email=sender_email,
                subject=subject,
                target_company=target_company,
                attachment=attachment,
                link_url=link_url
            )
            bar.update(1)
            
            # Apply personalization if provided
            if personalization:
                personalized_results = phishing_module.apply_personalization(personalization)
                results.update(personalized_results)
                bar.update(1)
            else:
                bar.update(1)
            
            # Validate email format
            validation_results = phishing_module.validate_email_template()
            results.update(validation_results)
            bar.update(1)
        
        if results:
            click.echo(ColoredFormatter.success("✅ Phishing email template generated"))
            
            # Show email preview
            if 'email_content' in results:
                email_content = results['email_content']
                click.echo(ColoredFormatter.header("\n📧 Email Preview:"))
                click.echo(f"  From: {email_content.get('from', 'Not specified')}")
                click.echo(f"  Subject: {email_content.get('subject', 'Not specified')}")
                
                body_preview = email_content.get('body', '')[:200]
                if len(body_preview) == 200:
                    body_preview += "..."
                click.echo(f"  Body: {body_preview}")
            
            # Show personalization stats
            if personalization and 'personalization_stats' in results:
                stats = results['personalization_stats']
                targets_count = stats.get('targets_processed', 0)
                click.echo(ColoredFormatter.success(f"👥 Personalized for {targets_count} targets"))
            
            # Show validation results
            if 'validation' in results:
                validation = results['validation']
                if validation.get('spam_score', 0) < 5:
                    click.echo(ColoredFormatter.success("✅ Low spam score - likely to pass filters"))
                else:
                    click.echo(ColoredFormatter.warning("⚠️  High spam score - may be filtered"))
                
                if validation.get('link_safety', True):
                    click.echo(ColoredFormatter.success("✅ Links appear safe to scanners"))
                else:
                    click.echo(ColoredFormatter.warning("⚠️  Links may trigger security warnings"))
            
            if output:
                save_results(results, output, format)
            else:
                display_results(results, format)
        else:
            click.echo(ColoredFormatter.error("❌ Failed to generate email template"))
            
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ Email generation failed: {e}"))


@phishing.command()
@click.argument('target_list', type=click.Path(exists=True))
@click.option('--email-template', help='Path to email template file')
@click.option('--smtp-server', help='SMTP server for sending emails')
@click.option('--smtp-port', type=int, default=587, help='SMTP server port')
@click.option('--smtp-user', help='SMTP username')
@click.option('--smtp-pass', help='SMTP password')
@click.option('--delay', type=int, default=5, help='Delay between emails (seconds)')
@click.option('--test-mode', is_flag=True, help='Test mode - don\'t actually send emails')
@click.option('--track-opens', is_flag=True, help='Include email open tracking')
@click.option('--track-clicks', is_flag=True, help='Include link click tracking')
@common_options
def campaign(target_list, email_template, smtp_server, smtp_port, smtp_user, smtp_pass, delay, test_mode, track_opens, track_clicks, output, format, timeout, threads):
    """Launch phishing email campaigns
    
    Examples:
        cybernox phishing campaign targets.csv --email-template phish.html --test-mode
        cybernox phishing campaign employees.csv --smtp-server mail.company.com --delay 10
        cybernox phishing campaign contacts.csv --track-opens --track-clicks --output campaign.json
        cybernox phishing campaign list.csv --smtp-user sender@domain.com --smtp-pass secret123
    """
    import os
    
    if not os.path.exists(target_list):
        click.echo(ColoredFormatter.error(f"❌ Target list not found: {target_list}"))
        return
    
    click.echo(ColoredFormatter.info(f"🎯 Loading targets from: {target_list}"))
    
    if email_template:
        if not os.path.exists(email_template):
            click.echo(ColoredFormatter.error(f"❌ Email template not found: {email_template}"))
            return
        click.echo(ColoredFormatter.info(f"📧 Using template: {email_template}"))
    else:
        click.echo(ColoredFormatter.info("📧 Using default email template"))
    
    if test_mode:
        click.echo(ColoredFormatter.warning("🧪 TEST MODE - No emails will be sent"))
    else:
        if not smtp_server or not smtp_user:
            click.echo(ColoredFormatter.error("❌ SMTP server and user required for sending"))
            return
        click.echo(ColoredFormatter.info(f"📮 SMTP: {smtp_server}:{smtp_port}"))
        click.echo(ColoredFormatter.info(f"👤 User: {smtp_user}"))
    
    click.echo(ColoredFormatter.info(f"⏱️  Delay between emails: {delay} seconds"))
    
    if track_opens:
        click.echo(ColoredFormatter.info("📬 Email open tracking enabled"))
    if track_clicks:
        click.echo(ColoredFormatter.info("🖱️  Link click tracking enabled"))
    
    try:
        phishing_module = PhishingModule()
        
        # Load and validate targets
        with click.progressbar(length=1, label='Loading targets') as bar:
            targets = phishing_module.load_targets(target_list)
            bar.update(1)
        
        if not targets:
            click.echo(ColoredFormatter.error("❌ No valid targets found"))
            return
        
        target_count = len(targets)
        click.echo(ColoredFormatter.success(f"✅ Loaded {target_count} targets"))
        
        if test_mode:
            # Test mode - just validate everything
            with click.progressbar(length=target_count, label='Validating campaign') as bar:
                results = phishing_module.test_campaign(
                    targets=targets,
                    email_template=email_template,
                    track_opens=track_opens,
                    track_clicks=track_clicks
                )
                bar.update(target_count)
        else:
            # Actual campaign
            estimated_time = target_count * delay
            click.echo(ColoredFormatter.info(f"⏱️  Estimated completion: {estimated_time} seconds"))
            
            with click.progressbar(length=target_count, label='Sending emails') as bar:
                results = phishing_module.launch_campaign(
                    targets=targets,
                    email_template=email_template,
                    smtp_server=smtp_server,
                    smtp_port=smtp_port,
                    smtp_user=smtp_user,
                    smtp_pass=smtp_pass,
                    delay=delay,
                    track_opens=track_opens,
                    track_clicks=track_clicks
                )
                for i in range(target_count):
                    bar.update(1)
                    import time
                    time.sleep(0.1)  # Simulate progress
        
        if results:
            sent_count = results.get('emails_sent', 0)
            failed_count = results.get('emails_failed', 0)
            
            if test_mode:
                click.echo(ColoredFormatter.success(f"✅ Campaign validation complete"))
                click.echo(ColoredFormatter.info(f"📧 {target_count} emails would be sent"))
            else:
                click.echo(ColoredFormatter.success(f"✅ Campaign completed"))
                click.echo(ColoredFormatter.success(f"📧 Sent: {sent_count}"))
                if failed_count > 0:
                    click.echo(ColoredFormatter.warning(f"❌ Failed: {failed_count}"))
            
            if track_opens or track_clicks:
                tracking_url = results.get('tracking_url')
                if tracking_url:
                    click.echo(ColoredFormatter.info(f"📊 Tracking dashboard: {tracking_url}"))
            
            if 'campaign_id' in results:
                campaign_id = results['campaign_id']
                click.echo(ColoredFormatter.info(f"🆔 Campaign ID: {campaign_id}"))
            
            if output:
                save_results(results, output, format)
            else:
                display_results(results, format)
        else:
            click.echo(ColoredFormatter.error("❌ Campaign failed"))
            
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ Campaign failed: {e}"))


@phishing.command()
@click.argument('campaign_id')
@click.option('--refresh-rate', type=int, default=30, help='Auto-refresh rate in seconds')
@click.option('--export-data', help='Export results to file')
@click.option('--show-details', is_flag=True, help='Show detailed target information')
@common_options
def track(campaign_id, refresh_rate, export_data, show_details, output, format, timeout, threads):
    """Track phishing campaign results and statistics
    
    Examples:
        cybernox phishing track CAMP_123456 --refresh-rate 60
        cybernox phishing track CAMP_789012 --show-details --export-data results.csv
        cybernox phishing track CAMP_345678 --output tracking.json
    """
    click.echo(ColoredFormatter.info(f"📊 Tracking campaign: {campaign_id}"))
    click.echo(ColoredFormatter.info(f"🔄 Auto-refresh: {refresh_rate} seconds"))
    
    if show_details:
        click.echo(ColoredFormatter.info("📋 Detailed mode enabled"))
    if export_data:
        click.echo(ColoredFormatter.info(f"💾 Will export to: {export_data}"))
    
    try:
        phishing_module = PhishingModule()
        
        with click.progressbar(length=1, label='Loading campaign data') as bar:
            results = phishing_module.get_campaign_stats(
                campaign_id=campaign_id,
                include_details=show_details
            )
            bar.update(1)
        
        if results:
            stats = results.get('statistics', {})
            
            # Basic statistics
            emails_sent = stats.get('emails_sent', 0)
            emails_opened = stats.get('emails_opened', 0)
            links_clicked = stats.get('links_clicked', 0)
            credentials_captured = stats.get('credentials_captured', 0)
            
            open_rate = (emails_opened / emails_sent * 100) if emails_sent > 0 else 0
            click_rate = (links_clicked / emails_sent * 100) if emails_sent > 0 else 0
            capture_rate = (credentials_captured / emails_sent * 100) if emails_sent > 0 else 0
            
            click.echo(ColoredFormatter.header("\n📊 Campaign Statistics:"))
            click.echo(f"  📧 Emails sent: {emails_sent}")
            click.echo(f"  📬 Emails opened: {emails_opened} ({open_rate:.1f}%)")
            click.echo(f"  🖱️  Links clicked: {links_clicked} ({click_rate:.1f}%)")
            click.echo(f"  🎣 Credentials captured: {credentials_captured} ({capture_rate:.1f}%)")
            
            # Timeline data
            if 'timeline' in results:
                click.echo(ColoredFormatter.header("\n⏰ Recent Activity:"))
                for event in results['timeline'][:5]:  # Show last 5 events
                    timestamp = event.get('timestamp', 'Unknown')
                    event_type = event.get('type', 'Unknown')
                    target = event.get('target', 'Unknown')
                    click.echo(f"  {timestamp}: {event_type} - {target}")
            
            # Detailed target information
            if show_details and 'targets' in results:
                click.echo(ColoredFormatter.header("\n👥 Target Details:"))
                for target in results['targets'][:10]:  # Show first 10 targets
                    email = target.get('email', 'Unknown')
                    status = target.get('status', 'Unknown')
                    last_action = target.get('last_action', 'None')
                    
                    status_icon = {
                        'sent': '📧',
                        'opened': '📬',
                        'clicked': '🖱️',
                        'captured': '🎣'
                    }.get(status, '❓')
                    
                    click.echo(f"  {status_icon} {email}: {status} - {last_action}")
            
            # Export data if requested
            if export_data:
                export_result = phishing_module.export_campaign_data(campaign_id, export_data)
                if export_result:
                    click.echo(ColoredFormatter.success(f"💾 Data exported to: {export_data}"))
            
            if output:
                save_results(results, output, format)
            else:
                display_results(results, format)
        else:
            click.echo(ColoredFormatter.error(f"❌ Campaign {campaign_id} not found"))
            
    except Exception as e:
        click.echo(ColoredFormatter.error(f"❌ Tracking failed: {e}"))
