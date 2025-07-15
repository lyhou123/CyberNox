"""
Phishing detection and analysis module for CyberNox
"""

import requests
import re
from urllib.parse import urlparse, urljoin
from utils.logger import logger
from utils.config import config

class PhishingDetector:
    """Phishing detection and URL analysis"""
    
    def __init__(self):
        self.user_agent = config.get('network.user_agent', 'CyberNox-Scanner/1.0')
        self.timeout = config.get('general.timeout', 5)
    
    def analyze_url(self, url):
        """Analyze URL for phishing indicators"""
        logger.info(f"Analyzing URL for phishing indicators: {url}")
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        indicators = []
        risk_score = 0
        
        # Parse URL
        parsed = urlparse(url)
        
        # Check domain characteristics
        domain_indicators = self._analyze_domain(parsed.netloc)
        indicators.extend(domain_indicators)
        risk_score += len(domain_indicators) * 10
        
        # Check URL structure
        url_indicators = self._analyze_url_structure(url)
        indicators.extend(url_indicators)
        risk_score += len(url_indicators) * 5
        
        # Check page content
        content_indicators = self._analyze_page_content(url)
        indicators.extend(content_indicators)
        risk_score += len(content_indicators) * 15
        
        # Determine risk level
        if risk_score >= 50:
            risk_level = "High"
        elif risk_score >= 25:
            risk_level = "Medium"
        elif risk_score >= 10:
            risk_level = "Low"
        else:
            risk_level = "Minimal"
        
        return {
            "url": url,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "indicators": indicators,
            "domain": parsed.netloc
        }
    
    def _analyze_domain(self, domain):
        """Analyze domain for suspicious characteristics"""
        indicators = []
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.link', '.work']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                indicators.append(f"Suspicious TLD: {tld}")
        
        # Check for excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            indicators.append(f"Excessive subdomains: {subdomain_count}")
        
        # Check for suspicious characters
        suspicious_chars = ['-', '_']
        for char in suspicious_chars:
            if domain.count(char) > 2:
                indicators.append(f"Excessive use of '{char}' in domain")
        
        # Check for digit sequences
        if re.search(r'\d{3,}', domain):
            indicators.append("Long digit sequence in domain")
        
        # Check for common brand impersonation patterns
        brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'twitter', 'instagram']
        for brand in brands:
            if brand in domain.lower() and not domain.lower().endswith(f'{brand}.com'):
                indicators.append(f"Potential {brand} impersonation")
       
        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link', 'ow.ly']
        if domain.lower() in shorteners:
            indicators.append("URL shortener detected")
        
        return indicators
    
    def _analyze_url_structure(self, url):
        """Analyze URL structure for suspicious patterns"""
        indicators = []
        
        # Check URL length
        if len(url) > 100:
            indicators.append(f"Unusually long URL: {len(url)} characters")
        
        # Check for excessive parameters
        param_count = url.count('&')
        if param_count > 5:
            indicators.append(f"Excessive URL parameters: {param_count}")
        
        # Check for suspicious keywords in URL
        suspicious_keywords = ['login', 'verify', 'secure', 'update', 'confirm', 'suspend', 'urgent']
        for keyword in suspicious_keywords:
            if keyword in url.lower():
                indicators.append(f"Suspicious keyword in URL: {keyword}")
        
        # Check for IP address instead of domain
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        if re.search(ip_pattern, url):
            indicators.append("IP address used instead of domain name")
        
        # Check for multiple redirections (basic)
        if url.count('redirect') > 0 or url.count('goto') > 0:
            indicators.append("Potential redirect mechanism")
        
        return indicators
    
    def _analyze_page_content(self, url):
        """Analyze page content for phishing indicators"""
        indicators = []
        
        try:
            headers = {'User-Agent': self.user_agent}
            response = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
            content = response.text.lower()
            
            # Check for suspicious keywords in content
            phishing_keywords = [
                'verify your account', 'suspended account', 'click here immediately',
                'confirm your identity', 'update payment', 'urgent action required',
                'limited time offer', 'act now', 'verify within 24 hours',
                'account will be closed', 'unauthorized access', 'security alert'
            ]
            
            for keyword in phishing_keywords:
                if keyword in content:
                    indicators.append(f"Phishing keyword detected: {keyword}")
            
            # Check for forms requesting sensitive information
            if '<form' in content:
                form_indicators = []
                if 'password' in content:
                    form_indicators.append('password')
                if 'credit card' in content or 'creditcard' in content:
                    form_indicators.append('credit card')
                if 'social security' in content or 'ssn' in content:
                    form_indicators.append('SSN')
                if 'bank account' in content:
                    form_indicators.append('bank account')
                
                if form_indicators:
                    indicators.append(f"Form requesting sensitive data: {', '.join(form_indicators)}")
            
            # Check for fake SSL indicators
            if 'secure' in content and response.url.startswith('http://'):
                indicators.append("Claims to be secure but uses HTTP")
            
            # Check for external resources from suspicious domains
            external_links = re.findall(r'href=["\']([^"\']+)["\']', content)
            external_domains = set()
            for link in external_links:
                if link.startswith('http'):
                    domain = urlparse(link).netloc
                    if domain and domain != urlparse(url).netloc:
                        external_domains.add(domain)
            
            if len(external_domains) > 10:
                indicators.append(f"Many external domains referenced: {len(external_domains)}")
            
            # Check for JavaScript obfuscation
            if 'eval(' in content or 'unescape(' in content:
                indicators.append("Potentially obfuscated JavaScript")
            
        except Exception as e:
            logger.debug(f"Content analysis failed for {url}: {e}")
            indicators.append("Unable to analyze page content")
        
        return indicators
    
    def check_reputation(self, url):
        """Check URL reputation using basic heuristics"""
        logger.info(f"Checking reputation for: {url}")
        
        # This is a basic implementation
        # In a real-world scenario, you would integrate with reputation services
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        reputation = {
            "domain": domain,
            "reputation": "Unknown",
            "blacklisted": False,
            "categories": [],
            "last_seen": None
        }
        
        # Basic checks
        suspicious_indicators = self.analyze_url(url)
        
        if suspicious_indicators["risk_level"] == "High":
            reputation["reputation"] = "Malicious"
            reputation["blacklisted"] = True
            reputation["categories"] = ["Phishing", "Malware"]
        elif suspicious_indicators["risk_level"] == "Medium":
            reputation["reputation"] = "Suspicious"
            reputation["categories"] = ["Potentially Unwanted"]
        else:
            reputation["reputation"] = "Clean"
        
        return reputation
