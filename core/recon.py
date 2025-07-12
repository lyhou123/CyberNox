"""
Reconnaissance module for CyberNox
"""

import socket
import requests
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from utils.logger import logger
from utils.config import config
from utils.nettools import NetworkUtils

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    logger.warning("python-whois not available, WHOIS functionality disabled")

class ReconModule:
    """Reconnaissance and information gathering"""
    
    def __init__(self):
        self.timeout = config.get('network.socket_timeout', 3)
        self.max_threads = config.get('general.max_threads', 10)
        self.user_agent = config.get('network.user_agent', 'CyberNox-Scanner/1.0')
    
    def whois_lookup(self, domain):
        """Perform WHOIS lookup for domain"""
        if not WHOIS_AVAILABLE:
            return {"error": "python-whois library not available"}
        
        try:
            logger.info(f"Performing WHOIS lookup for {domain}")
            w = whois.whois(domain)
            
            result = {
                "domain": domain,
                "registrar": getattr(w, 'registrar', 'Unknown'),
                "creation_date": str(getattr(w, 'creation_date', 'Unknown')),
                "expiration_date": str(getattr(w, 'expiration_date', 'Unknown')),
                "name_servers": getattr(w, 'name_servers', []),
                "status": getattr(w, 'status', 'Unknown'),
                "emails": getattr(w, 'emails', []),
                "org": getattr(w, 'org', 'Unknown')
            }
            
            logger.info(f"WHOIS lookup completed for {domain}")
            return result
            
        except Exception as e:
            error_msg = f"WHOIS lookup failed for {domain}: {e}"
            logger.error(error_msg)
            return {"error": error_msg}
    
    def subdomain_enum(self, domain, wordlist_file=None, max_threads=50):
        """Enumerate subdomains using wordlist"""
        if not wordlist_file:
            wordlist_file = config.get_wordlist_path("subdomains.txt")
        
        if not Path(wordlist_file).exists():
            error_msg = f"Wordlist file not found: {wordlist_file}"
            logger.error(error_msg)
            return {"error": error_msg}
        
        logger.info(f"Starting subdomain enumeration for {domain}")
        found_subdomains = []
        
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            
            def check_subdomain(subdomain):
                full_domain = f"{subdomain}.{domain}"
                try:
                    ip = NetworkUtils.resolve_hostname(full_domain)
                    if ip:
                        logger.info(f"Found subdomain: {full_domain} -> {ip}")
                        return {"subdomain": full_domain, "ip": ip}
                except:
                    pass
                return None
            
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                results = executor.map(check_subdomain, subdomains)
                found_subdomains = [r for r in results if r]
            
            logger.info(f"Subdomain enumeration completed. Found {len(found_subdomains)} subdomains")
            return {
                "domain": domain,
                "subdomains_found": len(found_subdomains),
                "subdomains": found_subdomains
            }
            
        except Exception as e:
            error_msg = f"Subdomain enumeration failed for {domain}: {e}"
            logger.error(error_msg)
            return {"error": error_msg}
    
    def dns_lookup(self, domain, record_types=['A', 'AAAA', 'MX', 'NS', 'TXT']):
        """Perform comprehensive DNS lookup"""
        logger.info(f"Performing DNS lookup for {domain}")
        
        results = {"domain": domain, "records": {}}
        
        # A record (IPv4)
        try:
            ip = NetworkUtils.resolve_hostname(domain)
            if ip:
                results["records"]["A"] = [ip]
        except:
            pass
        
        # MX records
        try:
            mx_records = NetworkUtils.get_mx_records(domain)
            if mx_records:
                results["records"]["MX"] = mx_records
        except:
            pass
        
        # Additional records would require dnspython
        # This is a basic implementation
        
        logger.info(f"DNS lookup completed for {domain}")
        return results

# Legacy functions for backward compatibility
def whois_lookup(domain):
    """Legacy function wrapper"""
    recon = ReconModule()
    result = recon.whois_lookup(domain)
    if "error" in result:
        return result["error"]
    return str(result)

def subdomain_enum(domain, wordlist='data/wordlists/subdomains.txt'):
    """Legacy function wrapper"""
    recon = ReconModule()
    result = recon.subdomain_enum(domain, wordlist)
    if "error" in result:
        return []
    return [sub["subdomain"] for sub in result["subdomains"]]
