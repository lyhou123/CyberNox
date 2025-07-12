"""
Network utility functions for CyberNox
"""

import socket
import ipaddress
import re
from urllib.parse import urlparse
from utils.logger import logger

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

class NetworkUtils:
    """Network utility functions"""
    
    @staticmethod
    def is_valid_ip(ip):
        """Check if IP address is valid"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_domain(domain):
        """Check if domain name is valid"""
        try:
            # Simple domain validation
            if not domain or len(domain) > 253:
                return False
            if domain[-1] == ".":
                domain = domain[:-1]
            allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
            return all(allowed.match(x) for x in domain.split("."))
        except:
            return False
    
    @staticmethod
    def resolve_hostname(hostname):
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror as e:
            logger.warning(f"Could not resolve hostname {hostname}: {e}")
            return None
    
    @staticmethod
    def reverse_dns(ip):
        """Perform reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror as e:
            logger.warning(f"Reverse DNS failed for {ip}: {e}")
            return None
    
    @staticmethod
    def get_mx_records(domain):
        """Get MX records for domain"""
        if not DNS_AVAILABLE:
            logger.warning("dnspython not available, cannot get MX records")
            return []
        
        try:
            mx_records = []
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx_records.append({
                    'priority': rdata.preference,
                    'exchange': str(rdata.exchange)
                })
            return mx_records
        except Exception as e:
            logger.warning(f"Could not get MX records for {domain}: {e}")
            return []
    
    @staticmethod
    def parse_url(url):
        """Parse URL and extract components"""
        try:
            parsed = urlparse(url)
            return {
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'hostname': parsed.hostname,
                'port': parsed.port,
                'path': parsed.path,
                'query': parsed.query,
                'fragment': parsed.fragment
            }
        except Exception as e:
            logger.error(f"Could not parse URL {url}: {e}")
            return None
    
    @staticmethod
    def is_port_open(host, port, timeout=3):
        """Check if a port is open on a host"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                return result == 0
        except Exception as e:
            logger.debug(f"Port check failed for {host}:{port}: {e}")
            return False