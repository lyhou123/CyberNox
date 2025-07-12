"""
Service fingerprinting utilities for CyberNox
"""

import socket
import ssl
import requests
from utils.logger import logger
from utils.config import config

class ServiceFingerprinter:
    """Service fingerprinting and banner grabbing"""
    
    def __init__(self):
        self.timeout = config.get('network.socket_timeout', 3)
        self.user_agent = config.get('network.user_agent', 'CyberNox-Scanner/1.0')
    
    def grab_banner(self, host, port):
        """Grab service banner from host:port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((host, port))
                
                # Send HTTP request for web services
                if port in [80, 8080, 8000]:
                    request = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
                    sock.send(request.encode())
                elif port == 443:
                    # Handle HTTPS
                    context = ssl.create_default_context()
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        request = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
                        ssock.send(request.encode())
                        banner = ssock.recv(1024).decode('utf-8', errors='ignore')
                        return banner.strip()
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return banner.strip()
                
        except Exception as e:
            logger.debug(f"Banner grab failed for {host}:{port}: {e}")
            return None
    
    def fingerprint_http(self, url):
        """Fingerprint HTTP service"""
        try:
            headers = {'User-Agent': self.user_agent}
            response = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
            
            fingerprint = {
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'Unknown'),
                'powered_by': response.headers.get('X-Powered-By', 'Unknown'),
                'content_type': response.headers.get('Content-Type', 'Unknown'),
                'cookies': list(response.cookies.keys()),
                'headers': dict(response.headers)
            }
            
            # Detect technologies from response
            content = response.text.lower()
            technologies = []
            
            if 'wordpress' in content:
                technologies.append('WordPress')
            if 'joomla' in content:
                technologies.append('Joomla')
            if 'drupal' in content:
                technologies.append('Drupal')
            if 'jquery' in content:
                technologies.append('jQuery')
            if 'bootstrap' in content:
                technologies.append('Bootstrap')
            
            fingerprint['technologies'] = technologies
            return fingerprint
            
        except Exception as e:
            logger.error(f"HTTP fingerprinting failed for {url}: {e}")
            return None
    
    def get_ssl_info(self, hostname, port=443):
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'sans': cert.get('subjectAltName', [])
                    }
                    
                    return ssl_info
                    
        except Exception as e:
            logger.error(f"SSL info gathering failed for {hostname}:{port}: {e}")
            return None