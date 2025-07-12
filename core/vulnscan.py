"""
Advanced vulnerability scanning module for CyberNox
"""

import requests
import json
import re
from urllib.parse import urljoin, urlparse
from utils.logger import logger
from utils.config import config
from utils.fingerprint import ServiceFingerprinter

class VulnerabilityScanner:
    """Advanced vulnerability scanner with web application testing capabilities"""
    
    def __init__(self):
        self.user_agent = config.get('network.user_agent', 'CyberNox-Scanner/1.0')
        self.timeout = config.get('general.timeout', 5)
        self.fingerprinter = ServiceFingerprinter()
    
    def scan_web_vulnerabilities(self, target_url):
        """Comprehensive web vulnerability scan"""
        logger.info(f"Starting web vulnerability scan for {target_url}")
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        vulnerabilities = []
        
        # Basic HTTP fingerprinting
        fingerprint = self.fingerprinter.fingerprint_http(target_url)
        
        # Test for common vulnerabilities
        vulnerabilities.extend(self._test_sql_injection(target_url))
        vulnerabilities.extend(self._test_xss(target_url))
        vulnerabilities.extend(self._test_directory_traversal(target_url))
        vulnerabilities.extend(self._test_sensitive_files(target_url))
        vulnerabilities.extend(self._test_security_headers(target_url))
        vulnerabilities.extend(self._test_ssl_vulnerabilities(target_url))
        
        return {
            "target": target_url,
            "fingerprint": fingerprint,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }
    
    def _test_sql_injection(self, base_url):
        """Test for SQL injection vulnerabilities"""
        logger.info("Testing for SQL injection vulnerabilities")
        vulnerabilities = []
        
        # Common SQL injection payloads
        payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin'/*",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--"
        ]
        
        # Test GET parameters
        test_params = ['id', 'user', 'search', 'q', 'query', 'page', 'category']
        
        for param in test_params:
            for payload in payloads:
                try:
                    test_url = f"{base_url}?{param}={payload}"
                    response = requests.get(test_url, timeout=self.timeout, verify=False)
                    
                    # Check for SQL error patterns
                    sql_errors = [
                        "SQL syntax",
                        "mysql_fetch",
                        "ORA-",
                        "Microsoft OLE DB",
                        "ODBC SQL Server",
                        "PostgreSQL",
                        "Warning: mysql_",
                        "MySQLSyntaxErrorException",
                        "valid MySQL result",
                        "SQLSTATE"
                    ]
                    
                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            vulnerabilities.append({
                                "type": "SQL Injection",
                                "severity": "High",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "evidence": error
                            })
                            break
                            
                except Exception as e:
                    logger.debug(f"SQL injection test failed for {test_url}: {e}")
        
        return vulnerabilities
    
    def _test_xss(self, base_url):
        """Test for Cross-Site Scripting (XSS) vulnerabilities"""
        logger.info("Testing for XSS vulnerabilities")
        vulnerabilities = []
        
        # XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')></iframe>"
        ]
        
        test_params = ['search', 'q', 'query', 'message', 'comment', 'name', 'email']
        
        for param in test_params:
            for payload in payloads:
                try:
                    test_url = f"{base_url}?{param}={payload}"
                    response = requests.get(test_url, timeout=self.timeout, verify=False)
                    
                    # Check if payload is reflected in response
                    if payload in response.text:
                        vulnerabilities.append({
                            "type": "Cross-Site Scripting (XSS)",
                            "severity": "Medium",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": "Payload reflected in response"
                        })
                        
                except Exception as e:
                    logger.debug(f"XSS test failed for {test_url}: {e}")
        
        return vulnerabilities
    
    def _test_directory_traversal(self, base_url):
        """Test for directory traversal vulnerabilities"""
        logger.info("Testing for directory traversal vulnerabilities")
        vulnerabilities = []
        
        # Directory traversal payloads
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "../../../etc/shadow",
            "../../../../../../etc/passwd%00"
        ]
        
        test_params = ['file', 'path', 'page', 'include', 'doc', 'document']
        
        for param in test_params:
            for payload in payloads:
                try:
                    test_url = f"{base_url}?{param}={payload}"
                    response = requests.get(test_url, timeout=self.timeout, verify=False)
                    
                    # Check for file contents
                    indicators = [
                        "root:x:0:0:",
                        "[extensions]",
                        "# localhost",
                        "daemon:x:",
                        "127.0.0.1"
                    ]
                    
                    for indicator in indicators:
                        if indicator in response.text:
                            vulnerabilities.append({
                                "type": "Directory Traversal",
                                "severity": "High",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "evidence": indicator
                            })
                            break
                            
                except Exception as e:
                    logger.debug(f"Directory traversal test failed for {test_url}: {e}")
        
        return vulnerabilities
    
    def _test_sensitive_files(self, base_url):
        """Test for sensitive file exposure"""
        logger.info("Testing for sensitive file exposure")
        vulnerabilities = []
        
        sensitive_files = [
            "/.env",
            "/config.php",
            "/wp-config.php",
            "/database.php",
            "/config/database.yml",
            "/admin/config.php",
            "/.git/config",
            "/.svn/entries",
            "/backup.sql",
            "/database.sql",
            "/dump.sql",
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/robots.txt",
            "/sitemap.xml",
            "/.htaccess",
            "/web.config",
            "/crossdomain.xml"
        ]
        
        for file_path in sensitive_files:
            try:
                test_url = urljoin(base_url, file_path)
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                
                if response.status_code == 200 and len(response.content) > 0:
                    # Check for sensitive content patterns
                    sensitive_patterns = [
                        "password",
                        "secret",
                        "api_key",
                        "database",
                        "mysql",
                        "postgresql",
                        "mongodb"
                    ]
                    
                    content_lower = response.text.lower()
                    for pattern in sensitive_patterns:
                        if pattern in content_lower:
                            vulnerabilities.append({
                                "type": "Sensitive File Exposure",
                                "severity": "Medium",
                                "url": test_url,
                                "file": file_path,
                                "evidence": f"Contains '{pattern}'"
                            })
                            break
                    else:
                        # File exists but no sensitive patterns found
                        vulnerabilities.append({
                            "type": "Information Disclosure",
                            "severity": "Low",
                            "url": test_url,
                            "file": file_path,
                            "evidence": "File accessible"
                        })
                        
            except Exception as e:
                logger.debug(f"Sensitive file test failed for {test_url}: {e}")
        
        return vulnerabilities
    
    def _test_security_headers(self, base_url):
        """Test for missing security headers"""
        logger.info("Testing security headers")
        vulnerabilities = []
        
        try:
            response = requests.get(base_url, timeout=self.timeout, verify=False)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': None,
                'Content-Security-Policy': None,
                'Referrer-Policy': None
            }
            
            for header, expected_value in security_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        "type": "Missing Security Header",
                        "severity": "Low",
                        "url": base_url,
                        "header": header,
                        "evidence": f"Missing {header} header"
                    })
                elif expected_value and headers[header] not in expected_value:
                    vulnerabilities.append({
                        "type": "Insecure Security Header",
                        "severity": "Low",
                        "url": base_url,
                        "header": header,
                        "evidence": f"Insecure {header}: {headers[header]}"
                    })
                    
        except Exception as e:
            logger.debug(f"Security headers test failed for {base_url}: {e}")
        
        return vulnerabilities
    
    def _test_ssl_vulnerabilities(self, base_url):
        """Test for SSL/TLS vulnerabilities"""
        logger.info("Testing SSL/TLS configuration")
        vulnerabilities = []
        
        if not base_url.startswith('https://'):
            return vulnerabilities
        
        try:
            parsed_url = urlparse(base_url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            ssl_info = self.fingerprinter.get_ssl_info(hostname, port)
            
            if ssl_info:
                # Check certificate validity
                import datetime
                try:
                    not_after = datetime.datetime.strptime(ssl_info['not_after'], "%b %d %H:%M:%S %Y %Z")
                    if not_after < datetime.datetime.now():
                        vulnerabilities.append({
                            "type": "Expired SSL Certificate",
                            "severity": "High",
                            "url": base_url,
                            "evidence": f"Certificate expired on {ssl_info['not_after']}"
                        })
                except:
                    pass
                
                # Check for weak cipher suites (basic check)
                # This would require more advanced SSL analysis
                
        except Exception as e:
            logger.debug(f"SSL test failed for {base_url}: {e}")
        
        return vulnerabilities