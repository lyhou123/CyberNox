"""
Port scanning and vulnerability scanning module for CyberNox
"""


import requests
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from utils.logger import logger
from utils.config import config
from utils.nettools import NetworkUtils

class PortScanner:
    """TCP Port Scanner with threading support"""
    
    def __init__(self):
        self.timeout = config.get('network.socket_timeout', 3)
        self.max_threads = config.get('scan.default_threads', 50)
        self.default_ports = config.get('network.default_ports', [80, 443, 22, 21, 25, 53])
    
    def scan_port(self, host, port):
        """Scan a single port"""
        try:
            is_open = NetworkUtils.is_port_open(host, port, self.timeout)
            if is_open:
                logger.info(f"Port {port}/tcp open on {host}")
                return {"port": port, "state": "open", "protocol": "tcp"}
        except Exception as e:
            logger.debug(f"Error scanning {host}:{port}: {e}")
        return None
    
    def tcp_scan(self, target, ports=None, max_threads=None):
        """Perform TCP port scan"""
        if ports is None:
            ports = self.default_ports
        
        if max_threads is None:
            max_threads = self.max_threads
        
        if not NetworkUtils.is_valid_ip(target):
            # Try to resolve hostname
            resolved_ip = NetworkUtils.resolve_hostname(target)
            if not resolved_ip:
                return {"error": f"Could not resolve target: {target}"}
            target = resolved_ip
        
        logger.info(f"Starting TCP scan of {target} on {len(ports)} ports")
        start_time = datetime.now()
        
        open_ports = []
        
        def scan_worker(port):
            result = self.scan_port(target, port)
            if result:
                open_ports.append(result)
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            executor.map(scan_worker, ports)
        
        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()
        
        logger.info(f"TCP scan completed in {scan_duration:.2f} seconds. Found {len(open_ports)} open ports")
        
        return {
            "target": target,
            "scan_type": "tcp",
            "open_ports": open_ports,
            "total_ports_scanned": len(ports),
            "scan_duration": scan_duration,
            "timestamp": start_time.isoformat()
        }

class VulnerabilityScanner:
    """CVE lookup and vulnerability scanning"""
    
    def __init__(self):
        self.api_url = config.get('cve.api_url', 'https://services.nvd.nist.gov/rest/json/cves/2.0')
        self.api_key = config.get('cve.api_key')
        self.timeout = config.get('general.timeout', 5)
        self.user_agent = config.get('network.user_agent', 'CyberNox-Scanner/1.0')
    
    def cve_lookup(self, service, max_results=10):
        """Look up CVEs for a specific service"""
        try:
            logger.info(f"Looking up CVEs for service: {service}")
            
            headers = {'User-Agent': self.user_agent}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            params = {
                'keywordSearch': service,
                'resultsPerPage': max_results,
                'startIndex': 0
            }
            
            response = requests.get(
                self.api_url,
                headers=headers,
                params=params,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []
                
                for item in data.get("vulnerabilities", []):
                    cve = item.get('cve', {})
                    cve_id = cve.get('id', 'Unknown')
                    descriptions = cve.get('descriptions', [])
                    description = descriptions[0].get('value', 'No description') if descriptions else 'No description'
                    
                    # Get CVSS score if available
                    metrics = cve.get('metrics', {})
                    cvss_score = 'Unknown'
                    if 'cvssMetricV31' in metrics:
                        cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV30' in metrics:
                        cvss_score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV2' in metrics:
                        cvss_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                    
                    vulnerabilities.append({
                        "cve_id": cve_id,
                        "description": description,
                        "cvss_score": cvss_score,
                        "published_date": cve.get('published', 'Unknown'),
                        "modified_date": cve.get('lastModified', 'Unknown')
                    })
                
                logger.info(f"Found {len(vulnerabilities)} CVEs for {service}")
                return {
                    "service": service,
                    "total_results": data.get('totalResults', 0),
                    "vulnerabilities": vulnerabilities
                }
            else:
                error_msg = f"CVE API request failed with status {response.status_code}"
                logger.error(error_msg)
                return {"error": error_msg}
                
        except Exception as e:
            error_msg = f"CVE lookup failed for {service}: {e}"
            logger.error(error_msg)
            return {"error": error_msg}

# Legacy functions for backward compatibility
def tcp_scan(target, ports):
    """Legacy function wrapper"""
    scanner = PortScanner()
    result = scanner.tcp_scan(target, ports)
    if "error" in result:
        return []
    return [port["port"] for port in result["open_ports"]]

def cve_lookup(service):
    """Legacy function wrapper"""
    vuln_scanner = VulnerabilityScanner()
    result = vuln_scanner.cve_lookup(service)
    if "error" in result:
        return []
    return result["vulnerabilities"]
