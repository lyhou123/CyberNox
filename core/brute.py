
"""
Directory and file brute force module for CyberNox
"""

import requests
import time
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from utils.logger import logger
from utils.config import config

class DirectoryBruteforcer:
    """Directory and file brute force scanner"""
    
    def __init__(self):
        self.user_agent = config.get('network.user_agent', 'CyberNox-Scanner/1.0')
        self.timeout = config.get('general.timeout', 5)
        self.max_threads = config.get('general.max_threads', 10)
        self.follow_redirects = config.get('brute.follow_redirects', True)
        self.rate_limit = config.get('brute.max_requests_per_second', 10)
        
        # Status codes that indicate found resources
        self.success_codes = [200, 301, 302, 403, 401]
        
        # Common extensions to try
        self.extensions = ['', '.html', '.php', '.asp', '.aspx', '.jsp', '.txt', '.bak', '.old']
    
    def make_request(self, url):
        """Make HTTP request with error handling"""
        try:
            headers = {
                'User-Agent': self.user_agent,
                'Accept': '*/*',
                'Connection': 'keep-alive'
            }
            
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                verify=False
            )
            
            return {
                'url': url,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'content_type': response.headers.get('Content-Type', ''),
                'server': response.headers.get('Server', ''),
                'title': self._extract_title(response.text) if response.status_code == 200 else ''
            }
            
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request failed for {url}: {e}")
            return None
    
    def _extract_title(self, html):
        """Extract title from HTML content"""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            title_tag = soup.find('title')
            return title_tag.get_text().strip() if title_tag else ''
        except:
            # Fallback to simple regex if BeautifulSoup fails
            import re
            match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            return match.group(1).strip() if match else ''
    
    def dir_brute(self, target_url, wordlist_file=None, extensions=None, max_threads=None):
        """Perform directory brute force attack"""
        if not wordlist_file:
            wordlist_file = config.get_wordlist_path("directories.txt")
        
        if not Path(wordlist_file).exists():
            error_msg = f"Wordlist file not found: {wordlist_file}"
            logger.error(error_msg)
            return {"error": error_msg}
        
        if extensions is None:
            extensions = self.extensions
        
        if max_threads is None:
            max_threads = self.max_threads
        
        # Normalize target URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        if not target_url.endswith('/'):
            target_url += '/'
        
        logger.info(f"Starting directory brute force on {target_url}")
        
        try:
            # Load wordlist
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            # Generate URLs to test
            urls_to_test = []
            for word in words:
                for ext in extensions:
                    test_url = urljoin(target_url, word + ext)
                    urls_to_test.append(test_url)
            
            logger.info(f"Testing {len(urls_to_test)} URLs with {max_threads} threads")
            
            found_resources = []
            
            def test_url(url):
                # Rate limiting
                time.sleep(1.0 / self.rate_limit)
                
                result = self.make_request(url)
                if result and result['status_code'] in self.success_codes:
                    logger.info(f"Found: {url} [{result['status_code']}] - {result['content_length']} bytes")
                    found_resources.append(result)
                    return result
                return None
            
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                results = list(executor.map(test_url, urls_to_test))
            
            # Filter out None results
            found_resources = [r for r in results if r]
            
            logger.info(f"Directory brute force completed. Found {len(found_resources)} resources")
            
            return {
                "target": target_url,
                "wordlist": str(wordlist_file),
                "total_requests": len(urls_to_test),
                "found_resources": len(found_resources),
                "resources": found_resources
            }
            
        except Exception as e:
            error_msg = f"Directory brute force failed: {e}"
            logger.error(error_msg)
            return {"error": error_msg}
    
    def file_brute(self, target_url, wordlist_file=None, extensions=None):
        """Perform file brute force attack"""
        if not wordlist_file:
            wordlist_file = config.get_wordlist_path("files.txt")
        
        return self.dir_brute(target_url, wordlist_file, extensions)

# Legacy function for backward compatibility
def dir_brute(target_url, wordlist='data/wordlists/directories.txt'):
    """Legacy function wrapper"""
    bruteforcer = DirectoryBruteforcer()
    result = bruteforcer.dir_brute(target_url, wordlist)
    if "error" in result:
        return []
    return [resource["url"] for resource in result["resources"]]
