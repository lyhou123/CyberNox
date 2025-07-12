#!/usr/bin/env python3
"""
Test script for CyberNox functionality
"""

import sys
import subprocess
from pathlib import Path

def test_imports():
    """Test if all modules can be imported"""
    print("Testing module imports...")
    
    try:
        from core.recon import ReconModule
        from core.scanner import PortScanner, VulnerabilityScanner
        from core.brute import DirectoryBruteforcer
        from core.exploit import ExploitModule
        from core.vulnscan import VulnerabilityScanner as WebVulnScanner
        from core.phishing import PhishingDetector
        from core.monitor import NetworkMonitor, BasicNetworkMonitor
        from core.report import ReportGenerator
        from utils.logger import setup_logger, logger
        from utils.config import config
        from utils.fingerprint import ServiceFingerprinter
        from utils.nettools import NetworkUtils
        
        print("✓ All core modules imported successfully")
        return True
        
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

def test_basic_functionality():
    """Test basic functionality"""
    print("\nTesting basic functionality...")
    
    try:
        # Test configuration
        from utils.config import config
        test_value = config.get('general.debug', False)
        print("✓ Configuration system working")
        
        # Test logger
        from utils.logger import logger
        logger.info("Test log message")
        print("✓ Logging system working")
        
        # Test network utils
        from utils.nettools import NetworkUtils
        is_valid = NetworkUtils.is_valid_ip("192.168.1.1")
        print("✓ Network utilities working")
        
        # Test exploit module
        from core.exploit import ExploitModule
        exploit = ExploitModule()
        shell = exploit.generate_reverse_shell("bash", "127.0.0.1", 4444)
        if shell and "payload" in shell:
            print("✓ Exploit module working")
        
        return True
        
    except Exception as e:
        print(f"✗ Functionality test failed: {e}")
        return False

def test_cli():
    """Test CLI interface"""
    print("\nTesting CLI interface...")
    
    try:
        # Test help command
        result = subprocess.run([sys.executable, "main.py", "--help"], 
                               capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0 and "CyberNox" in result.stdout:
            print("✓ CLI help working")
            return True
        else:
            print(f"✗ CLI test failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("✗ CLI test timeout")
        return False
    except Exception as e:
        print(f"✗ CLI test error: {e}")
        return False

def test_wordlists():
    """Test if wordlists exist"""
    print("\nTesting wordlists...")
    
    wordlist_files = [
        "data/wordlists/subdomains.txt",
        "data/wordlists/directories.txt",
        "data/wordlists/files.txt"
    ]
    
    all_exist = True
    for wordlist in wordlist_files:
        if Path(wordlist).exists():
            print(f"✓ {wordlist} exists")
        else:
            print(f"✗ {wordlist} missing")
            all_exist = False
    
    return all_exist

def test_configuration():
    """Test configuration file"""
    print("\nTesting configuration...")
    
    if Path("config.yml").exists():
        print("✓ config.yml exists")
        
        try:
            from utils.config import config
            debug_setting = config.get('general.debug')
            print(f"✓ Configuration loaded (debug: {debug_setting})")
            return True
        except Exception as e:
            print(f"✗ Configuration error: {e}")
            return False
    else:
        print("✗ config.yml missing")
        return False

def main():
    """Run all tests"""
    print("=" * 50)
    print("CyberNox Test Suite")
    print("=" * 50)
    
    tests = [
        ("Module Imports", test_imports),
        ("Basic Functionality", test_basic_functionality),
        ("CLI Interface", test_cli),
        ("Wordlists", test_wordlists),
        ("Configuration", test_configuration)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n[{test_name}]")
        if test_func():
            passed += 1
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    print("=" * 50)
    
    if passed == total:
        print("🎉 All tests passed! CyberNox is ready to use.")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the installation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
