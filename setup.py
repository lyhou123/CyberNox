#!/usr/bin/env python3
"""
Setup and installation script for CyberNox
"""

import subprocess
import sys
import os
from pathlib import Path

def install_requirements():
    """Install required packages"""
    print("Installing required packages...")
    
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✓ All requirements installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to install requirements: {e}")
        return False
    
    return True

def create_directories():
    """Create necessary directories"""
    print("Creating necessary directories...")
    
    directories = [
        'reports',
        'logs',
        'data/payloads',
        'data/wordlists'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✓ Created directory: {directory}")

def check_python_version():
    """Check if Python version is compatible"""
    print("Checking Python version...")
    
    if sys.version_info < (3, 7):
        print("✗ Python 3.7 or higher is required")
        return False
    
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor} is compatible")
    return True

def make_executable():
    """Make main.py executable on Unix-like systems"""
    if os.name != 'nt':  # Not Windows
        try:
            os.chmod('main.py', 0o755)
            print("✓ Made main.py executable")
        except Exception as e:
            print(f"✗ Failed to make main.py executable: {e}")

def main():
    """Main setup function"""
    print("=" * 50)
    print("CyberNox Setup Script")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Install requirements
    if not install_requirements():
        print("Setup failed. Please install requirements manually.")
        sys.exit(1)
    
    # Make executable
    make_executable()
    
    print("\n" + "=" * 50)
    print("Setup completed successfully!")
    print("=" * 50)
    print("\nYou can now run CyberNox:")
    print("  python main.py --help")
    print("  python main.py recon --whois example.com")
    print("  python main.py scan --target 192.168.1.1 --ports 80 443")

if __name__ == '__main__':
    main()
