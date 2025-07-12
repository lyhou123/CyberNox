#!/usr/bin/env python3
"""
CyberNox - Advanced Cybersecurity Toolkit
Main application entry point with modular CLI architecture
Version: 2.0.0
Author: CyberNox Team

A comprehensive cybersecurity toolkit for penetration testing, vulnerability assessment,
network monitoring, and security research with professional modular CLI.
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import the new modular CLI
from cli.main import cli

if __name__ == '__main__':
    try:
        cli()
    except KeyboardInterrupt:
        print("\n🛑 Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)
