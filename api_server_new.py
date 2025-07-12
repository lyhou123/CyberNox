#!/usr/bin/env python3
"""
CyberNox API Server
Professional modular Flask application
"""

import sys
import os

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from api.app import create_app
from utils.logger import logger


def main():
    """Main application entry point"""
    try:
        # Create Flask application
        app = create_app('development')
        
        # Start server
        logger.info("Starting CyberNox API Server...")
        print("=" * 60)
        print("🛡️  CyberNox Professional Security Suite")
        print("=" * 60)
        print("🚀 API Server: http://127.0.0.1:5000")
        print("🔐 Admin Login: http://127.0.0.1:5000/api/v1/auth/login")
        print("📊 Dashboard: http://127.0.0.1:5000/api/v1/auth/dashboard")
        print("=" * 60)
        
        app.run(
            host='127.0.0.1',
            port=5000,
            debug=True,
            threaded=True
        )
        
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        print("\n🛑 Server stopped")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        print(f"\n❌ Server error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
