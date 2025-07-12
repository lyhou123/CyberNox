#!/usr/bin/env python3
"""
CyberNox API Server
Simple script to start the CyberNox API server
"""

import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from api.app import create_app
from utils.logger import logger

def start_api_server(host='127.0.0.1', port=5000, debug=True):
    """
    Start the CyberNox API server
    
    Args:
        host (str): Host to bind to
        port (int): Port to listen on
        debug (bool): Enable debug mode
    """
    try:
        # Create the Flask app
        app = create_app('development' if debug else 'production')
        
        # Print startup information
        print(f"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                      CyberNox API Server                      ║
    ║                   Professional REST API                      ║
    ╚═══════════════════════════════════════════════════════════════╝
    
    🚀 Starting CyberNox API Server...
    🌐 URL: http://{host}:{port}
    📊 Debug Mode: {'Enabled' if debug else 'Disabled'}
    🔧 Environment: {'Development' if debug else 'Production'}
    
    Available Endpoints:
    📡 GET  /api/v1/status          - API status
    🔍 POST /api/v1/recon/whois     - WHOIS lookup
    🎯 POST /api/v1/scan/ports      - Port scanning
    🔒 POST /api/v1/vuln/web        - Web vulnerability scan
    🎣 POST /api/v1/phishing/analyze - Phishing analysis
    📊 GET  /api/v1/reports         - Get reports
    🌐 GET  /                       - Web dashboard
    
    Press Ctrl+C to stop the server
        """)
        
        # Start the server
        app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=True
        )
        
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Failed to start API server: {e}")
        print(f"❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='CyberNox API Server')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on (default: 5000)')
    parser.add_argument('--production', action='store_true', help='Run in production mode (disables debug)')
    parser.add_argument('--public', action='store_true', help='Allow public access (bind to 0.0.0.0)')
    
    args = parser.parse_args()
    
    # Set host for public access
    host = '0.0.0.0' if args.public else args.host
    debug = not args.production
    
    start_api_server(host=host, port=args.port, debug=debug)
