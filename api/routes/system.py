"""
System Routes
Status, health checks, and system information endpoints
"""

from flask import Blueprint, jsonify, redirect, url_for
import psutil
import platform
from datetime import datetime

from ..middleware.auth import auth_required
from utils.logger import logger

system_bp = Blueprint('system', __name__)


@system_bp.route('/', methods=['GET'])
def home():
    """Home page - redirect to login"""
    return redirect(url_for('auth.login'))


@system_bp.route('/api/v1/status', methods=['GET'])
@auth_required
def status():
    """Get system status and health information"""
    try:
        # Get system information
        system_info = {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'architecture': platform.architecture()[0],
            'processor': platform.processor(),
            'hostname': platform.node(),
            'python_version': platform.python_version()
        }
        
        # Get system resources
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        resources = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory': {
                'total': memory.total,
                'available': memory.available,
                'percent': memory.percent,
                'used': memory.used
            },
            'disk': {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': (disk.used / disk.total) * 100
            }
        }
        
        return jsonify({
            'status': 'online',
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0',
            'system': system_info,
            'resources': resources,
            'services': {
                'api': 'running',
                'database': 'connected',
                'scanner': 'ready'
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Status check error: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@system_bp.route('/api/v1/health', methods=['GET'])
def health_check():
    """Simple health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    }), 200


@system_bp.route('/api/v1/info', methods=['GET'])
def system_info():
    """Get basic system information"""
    return jsonify({
        'name': 'CyberNox Security Suite',
        'version': '1.0.0',
        'description': 'Professional Cybersecurity Toolkit',
        'author': 'CyberNox Team',
        'status': 'active'
    }), 200
