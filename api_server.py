"""
RESTful API interface for CyberNox
Professional web service for remote scanning and management
"""

from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import threading
import uuid
from datetime import datetime, timedelta
import jwt
from functools import wraps


# Import CyberNox modules
from core.recon import ReconModule
from core.scanner import PortScanner
from core.exploit import ExploitModule
from core.vulnscan import VulnerabilityScanner as WebVulnScanner
from core.report import ReportGenerator
from utils.database import db
from utils.logger import logger
from utils.advanced_config import config_manager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cybernox-professional-api-key-change-in-production'

# Enable CORS for web interface
CORS(app)

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)
limiter.init_app(app)

# In-memory storage for running tasks
running_tasks = {}

class TaskManager:
    """Manage long-running scan tasks"""
    
    @staticmethod
    def create_task(task_type: str, target: str, params: dict) -> str:
        """Create a new task"""
        task_id = str(uuid.uuid4())
        task = {
            'id': task_id,
            'type': task_type,
            'target': target,
            'params': params,
            'status': 'pending',
            'created': datetime.now(),
            'started': None,
            'completed': None,
            'progress': 0,
            'results': None,
            'error': None
        }
        running_tasks[task_id] = task
        return task_id
    
    @staticmethod
    def update_task(task_id: str, **kwargs):
        """Update task information"""
        if task_id in running_tasks:
            running_tasks[task_id].update(kwargs)
    
    @staticmethod
    def get_task(task_id: str) -> dict:
        """Get task information"""
        return running_tasks.get(task_id)
    
    @staticmethod
    def get_all_tasks() -> list:
        """Get all tasks"""
        return list(running_tasks.values())

def auth_required(f):
    """Authentication decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            
            # For demo purposes, accept any token
            # In production, implement proper JWT validation
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token is invalid'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

@app.route('/api/v1/auth/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    """Login endpoint - serves form on GET, processes login on POST"""
    
    if request.method == 'GET':
        # Serve the login form
        with open('admin_login.html', 'r', encoding='utf-8') as f:
            login_html = f.read()
        return login_html
    
    # POST request - process login
    data = request.get_json()
    
    # Demo authentication - replace with real auth
    username = data.get('username')
    password = data.get('password')
    
    if username == 'admin' and password == 'cybernox123':
        token = jwt.encode({
            'user': username,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'success': True,
            'token': token,
            'expires_in': 86400,
            'redirect_url': '/api/v1/dashboard'
        })
    
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/', methods=['GET'])
def home():
    """Root endpoint - API information"""
    return jsonify({
        'message': 'CyberNox Professional Security API',
        'version': '1.0.0',
        'status': 'online',
        'documentation': {
            'web_dashboard': 'Open web_dashboard.html in your browser',
            'api_status': '/api/v1/status',
            'authentication': '/api/v1/auth/login',
            'endpoints': '/api/v1/status'
        },
        'demo_credentials': {
            'username': 'admin',
            'password': 'cybernox123'
        }
    })

@app.route('/api/v1/status', methods=['GET'])
def status():
    """API status and information"""
    return jsonify({
        'status': 'online',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat(),
        'active_tasks': len(running_tasks),
        'endpoints': {
            'authentication': '/api/v1/auth/login',
            'reconnaissance': '/api/v1/recon/*',
            'scanning': '/api/v1/scan/*',
            'vulnerabilities': '/api/v1/vuln/*',
            'exploitation': '/api/v1/exploit/*',
            'monitoring': '/api/v1/monitor/*',
            'reports': '/api/v1/reports/*',
            'tasks': '/api/v1/tasks/*'
        }
    })

@app.route('/api/v1/recon/whois', methods=['POST'])
@auth_required
@limiter.limit("10 per minute")
def whois_lookup():
    """Perform WHOIS lookup"""
    data = request.get_json()
    domain = data.get('domain')
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    try:
        recon = ReconModule()
        results = recon.whois_lookup(domain)
        
        # Save to database
        db.save_scan_result('whois', domain, results)
        
        return jsonify({
            'success': True,
            'domain': domain,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"WHOIS API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/recon/subdomains', methods=['POST'])
@auth_required
@limiter.limit("5 per minute")
def subdomain_enumeration():
    """Start subdomain enumeration task"""
    data = request.get_json()
    domain = data.get('domain')
    wordlist = data.get('wordlist')
    max_threads = data.get('max_threads', 50)
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    # Create task
    task_id = TaskManager.create_task('subdomain_enum', domain, {
        'wordlist': wordlist,
        'max_threads': max_threads
    })
    
    # Start task in background
    def run_subdomain_enum():
        try:
            TaskManager.update_task(task_id, status='running', started=datetime.now())
            
            recon = ReconModule()
            results = recon.subdomain_enum(domain, wordlist, max_threads)
            
            # Save to database
            db.save_scan_result('subdomain_enum', domain, results)
            
            TaskManager.update_task(task_id, 
                                  status='completed', 
                                  completed=datetime.now(),
                                  progress=100,
                                  results=results)
            
        except Exception as e:
            TaskManager.update_task(task_id, 
                                  status='failed', 
                                  error=str(e),
                                  completed=datetime.now())
    
    thread = threading.Thread(target=run_subdomain_enum)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'task_id': task_id,
        'status': 'started',
        'domain': domain
    })

@app.route('/api/v1/scan/ports', methods=['POST'])
@auth_required
@limiter.limit("10 per minute")
def port_scan():
    """Perform port scan"""
    data = request.get_json()
    target = data.get('target')
    ports = data.get('ports', [80, 443, 22, 21, 25, 53])
    max_threads = data.get('max_threads', 50)
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    try:
        scanner = PortScanner()
        results = scanner.tcp_scan(target, ports, max_threads)
        
        # Save to database
        db.save_scan_result('port_scan', target, results)
        
        return jsonify({
            'success': True,
            'target': target,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Port scan API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/vuln/web', methods=['POST'])
@auth_required
@limiter.limit("5 per minute")
def web_vulnerability_scan():
    """Start web vulnerability scan task"""
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Create task
    task_id = TaskManager.create_task('web_vuln_scan', url, {})
    
    # Start task in background
    def run_web_scan():
        try:
            TaskManager.update_task(task_id, status='running', started=datetime.now())
            
            scanner = WebVulnScanner()
            results = scanner.scan_web_vulnerabilities(url)
            
            # Save to database
            db.save_scan_result('vulnerability_scan', url, results)
            
            TaskManager.update_task(task_id,
                                  status='completed',
                                  completed=datetime.now(),
                                  progress=100,
                                  results=results)
            
        except Exception as e:
            TaskManager.update_task(task_id,
                                  status='failed',
                                  error=str(e),
                                  completed=datetime.now())
    
    thread = threading.Thread(target=run_web_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'task_id': task_id,
        'status': 'started',
        'url': url
    })

@app.route('/api/v1/exploit/shell', methods=['POST'])
@auth_required
@limiter.limit("20 per minute")
def generate_shell():
    """Generate reverse shell payload"""
    data = request.get_json()
    shell_type = data.get('type')
    lhost = data.get('lhost')
    lport = data.get('lport')
    
    if not all([shell_type, lhost, lport]):
        return jsonify({'error': 'Type, lhost, and lport are required'}), 400
    
    try:
        exploit = ExploitModule()
        results = exploit.generate_reverse_shell(shell_type, lhost, lport)
        
        return jsonify({
            'success': True,
            'shell_type': shell_type,
            'lhost': lhost,
            'lport': lport,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Shell generation API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/tasks/<task_id>', methods=['GET'])
@auth_required
def get_task_status(task_id):
    """Get task status and results"""
    task = TaskManager.get_task(task_id)
    
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    
    return jsonify({
        'success': True,
        'task': task
    })

@app.route('/api/v1/tasks', methods=['GET'])
@auth_required
def get_all_tasks():
    """Get all tasks"""
    tasks = TaskManager.get_all_tasks()
    
    return jsonify({
        'success': True,
        'tasks': tasks,
        'total': len(tasks)
    })

@app.route('/api/v1/reports/generate', methods=['POST'])
@auth_required
@limiter.limit("5 per minute")
def generate_report():
    """Generate security report"""
    data = request.get_json()
    scan_ids = data.get('scan_ids', [])
    format_type = data.get('format', 'html')
    title = data.get('title', 'CyberNox Security Report')
    
    try:
        # Get scan results from database
        scan_results = []
        for scan_id in scan_ids:
            # This would need to be implemented in the database module
            pass
        
        # Generate report
        report_gen = ReportGenerator()
        report_gen.output_format = format_type
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cybernox_report_{timestamp}"
        
        result = report_gen.generate_scan_report(scan_results, filename)
        
        return jsonify({
            'success': True,
            'report': result
        })
        
    except Exception as e:
        logger.error(f"Report generation API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/dashboard', methods=['GET'])
@auth_required
def dashboard_page():
    """Serve the admin dashboard page"""
    try:
        with open('admin_dashboard.html', 'r', encoding='utf-8') as f:
            dashboard_html = f.read()
        return dashboard_html
    except FileNotFoundError:
        return jsonify({'error': 'Dashboard page not found'}), 404

@app.route('/api/v1/dashboard/data', methods=['GET'])
@auth_required
def dashboard_data():
    """Get dashboard data"""
    try:
        dashboard_data = db.generate_dashboard_data()
        
        return jsonify({
            'success': True,
            'data': dashboard_data
        })
        
    except Exception as e:
        logger.error(f"Dashboard API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/targets/<target>/stats', methods=['GET'])
@auth_required
def target_statistics(target):
    """Get target statistics"""
    try:
        stats = db.get_target_statistics(target)
        
        return jsonify({
            'success': True,
            'target': target,
            'statistics': stats
        })
        
    except Exception as e:
        logger.error(f"Target stats API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/config', methods=['GET'])
@auth_required
def get_config():
    """Get current configuration"""
    try:
        config_data = {
            'network': {
                'user_agent': config_manager.network.user_agent,
                'timeout': config_manager.network.timeout,
                'max_retries': config_manager.network.max_retries,
            },
            'scan': {
                'default_threads': config_manager.scan.default_threads,
                'rate_limit': config_manager.scan.rate_limit,
                'stealth_mode': config_manager.scan.stealth_mode,
            },
            'security': {
                'ssl_verify': config_manager.security.ssl_verify,
                'follow_redirects': config_manager.security.follow_redirects,
            }
        }
        
        return jsonify({
            'success': True,
            'configuration': config_data
        })
        
    except Exception as e:
        logger.error(f"Config API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded', 'retry_after': str(e.retry_after)}), 429

def run_api_server(host='127.0.0.1', port=5000, debug=False):
    """Run the API server"""
    logger.info(f"Starting CyberNox API server on {host}:{port}")
    app.run(host=host, port=port, debug=debug, threaded=True)

if __name__ == '__main__':
    run_api_server(debug=True)
