"""
Reconnaissance Routes
WHOIS, subdomain enumeration, and reconnaissance endpoints
"""

from flask import Blueprint, request, jsonify
import threading

from ..middleware.auth import auth_required
from ..models.task import task_manager, TaskType
from core.recon import ReconModule
from utils.logger import logger

recon_bp = Blueprint('recon', __name__, url_prefix='/api/v1/recon')


@recon_bp.route('/whois', methods=['POST'])
@auth_required
def whois_lookup():
    """Perform WHOIS lookup"""
    try:
        data = request.get_json()
        domain = data.get('domain')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        # Create task
        task = task_manager.create_task(
            task_type=TaskType.RECON.value,
            target=domain,
            params={'operation': 'whois'}
        )
        
        # Execute WHOIS lookup in background
        def run_whois():
            try:
                task.start()
                recon = ReconModule()
                result = recon.whois_lookup(domain)
                task.complete({'whois_data': result})
            except Exception as e:
                task.fail(str(e))
        
        threading.Thread(target=run_whois, daemon=True).start()
        
        return jsonify({
            'message': 'WHOIS lookup started',
            'task_id': task.id
        }), 202
        
    except Exception as e:
        logger.error(f"WHOIS lookup error: {str(e)}")
        return jsonify({'error': 'WHOIS lookup failed'}), 500


@recon_bp.route('/subdomains', methods=['POST'])
@auth_required
def subdomain_enumeration():
    """Perform subdomain enumeration"""
    try:
        data = request.get_json()
        domain = data.get('domain')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        # Create task
        task = task_manager.create_task(
            task_type=TaskType.RECON.value,
            target=domain,
            params={'operation': 'subdomains'}
        )
        
        def run_subdomain_enum():
            try:
                task.start()
                recon = ReconModule()
                result = recon.enumerate_subdomains(domain)
                task.complete({'subdomains': result})
            except Exception as e:
                task.fail(str(e))
        
        threading.Thread(target=run_subdomain_enum, daemon=True).start()
        
        return jsonify({
            'message': 'Subdomain enumeration started',
            'task_id': task.id
        }), 202
        
    except Exception as e:
        logger.error(f"Subdomain enumeration error: {str(e)}")
        return jsonify({'error': 'Subdomain enumeration failed'}), 500


@recon_bp.route('/dns', methods=['POST'])
@auth_required
def dns_enumeration():
    """Perform DNS enumeration"""
    try:
        data = request.get_json()
        domain = data.get('domain')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        task = task_manager.create_task(
            task_type=TaskType.RECON.value,
            target=domain,
            params={'operation': 'dns'}
        )
        
        def run_dns_enum():
            try:
                task.start()
                recon = ReconModule()
                result = recon.dns_enumeration(domain)
                task.complete({'dns_records': result})
            except Exception as e:
                task.fail(str(e))
        
        threading.Thread(target=run_dns_enum, daemon=True).start()
        
        return jsonify({
            'message': 'DNS enumeration started',
            'task_id': task.id
        }), 202
        
    except Exception as e:
        logger.error(f"DNS enumeration error: {str(e)}")
        return jsonify({'error': 'DNS enumeration failed'}), 500
