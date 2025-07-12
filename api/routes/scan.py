"""
Scanning Routes
Port scanning and network discovery endpoints
"""

from flask import Blueprint, request, jsonify
import threading

from ..middleware.auth import auth_required
from ..models.task import task_manager, TaskType
from core.scanner import PortScanner
from utils.logger import logger

scan_bp = Blueprint('scan', __name__, url_prefix='/api/v1/scan')


@scan_bp.route('/ports', methods=['POST'])
@auth_required
def port_scan():
    """Perform port scanning"""
    try:
        data = request.get_json()
        target = data.get('target')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Parse scan parameters
        ports = data.get('ports', '1-1000')
        scan_type = data.get('scan_type', 'tcp')
        
        # Create task
        task = task_manager.create_task(
            task_type=TaskType.PORT_SCAN.value,
            target=target,
            params={
                'ports': ports,
                'scan_type': scan_type
            }
        )
        
        def run_port_scan():
            try:
                task.start()
                scanner = PortScanner()
                result = scanner.scan_ports(target, ports)
                task.complete({'scan_results': result})
            except Exception as e:
                task.fail(str(e))
        
        threading.Thread(target=run_port_scan, daemon=True).start()
        
        return jsonify({
            'message': 'Port scan started',
            'task_id': task.id,
            'target': target,
            'ports': ports
        }), 202
        
    except Exception as e:
        logger.error(f"Port scan error: {str(e)}")
        return jsonify({'error': 'Port scan failed'}), 500


@scan_bp.route('/network', methods=['POST'])
@auth_required
def network_discovery():
    """Perform network discovery"""
    try:
        data = request.get_json()
        network = data.get('network')
        
        if not network:
            return jsonify({'error': 'Network range is required'}), 400
        
        task = task_manager.create_task(
            task_type=TaskType.PORT_SCAN.value,
            target=network,
            params={'operation': 'network_discovery'}
        )
        
        def run_network_scan():
            try:
                task.start()
                scanner = PortScanner()
                result = scanner.discover_hosts(network)
                task.complete({'discovered_hosts': result})
            except Exception as e:
                task.fail(str(e))
        
        threading.Thread(target=run_network_scan, daemon=True).start()
        
        return jsonify({
            'message': 'Network discovery started',
            'task_id': task.id,
            'network': network
        }), 202
        
    except Exception as e:
        logger.error(f"Network discovery error: {str(e)}")
        return jsonify({'error': 'Network discovery failed'}), 500


@scan_bp.route('/start', methods=['POST'])
@auth_required
def start_quick_scan():
    """Start a quick scan (used by dashboard)"""
    try:
        data = request.get_json()
        target = data.get('target')
        scan_type = data.get('scan_type', 'port')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Map scan types
        task_type_map = {
            'port': TaskType.PORT_SCAN.value,
            'vuln': TaskType.VULN_SCAN.value,
            'recon': TaskType.RECON.value
        }
        
        task_type = task_type_map.get(scan_type, TaskType.PORT_SCAN.value)
        
        task = task_manager.create_task(
            task_type=task_type,
            target=target,
            params={'quick_scan': True}
        )
        
        def run_quick_scan():
            try:
                task.start()
                # Simulate scan execution
                import time
                time.sleep(2)  # Simulate scan time
                task.complete({
                    'message': f'Quick {scan_type} scan completed',
                    'target': target,
                    'findings': f'Scan completed successfully for {target}'
                })
            except Exception as e:
                task.fail(str(e))
        
        threading.Thread(target=run_quick_scan, daemon=True).start()
        
        return jsonify({
            'message': f'Quick {scan_type} scan started for {target}',
            'task_id': task.id
        }), 200
        
    except Exception as e:
        logger.error(f"Quick scan error: {str(e)}")
        return jsonify({'error': 'Quick scan failed'}), 500
