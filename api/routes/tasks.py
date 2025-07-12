"""
Task Management Routes
Task status, monitoring, and management endpoints
"""

from flask import Blueprint, request, jsonify

from ..middleware.auth import auth_required
from ..models.task import task_manager
from utils.logger import logger

task_bp = Blueprint('tasks', __name__, url_prefix='/api/v1/tasks')


@task_bp.route('/<task_id>', methods=['GET'])
@auth_required
def get_task_status(task_id):
    """Get task status by ID"""
    try:
        task = task_manager.get_task(task_id)
        
        if not task:
            return jsonify({'error': 'Task not found'}), 404
        
        return jsonify(task.to_dict()), 200
        
    except Exception as e:
        logger.error(f"Get task status error: {str(e)}")
        return jsonify({'error': 'Failed to get task status'}), 500


@task_bp.route('', methods=['GET'])
@auth_required
def get_all_tasks():
    """Get all tasks"""
    try:
        tasks = task_manager.get_all_tasks()
        task_list = [task.to_dict() for task in tasks.values()]
        
        # Sort by creation time (newest first)
        task_list.sort(key=lambda x: x['created_at'], reverse=True)
        
        return jsonify({
            'tasks': task_list,
            'total': len(task_list)
        }), 200
        
    except Exception as e:
        logger.error(f"Get all tasks error: {str(e)}")
        return jsonify({'error': 'Failed to get tasks'}), 500


@task_bp.route('/<task_id>', methods=['DELETE'])
@auth_required
def delete_task(task_id):
    """Delete task by ID"""
    try:
        success = task_manager.delete_task(task_id)
        
        if success:
            return jsonify({'message': 'Task deleted successfully'}), 200
        else:
            return jsonify({'error': 'Task not found'}), 404
            
    except Exception as e:
        logger.error(f"Delete task error: {str(e)}")
        return jsonify({'error': 'Failed to delete task'}), 500


@task_bp.route('/cleanup', methods=['POST'])
@auth_required
def cleanup_tasks():
    """Clean up old completed tasks"""
    try:
        data = request.get_json() or {}
        max_age_hours = data.get('max_age_hours', 24)
        
        task_manager.cleanup_completed_tasks(max_age_hours)
        
        return jsonify({'message': 'Task cleanup completed'}), 200
        
    except Exception as e:
        logger.error(f"Task cleanup error: {str(e)}")
        return jsonify({'error': 'Failed to cleanup tasks'}), 500
