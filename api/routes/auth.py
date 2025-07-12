"""
Authentication Routes
Login, logout, and token validation endpoints
"""

from flask import Blueprint, request, jsonify, render_template, redirect, url_for

from ..middleware.auth import generate_token, validate_credentials, auth_required
from utils.logger import logger

auth_bp = Blueprint('auth', __name__, url_prefix='/api/v1/auth')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user authentication"""
    if request.method == 'GET':
        # Render login page
        return render_template('login.html')
    
    try:
        # Handle JSON login requests
        if request.is_json:
            data = request.get_json()
            username = data.get('username', '').strip()
            password = data.get('password', '')
            remember_me = data.get('remember_me', False)
        else:
            # Handle form data
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            remember_me = request.form.get('remember_me') == 'on'
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        if validate_credentials(username, password):
            token = generate_token(username, remember_me)
            
            response_data = {
                'message': 'Login successful',
                'token': token,
                'user': {'username': username},
                'redirect_url': '/api/v1/dashboard'
            }
            
            return jsonify(response_data), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500


@auth_bp.route('/logout', methods=['POST'])
@auth_required
def logout():
    """Handle user logout"""
    logger.info("User logged out successfully")
    return jsonify({'message': 'Logout successful'}), 200


@auth_bp.route('/validate', methods=['GET'])
@auth_required
def validate_token():
    """Validate current token"""
    return jsonify({
        'valid': True,
        'message': 'Token is valid'
    }), 200


@auth_bp.route('/dashboard', methods=['GET'])
@auth_required
def dashboard():
    """Render admin dashboard"""
    return render_template('dashboard.html')
