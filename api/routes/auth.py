"""
Authentication Routes
Login, logout, and token validation endpoints
"""

from flask import Blueprint, request, jsonify, render_template, redirect, url_for, session
from datetime import datetime, timedelta

from ..middleware.auth import generate_token, validate_credentials, auth_required, web_auth_required
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
            from ..middleware.auth import get_user_info
            
            token = generate_token(username, remember_me)
            user_info = get_user_info(username)
            
            # Set session for browser requests
            session['user_id'] = user_info['id'] if user_info else None
            session['username'] = username
            session['role'] = user_info.get('role', 'user') if user_info else 'user'
            
            # Set session expiration
            expiration_hours = 720 if remember_me else 24  # 30 days if remember_me
            expires_at = datetime.utcnow() + timedelta(hours=expiration_hours)
            session['expires_at'] = expires_at.isoformat()
            session.permanent = remember_me
            
            response_data = {
                'message': 'Login successful',
                'token': token,
                'user': {
                    'username': username,
                    'role': user_info.get('role', 'user') if user_info else 'user',
                    'email': user_info.get('email') if user_info else None
                },
                'redirect_url': '/api/v1/auth/dashboard' if user_info and user_info.get('role') == 'admin' else '/api/v1/dashboard'
            }
            
            return jsonify(response_data), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500


@auth_bp.route('/validate', methods=['GET'])
@auth_required
def validate_token():
    """Validate current token"""
    return jsonify({
        'valid': True,
        'message': 'Token is valid'
    }), 200


@auth_bp.route('/dashboard', methods=['GET'])
@web_auth_required
def dashboard():
    """Render admin dashboard"""
    return render_template('dashboard.html')


@auth_bp.route('/logout', methods=['POST', 'GET'])
def logout():
    """Handle user logout"""
    username = session.get('username', 'unknown')
    session.clear()
    
    logger.info(f"User logged out: {username}")
    
    if request.is_json:
        return jsonify({'message': 'Logged out successfully'}), 200
    else:
        return redirect(url_for('auth.login'))
