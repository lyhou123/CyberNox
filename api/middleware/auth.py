"""
Authentication Middleware
JWT token handling and auth decorators
"""

import jwt
from functools import wraps
from flask import request, jsonify, current_app
from datetime import datetime, timedelta

from utils.logger import logger


def init_auth(app):
    """Initialize authentication configuration"""
    app.config.setdefault('JWT_EXPIRATION_HOURS', 24)
    logger.info("Authentication middleware initialized")


def auth_required(f):
    """
    Decorator for routes that require authentication
    Validates JWT token from Authorization header
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
            except IndexError:
                logger.warning(f"Invalid Authorization header format from {request.remote_addr}")
                return jsonify({
                    'error': 'Invalid token format. Use: Bearer <token>',
                    'redirect_url': '/api/v1/auth/login'
                }), 401
        
        if not token:
            logger.warning(f"Missing token for protected route {request.endpoint} from {request.remote_addr}")
            return jsonify({
                'error': 'Token is missing',
                'redirect_url': '/api/v1/auth/login'
            }), 401
        
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            logger.debug(f"Token validated successfully for user: {data.get('username', 'unknown')}")
        except jwt.ExpiredSignatureError:
            logger.warning(f"Expired token used from {request.remote_addr}")
            return jsonify({
                'error': 'Token has expired',
                'redirect_url': '/api/v1/auth/login'
            }), 401
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token from {request.remote_addr}: {str(e)}")
            return jsonify({
                'error': 'Invalid token',
                'redirect_url': '/api/v1/auth/login'
            }), 401
        
        return f(*args, **kwargs)
    
    return decorated


def generate_token(username, remember_me=False):
    """
    Generate JWT token for user
    
    Args:
        username (str): Username for token
        remember_me (bool): Extended expiration if True
        
    Returns:
        str: JWT token
    """
    expiration_hours = 720 if remember_me else 24  # 30 days if remember_me
    payload = {
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=expiration_hours),
        'iat': datetime.utcnow()
    }
    
    token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
    logger.info(f"Token generated for user: {username} (remember_me: {remember_me})")
    return token


def validate_credentials(username, password):
    """
    Validate user credentials
    
    Args:
        username (str): Username
        password (str): Password
        
    Returns:
        bool: True if valid credentials
    """
    # In production, this should check against a proper user database
    valid_users = {
        'admin': 'cybernox2024',
        'cybernox': 'admin123',
        'demo': 'demo123'
    }
    
    is_valid = username in valid_users and valid_users[username] == password
    
    if is_valid:
        logger.info(f"Successful login for user: {username}")
    else:
        logger.warning(f"Failed login attempt for user: {username} from {request.remote_addr}")
    
    return is_valid
