"""
Authentication Middleware
JWT token handling and auth decorators
"""

import jwt
from functools import wraps
from flask import request, jsonify, current_app, session, redirect, url_for
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


def web_auth_required(f):
    """
    Decorator for web routes that require authentication
    Supports both session cookies and JWT tokens
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check for session-based authentication first (for browser requests)
        if 'user_id' in session and 'username' in session:
            # Validate session hasn't expired
            if 'expires_at' in session:
                if datetime.fromisoformat(session['expires_at']) > datetime.utcnow():
                    logger.debug(f"Valid session found for user: {session['username']}")
                    return f(*args, **kwargs)
                else:
                    session.clear()
                    logger.warning(f"Expired session cleared for user: {session.get('username', 'unknown')}")
            else:
                # Session without expiration, assume valid
                return f(*args, **kwargs)
        
        # Check for JWT token in Authorization header (for API requests)
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
                data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
                logger.debug(f"Token validated successfully for user: {data.get('username', 'unknown')}")
                return f(*args, **kwargs)
            except jwt.ExpiredSignatureError:
                logger.warning(f"Expired token used from {request.remote_addr}")
            except jwt.InvalidTokenError as e:
                logger.warning(f"Invalid token from {request.remote_addr}: {str(e)}")
            except IndexError:
                logger.warning(f"Invalid Authorization header format from {request.remote_addr}")
        
        # No valid authentication found
        logger.warning(f"Unauthorized access attempt to {request.endpoint} from {request.remote_addr}")
        
        # Return appropriate response based on request type
        if request.is_json or auth_header:
            # API request - return JSON error
            return jsonify({
                'error': 'Authentication required',
                'redirect_url': '/api/v1/auth/login'
            }), 401
        else:
            # Browser request - redirect to login
            return redirect(url_for('auth.login'))
    
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
    Validate user credentials against database
    
    Args:
        username (str): Username
        password (str): Password
        
    Returns:
        bool: True if valid credentials
    """
    from utils.database import db
    
    user_info = db.validate_user_credentials(username, password)
    
    if user_info:
        logger.info(f"Successful database login for user: {username}")
        return True
    else:
        logger.warning(f"Failed database login attempt for user: {username} from {request.remote_addr}")
        return False


def get_user_info(username):
    """
    Get user information from database
    
    Args:
        username (str): Username
        
    Returns:
        dict: User information or None
    """
    from utils.database import db
    return db.get_user_by_username(username)
