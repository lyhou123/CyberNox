"""
Flask Application Factory
Creates and configures the Flask app with all extensions
"""

from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from .middleware.auth import init_auth
from .routes import register_all_routes
from utils.logger import logger


def create_app(config_name='development'):
    """
    Create Flask application using the factory pattern
    
    Args:
        config_name (str): Configuration environment name
        
    Returns:
        Flask: Configured Flask application
    """
    app = Flask(__name__, 
                template_folder='../web/templates', 
                static_folder='../web/static')
    
    # Load configuration
    app.config.update({
        'SECRET_KEY': 'cybernox-professional-api-key-change-in-production',
        'DEBUG': config_name == 'development',
        'TESTING': config_name == 'testing'
    })
    
    # Initialize extensions
    CORS(app)
    
    # Rate limiting
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["100 per hour"]
    )
    limiter.init_app(app)
    
    # Initialize authentication
    init_auth(app)
    
    # Register all route blueprints
    register_all_routes(app)
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return {'error': 'Endpoint not found'}, 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {error}")
        return {'error': 'Internal server error'}, 500
    
    logger.info(f"CyberNox API initialized in {config_name} mode")
    return app
