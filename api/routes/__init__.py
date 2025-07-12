"""
API Routes Package
Register all route blueprints
"""

from .auth import auth_bp
from .recon import recon_bp
from .scan import scan_bp
from .tasks import task_bp
from .system import system_bp


def register_all_routes(app):
    """Register all route blueprints with the Flask app"""
    app.register_blueprint(auth_bp)
    app.register_blueprint(recon_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(task_bp)
    app.register_blueprint(system_bp)
    
    return app
