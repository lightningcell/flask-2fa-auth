from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from config import config

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()


def create_app(config_name='default'):
    """
    Application factory pattern for creating Flask app instances.
    
    Security considerations:
    - CSRF protection enabled globally
    - Secure session configuration
    - Login manager with proper security settings
    """
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    
    # Configure Flask-Login for security
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    login_manager.session_protection = 'strong'  # Enhanced session protection
    
    @login_manager.user_loader
    def load_user(user_id):
        """
        User loader function for Flask-Login.
        Uses parameterized query to prevent SQL injection.
        """
        from app.models import User
        return User.query.get(int(user_id))
    
    # Register blueprints
    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    
    from app.main import bp as main_bp
    app.register_blueprint(main_bp)
    
    # Security headers middleware
    @app.after_request
    def security_headers(response):
        """Add security headers to all responses."""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
    
    return app


# Import models to ensure they are registered with SQLAlchemy
from app import models
