import os
from datetime import timedelta

class Config:
    """Base configuration class with security best practices."""
    
    # Security: Use environment variables for sensitive data
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-change-in-production-use-secrets-manager'
    
    # CSRF Protection - enabled by default with Flask-WTF
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour CSRF token timeout
    
    # Database configuration with connection pooling
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,  # Verify connections before use
        'pool_recycle': 300,    # Recycle connections every 5 minutes
    }
    
    # Session security settings
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    SESSION_COOKIE_SECURE = True  # HTTPS only cookies
    SESSION_COOKIE_HTTPONLY = True  # Prevent XSS attacks
    SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
      # Additional security headers
    SEND_FILE_MAX_AGE_DEFAULT = timedelta(hours=1)
    
    # Mail configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'noreply@flask2fa.com'
    
    # Security settings for location tracking
    MAX_LOGIN_ATTEMPTS = 5
    LOCATION_APPROVAL_TOKEN_EXPIRE = timedelta(hours=24)
    SUSPICIOUS_LOGIN_THRESHOLD_KM = 100  # Alert if login from >100km away


class DevelopmentConfig(Config):
    """Development configuration with debug enabled."""
    DEBUG = True
    
    # Allow HTTP cookies in development
    SESSION_COOKIE_SECURE = False
    
    # Development database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or 'sqlite:///dev.db'


class ProductionConfig(Config):
    """Production configuration with enhanced security."""
    DEBUG = False
    
    # Production should use PostgreSQL or similar
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://user:pass@localhost/flask_2fa'
    
    # Stricter session settings for production
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    WTF_CSRF_ENABLED = False  # Disable CSRF for testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
