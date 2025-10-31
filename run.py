#!/usr/bin/env python3
"""
Flask 2FA Authentication Application

This is the main entry point for the Flask application with two-factor authentication.
The application implements security best practices including:
- CSRF protection
- Secure password hashing with bcrypt  
- Two-factor authentication using TOTP
- Secure session management
- SQL injection prevention
- XSS protection

Security considerations:
- Never run in debug mode in production
- Use environment variables for sensitive configuration
- Ensure HTTPS is enabled in production
- Regularly update dependencies for security patches
"""

import os
from app import create_app, db
from app.models import User
from flask_migrate import upgrade


def deploy():
    """
    Deployment function for production environments.
    
    This function:
    1. Creates the application instance
    2. Runs database migrations
    3. Sets up initial data if needed
    """
    app = create_app(os.getenv('FLASK_CONFIG') or 'default')
    
    with app.app_context():
        # Create database tables
        db.create_all()
        
        # Run database migrations
        upgrade()


# Create application instance
app = create_app(os.getenv('FLASK_CONFIG') or 'default')


@app.shell_context_processor
def make_shell_context():
    """
    Shell context processor for Flask shell command.
    
    Provides convenient access to common objects when using 'flask shell'.
    """
    return {
        'db': db, 
        'User': User
    }


@app.cli.command()
def deploy_cmd():
    """Flask CLI command for deployment."""
    deploy()


@app.cli.command()
def create_admin():
    """
    Create an admin user for testing purposes.
    
    Security note: This is for development/testing only.
    In production, admin users should be created through secure processes.
    """
    username = input("Admin username: ")
    email = input("Admin email: ")
    password = input("Admin password: ")
    
    if User.query.filter_by(username=username).first():
        print(f"User {username} already exists!")
        return
    
    admin_user = User(username=username, email=email)
    admin_user.set_password(password)
    admin_user.generate_totp_secret()
    
    db.session.add(admin_user)
    db.session.commit()
    
    print(f"Admin user {username} created successfully!")
    print("Please complete 2FA setup by registering through the web interface.")


if __name__ == '__main__':
    # Security warning for development
    if app.config.get('DEBUG'):
        print("\n" + "="*60)
        print("WARNING: Running in DEBUG mode!")
        print("This should NEVER be used in production.")
        print("Set FLASK_CONFIG=production for production deployment.")
        print("="*60 + "\n")
    
    # Get port from environment or default to 5000
    port = int(os.environ.get('PORT', 5000))
    
    # Run the application
    # Note: For production, use a proper WSGI server like Gunicorn
    
    app.run(
        host='127.0.0.1',  # Change to '0.0.0.0' if you need external access
        port=port,
        debug=app.config.get('DEBUG', False),
        threaded=True  # Enable threading for better performance
    )
