#!/usr/bin/env python3
"""
Database initialization script for Flask 2FA Authentication Application

This script creates the database tables and sets up the initial schema.
"""

import os
import sys

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from app.models import User


def init_database():
    """Initialize the database with tables."""
    app = create_app('development')
    
    with app.app_context():
        print("Creating database tables...")
        
        # Create all tables
        db.create_all()
        
        print("Database tables created successfully!")
        
        # Show created tables
        print("\nCreated tables:")
        print("- User table with columns:")
        print("  - id (Primary Key)")
        print("  - username (Unique)")
        print("  - email (Unique)")
        print("  - password_hash")
        print("  - totp_secret")
        print("  - is_2fa_enabled")
        print("  - created_at")
        print("  - last_login")
        
        print("\nDatabase initialization complete!")
        print("You can now run the application with: python run.py")


if __name__ == '__main__':
    init_database()
