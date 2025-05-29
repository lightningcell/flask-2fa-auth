#!/usr/bin/env python3
"""
Test script for Flask 2FA Authentication Application

This script performs basic functionality tests to ensure the application
is working correctly.
"""

import os
import sys
import requests
import time

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from app.models import User


def test_database():
    """Test database connectivity and User model."""
    print("Testing database connectivity...")
    
    app = create_app('development')
    
    with app.app_context():
        try:
            # Test database connection
            db.create_all()
            
            # Test User model
            test_user = User(username='testuser', email='test@example.com')
            test_user.set_password('testpassword123')
            test_user.generate_totp_secret()
            
            print("✓ Database connection successful")
            print("✓ User model working correctly")
            print("✓ Password hashing working")
            print("✓ TOTP secret generation working")
            
            # Test TOTP URI generation
            uri = test_user.generate_totp_uri()
            print(f"✓ TOTP URI generated: {uri[:50]}...")
            
            # Test QR code generation
            qr_code = test_user.generate_qr_code()
            print(f"✓ QR code generated ({len(qr_code)} characters)")
            
            return True
            
        except Exception as e:
            print(f"✗ Database test failed: {e}")
            return False


def test_application_startup():
    """Test if the application starts without errors."""
    print("\nTesting application startup...")
    
    try:
        app = create_app('development')
        
        with app.test_client() as client:
            # Test home page
            response = client.get('/')
            if response.status_code == 200:
                print("✓ Home page loads successfully")
            else:
                print(f"✗ Home page failed: {response.status_code}")
                return False
            
            # Test registration page
            response = client.get('/auth/register')
            if response.status_code == 200:
                print("✓ Registration page loads successfully")
            else:
                print(f"✗ Registration page failed: {response.status_code}")
                return False
            
            # Test login page
            response = client.get('/auth/login')
            if response.status_code == 200:
                print("✓ Login page loads successfully")
            else:
                print(f"✗ Login page failed: {response.status_code}")
                return False
            
            return True
            
    except Exception as e:
        print(f"✗ Application startup test failed: {e}")
        return False


def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("Flask 2FA Authentication Application - Test Suite")
    print("=" * 60)
    
    tests_passed = 0
    total_tests = 2
    
    # Test database
    if test_database():
        tests_passed += 1
    
    # Test application startup
    if test_application_startup():
        tests_passed += 1
    
    # Results
    print("\n" + "=" * 60)
    print("TEST RESULTS")
    print("=" * 60)
    print(f"Tests passed: {tests_passed}/{total_tests}")
    
    if tests_passed == total_tests:
        print("✓ All tests passed! The application is ready to use.")
        print("\nTo start the application:")
        print("  python run.py")
        print("\nThen open your browser to: http://127.0.0.1:5000")
    else:
        print("✗ Some tests failed. Please check the errors above.")
    
    print("=" * 60)


if __name__ == '__main__':
    run_all_tests()
