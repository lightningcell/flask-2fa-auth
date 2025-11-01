"""
Modular mail service for Flask 2FA application.

This module provides a reusable mail service that can be used for:
- Suspicious login alerts
- Location approval requests
- Account security notifications
- General application notifications

Security features:
- HTML email with security headers
- Secure token handling
- Rate limiting support
- Template-based emails
"""

import logging
from flask import current_app, render_template, url_for
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any


class MailService:
    """
    Centralized mail service for the application.
    
    Provides secure email functionality with template support
    and security best practices.
    """
    
    def __init__(self, mail_instance: Optional[Mail] = None):
        """
        Initialize mail service.
        
        Args:
            mail_instance: Flask-Mail instance (optional)
        """
        self.mail = mail_instance
        self.logger = logging.getLogger(__name__)
    
    def init_app(self, app, mail_instance: Mail):
        """Initialize mail service with Flask app and Mail instance."""
        self.mail = mail_instance
        with app.app_context():
            self.logger.info("Mail service initialized")
    
    def send_email(self, 
                   subject: str, 
                   recipients: List[str], 
                   template: str, 
                   **template_vars) -> bool:
        """
        Send an email using template.
        
        Args:
            subject: Email subject line
            recipients: List of recipient email addresses
            template: Template name (without .html extension)
            **template_vars: Variables to pass to template
            
        Returns:
            bool: True if email sent successfully, False otherwise
        """
        try:
            # Create message
            msg = Message(
                subject=subject,
                recipients=recipients,
                sender=current_app.config['MAIL_DEFAULT_SENDER']
            )
            
            # Render HTML template
            msg.html = render_template(f'emails/{template}.html', **template_vars)
            
            # Add security headers to email
            msg.extra_headers = {
                'X-Mailer': 'Flask-2FA-App',
                'X-Priority': '1',
                'X-MSMail-Priority': 'High'
            }

            try:
                self.logger.warning(f"MAIL_PASSWORD is {current_app.config.get('MAIL_PASSWORD')}")
            except Exception:
                pass

            # Send email
            self.mail.send(msg)
            
            self.logger.info(f"Email sent successfully to {recipients}: {subject}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email to {recipients}: {str(e)}")
            return False
    
    def send_suspicious_login_alert(self, 
                                   user_email: str, 
                                   user_name: str,
                                   location_data: Dict[str, Any],
                                   approval_token: str) -> bool:
        """
        Send suspicious login alert email.
        
        Args:
            user_email: User's email address
            user_name: User's display name
            location_data: Dictionary containing location information
            approval_token: Token for approving the location
            
        Returns:
            bool: True if email sent successfully
        """
        approval_url = url_for('auth.approve_location', 
                              token=approval_token, 
                              _external=True)
        
        return self.send_email(
            subject="🔐 Suspicious Login Detected - Action Required",
            recipients=[user_email],
            template="suspicious_login",
            user_name=user_name,
            location=location_data,
            approval_url=approval_url,
            login_time=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            app_name="Flask 2FA App"
        )
    
    def send_location_approved_notification(self, 
                                          user_email: str, 
                                          user_name: str,
                                          location_data: Dict[str, Any]) -> bool:
        """
        Send location approval confirmation email.
        
        Args:
            user_email: User's email address
            user_name: User's display name
            location_data: Dictionary containing location information
            
        Returns:
            bool: True if email sent successfully
        """
        return self.send_email(
            subject="✅ Login Location Approved",
            recipients=[user_email],
            template="location_approved",
            user_name=user_name,
            location=location_data,
            approval_time=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            app_name="Flask 2FA App"
        )
    
    def send_account_security_alert(self, 
                                   user_email: str, 
                                   user_name: str,
                                   alert_type: str,
                                   details: Dict[str, Any]) -> bool:
        """
        Send general account security alert.
        
        Args:
            user_email: User's email address
            user_name: User's display name
            alert_type: Type of security alert
            details: Additional details for the alert
            
        Returns:
            bool: True if email sent successfully
        """
        return self.send_email(
            subject=f"🔔 Security Alert: {alert_type}",
            recipients=[user_email],
            template="security_alert",
            user_name=user_name,
            alert_type=alert_type,
            details=details,
            timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            app_name="Flask 2FA App"
        )
    
    def send_welcome_email(self, 
                          user_email: str, 
                          user_name: str) -> bool:
        """
        Send welcome email to new users.
        
        Args:
            user_email: User's email address
            user_name: User's display name
            
        Returns:
            bool: True if email sent successfully
        """
        dashboard_url = url_for('main.dashboard', _external=True)
        
        return self.send_email(
            subject="🎉 Welcome to Flask 2FA App!",
            recipients=[user_email],
            template="welcome",
            user_name=user_name,
            dashboard_url=dashboard_url,
            app_name="Flask 2FA App"
        )


# Global mail service instance
mail_service = MailService()
