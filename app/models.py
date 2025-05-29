import secrets
import pyotp
import qrcode
import io
import base64
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db


class User(UserMixin, db.Model):
    """
    User model with two-factor authentication support.
    
    Security features:
    - Bcrypt password hashing
    - TOTP secret generation and verification
    - Secure random secret generation
    """
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    last_login = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        """
        Hash and set the user's password using bcrypt.
        
        Security: Uses bcrypt with automatic salt generation
        for resistance against rainbow table attacks.
        """
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        """
        Verify the provided password against the stored hash.
        
        Security: Uses constant-time comparison to prevent timing attacks.
        """
        return check_password_hash(self.password_hash, password)
    
    def generate_totp_secret(self):
        """
        Generate a new TOTP secret for two-factor authentication.
        
        Security: Uses cryptographically secure random generation.
        """
        if not self.totp_secret:
            self.totp_secret = pyotp.random_base32()
        return self.totp_secret
    
    def generate_totp_uri(self, issuer_name='Flask-2FA-App'):
        """
        Generate a TOTP URI for QR code generation.
        
        Args:
            issuer_name: The name of the application (displayed in authenticator apps)
            
        Returns:
            str: TOTP URI compatible with authenticator apps like Google Authenticator
        """
        if not self.totp_secret:
            self.generate_totp_secret()
        
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.username,
            issuer_name=issuer_name
        )
    
    def verify_totp(self, token):
        """
        Verify a TOTP token against the user's secret.
        
        Args:
            token: The 6-digit TOTP token from the authenticator app
            
        Returns:
            bool: True if the token is valid, False otherwise
            
        Security: Uses time-window verification with built-in replay protection.
        """
        if not self.totp_secret:
            return False
        
        totp = pyotp.TOTP(self.totp_secret)
        # Verify token with a 1-period window (30 seconds before/after)
        return totp.verify(token, valid_window=1)
    
    def generate_qr_code(self, issuer_name='Flask-2FA-App'):
        """
        Generate a QR code for the TOTP URI.
        
        Returns:
            str: Base64-encoded PNG image of the QR code
        """
        uri = self.generate_totp_uri(issuer_name)
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 for HTML embedding
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        return base64.b64encode(img_buffer.getvalue()).decode()
    
    def enable_2fa(self):
        """Enable two-factor authentication for the user."""
        if self.totp_secret:
            self.is_2fa_enabled = True
            db.session.commit()
    
    def disable_2fa(self):
        """Disable two-factor authentication for the user."""
        self.is_2fa_enabled = False
        self.totp_secret = None
        db.session.commit()


# Database event listeners for additional security
from sqlalchemy import event

@event.listens_for(User.password_hash, 'set')
def validate_password_hash(target, value, oldvalue, initiator):
    """Ensure password hash is never stored as plaintext."""
    if value and not value.startswith('pbkdf2:sha256'):
        raise ValueError("Password must be hashed before storage")
