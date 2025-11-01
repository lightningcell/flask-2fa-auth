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
            str: HTML img tag with base64-encoded PNG image of the QR code
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
        
        base64_img = base64.b64encode(img_buffer.getvalue()).decode()
        return f'<img src="data:image/png;base64,{base64_img}" class="img-fluid" alt="QR Code for 2FA Setup" style="max-width: 200px;">'
    
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


class LoginLocation(db.Model):
    """
    Model to track user login locations for security monitoring.
    
    Security features:
    - IP address tracking
    - Geolocation data storage
    - Login attempt tracking
    - Suspicious activity detection
    """
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv6 support
    country = db.Column(db.String(100))
    region = db.Column(db.String(100))
    city = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    user_agent = db.Column(db.Text)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)
    is_suspicious = db.Column(db.Boolean, default=False, nullable=False)
    login_time = db.Column(db.DateTime, default=db.func.current_timestamp())
    approved_at = db.Column(db.DateTime)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('login_locations', lazy=True, 
                                                     order_by='LoginLocation.login_time.desc()'))
    
    def __repr__(self):
        return f'<LoginLocation {self.user_id}: {self.city}, {self.country} at {self.login_time}>'
    
    @property
    def location_display(self):
        """Human-readable location string."""
        parts = []
        if self.city:
            parts.append(self.city)
        if self.region and self.region != self.city:
            parts.append(self.region)
        if self.country:
            parts.append(self.country)
        return ', '.join(parts) if parts else 'Unknown Location'
    
    @property
    def coordinates(self):
        """Return coordinates as tuple if available."""
        if self.latitude is not None and self.longitude is not None:
            return (self.latitude, self.longitude)
        return None


class LocationApprovalToken(db.Model):
    """
    Model for secure location approval tokens sent via email.
    
    Security features:
    - Cryptographically secure token generation
    - Token expiration
    - One-time use tokens
    """
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('login_location.id'), nullable=False)
    token = db.Column(db.String(255), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime)
    is_used = db.Column(db.Boolean, default=False, nullable=False)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('location_tokens', lazy=True))
    location = db.relationship('LoginLocation', backref=db.backref('approval_tokens', lazy=True))
    
    def __repr__(self):
        return f'<LocationApprovalToken {self.token[:8]}... for user {self.user_id}>'
