from flask import render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, current_user, login_required
from urllib.parse import urlparse
from datetime import datetime, timedelta
from app import db
from app.auth import bp
from app.auth.forms import RegistrationForm, LoginForm, TwoFactorForm
from app.models import User, LoginLocation, LocationApprovalToken
from app.utils.location import location_service
from app.utils.mail import mail_service
import logging

# Configure logging for security events
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    User registration endpoint with 2FA setup.
    
    Security features:
    - CSRF protection via Flask-WTF
    - Password hashing via bcrypt
    - Input validation and sanitization
    - SQL injection prevention via parameterized queries
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            # Create new user with hashed password
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)
            
            # Generate TOTP secret for 2FA
            user.generate_totp_secret()
            
            # Save user to database
            db.session.add(user)
            db.session.commit()
            
            # Log successful registration (without sensitive data)
            logger.info(f'New user registered: {user.username}')
            
            flash('Registration successful! Please scan the QR code with your authenticator app.', 'success')
            
            # Store user ID in session for QR code display
            session['temp_user_id'] = user.id
            
            return redirect(url_for('auth.setup_2fa'))
            
        except Exception as e:
            # Rollback transaction on error
            db.session.rollback()
            logger.error(f'Registration error for user {form.username.data}: {str(e)}')
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('auth/register.html', form=form, title='Register')


@bp.route('/setup-2fa')
def setup_2fa():
    """
    Display QR code for 2FA setup after registration.
    
    Security: Requires temp_user_id in session to prevent unauthorized access.
    """
    user_id = session.get('temp_user_id')
    if not user_id:
        flash('Invalid session. Please register again.', 'error')
        return redirect(url_for('auth.register'))
    
    user = User.query.get(user_id)
    if not user:
        flash('User not found. Please register again.', 'error')
        return redirect(url_for('auth.register'))
    
    # Generate QR code for Google Authenticator
    qr_code = user.generate_qr_code()
    
    # Clear temp session data
    session.pop('temp_user_id', None)
    
    return render_template('auth/setup_2fa.html', 
                         qr_code=qr_code, 
                         username=user.username,
                         title='Setup Two-Factor Authentication')


@bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    User login endpoint with first-factor authentication.
    
    Security features:
    - CSRF protection via Flask-WTF
    - Secure password verification
    - Session protection
    - Login attempt logging
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        # Use parameterized query to prevent SQL injection
        user = User.query.filter_by(username=form.username.data).first()
        
        if user is None or not user.check_password(form.password.data):
            # Log failed login attempt
            logger.warning(f'Failed login attempt for username: {form.username.data}')
            flash('Invalid username or password', 'error')
            return redirect(url_for('auth.login'))
        
        # Store user ID in session for 2FA verification
        session['temp_user_id'] = user.id
        session['remember_me'] = form.remember_me.data
        
        # Log successful first-factor authentication
        logger.info(f'First-factor authentication successful for user: {user.username}')
        
        # Redirect to 2FA verification
        flash('Please enter your authentication code', 'info')
        return redirect(url_for('auth.verify_otp'))
    
    return render_template('auth/login.html', form=form, title='Sign In')


@bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    """
    Second-factor authentication endpoint using TOTP.
    
    Security features:
    - CSRF protection via Flask-WTF
    - Time-based token verification
    - Session validation
    - Replay attack protection (built into PyOTP)
    """
    user_id = session.get('temp_user_id')
    if not user_id:
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('auth.login'))
    
    user = User.query.get(user_id)
    if not user:
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('auth.login'))
    
    form = TwoFactorForm()
    if form.validate_on_submit():
        if user.verify_totp(form.token.data):
            # Enable 2FA if this is the first successful verification
            if not user.is_2fa_enabled:
                user.enable_2fa()
            
            # Track login location
            success = track_login_location(user)
            
            # Update last login timestamp
            user.last_login = db.func.current_timestamp()
            db.session.commit()
            
            # Clear temp session data
            remember_me = session.pop('remember_me', False)
            session.pop('temp_user_id', None)
            
            # Complete login process
            login_user(user, remember=remember_me)
            
            # Show appropriate message based on location tracking
            if success:
                flash('Login successful!', 'success')
            else:
                flash('Login successful! Check your email for location verification.', 'info')
            
            # Log successful login
            logger.info(f'Successful login for user: {user.username}')
            
            # Redirect to originally requested page or dashboard
            next_page = request.args.get('next')
            if not next_page or urlparse(next_page).netloc != '':
                next_page = url_for('main.index')
            return redirect(next_page)
        else:
            # Log failed 2FA attempt
            logger.warning(f'Failed 2FA verification for user: {user.username}')
            flash('Invalid authentication code. Please try again.', 'error')
    
    return render_template('auth/verify_otp.html', form=form, title='Two-Factor Authentication')


@bp.route('/logout')
@login_required
def logout():
    """
    User logout endpoint.
    
    Security: Properly clears session and logs security event.
    """
    username = current_user.username if current_user.is_authenticated else 'Unknown'
    logout_user()
    
    # Clear any remaining session data
    session.clear()
    
    # Log logout event
    logger.info(f'User logged out: {username}')
    
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('main.index'))


@bp.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    """
    Disable two-factor authentication for the current user.
    
    Security: Requires active login session and POST request.
    """
    try:
        current_user.disable_2fa()
        logger.info(f'2FA disabled for user: {current_user.username}')
        flash('Two-factor authentication has been disabled.', 'warning')
    except Exception as e:
        logger.error(f'Error disabling 2FA for user {current_user.username}: {str(e)}')
        flash('Failed to disable two-factor authentication.', 'error')
    
    return redirect(url_for('main.profile'))


@bp.route('/enable-2fa')
@login_required
def enable_2fa():
    """
    Enable 2FA for existing logged-in users.
    
    Security: Requires active login session.
    """
    if current_user.is_2fa_enabled:
        flash('Two-factor authentication is already enabled for your account.', 'info')
        return redirect(url_for('main.profile'))
    
    # Generate new TOTP secret if not exists
    if not current_user.totp_secret:
        current_user.generate_totp_secret()
        db.session.commit()
    
    # Generate QR code for Google Authenticator
    qr_code = current_user.generate_qr_code()
    
    return render_template('auth/enable_2fa.html', 
                         qr_code=qr_code, 
                         username=current_user.username,
                         title='Enable Two-Factor Authentication')


@bp.route('/verify-enable-2fa', methods=['POST'])
@login_required
def verify_enable_2fa():
    """
    Verify TOTP token and enable 2FA for existing user.
    
    Security: Requires active login session and valid TOTP token.
    """
    if current_user.is_2fa_enabled:
        flash('Two-factor authentication is already enabled.', 'info')
        return redirect(url_for('main.profile'))
    
    token = request.form.get('token', '').strip()
    
    if not token:
        flash('Please enter the authentication code.', 'error')
        return redirect(url_for('auth.enable_2fa'))
    
    if current_user.verify_totp(token):
        # Enable 2FA for the user
        current_user.enable_2fa()
        
        logger.info(f'2FA enabled for user: {current_user.username}')
        flash('Two-factor authentication has been successfully enabled!', 'success')
        
        return redirect(url_for('main.profile'))
    else:
        logger.warning(f'Failed 2FA enable verification for user: {current_user.username}')
        flash('Invalid authentication code. Please try again.', 'error')
        return redirect(url_for('auth.enable_2fa'))


def track_login_location(user):
    """
    Track user login location and handle suspicious login detection.
    
    Args:
        user: User object
        
    Returns:
        bool: True if location is trusted, False if suspicious (email sent)
    """
    try:
        # Get current IP and location data
        ip_address = location_service.get_client_ip()
        user_agent = location_service.get_user_agent()
        location_data = location_service.get_location_from_ip(ip_address)
        
        # Check if location is suspicious
        is_suspicious, last_location = location_service.is_suspicious_location(
            user.id, location_data
        )
        
        # Create login location record
        login_location = LoginLocation(
            user_id=user.id,
            ip_address=ip_address,
            country=location_data.get('country'),
            region=location_data.get('region'),
            city=location_data.get('city'),
            latitude=location_data.get('latitude'),
            longitude=location_data.get('longitude'),
            user_agent=user_agent,
            is_approved=not is_suspicious,
            is_suspicious=is_suspicious
        )
        
        db.session.add(login_location)
        db.session.commit()
        
        # Handle suspicious login
        if is_suspicious:
            # Create approval token
            token = LocationApprovalToken.generate_token()
            approval_token = LocationApprovalToken(
                user_id=user.id,
                location_id=login_location.id,
                token=token,
                expires_at=datetime.utcnow() + timedelta(hours=24)
            )
            
            db.session.add(approval_token)
            db.session.commit()
            
            # Prepare location data for email
            email_location_data = {
                'city': location_data.get('city'),
                'region': location_data.get('region'),
                'country': location_data.get('country'),
                'ip_address': ip_address,
                'distance_km': last_location.get('distance_km') if last_location else None
            }
            
            # Send suspicious login alert email
            mail_service.send_suspicious_login_alert(
                user.email,
                user.username,
                email_location_data,
                token
            )
            
            logger.warning(f"Suspicious login detected for user {user.username} from {location_data.get('city', 'Unknown')}")
            return False
        
        logger.info(f"Trusted location login for user {user.username} from {location_data.get('city', 'Unknown')}")
        return True
        
    except Exception as e:
        logger.error(f"Error tracking login location for user {user.username}: {str(e)}")
        # On error, allow login but log the issue
        return True


@bp.route('/approve-location/<token>')
def approve_location(token):
    """
    Approve a suspicious login location via email link.
    
    Args:
        token: Location approval token from email
    """
    try:
        # Find and validate token
        approval_token = LocationApprovalToken.query.filter_by(token=token).first()
        
        if not approval_token:
            flash('Invalid or expired approval link.', 'error')
            return redirect(url_for('main.index'))
        
        if not approval_token.is_valid():
            flash('This approval link has expired or already been used.', 'error')
            return redirect(url_for('main.index'))
        
        # Mark location as approved
        location = approval_token.location
        location.is_approved = True
        location.is_suspicious = False
        location.approved_at = datetime.utcnow()
        
        # Mark token as used
        approval_token.is_used = True
        approval_token.used_at = datetime.utcnow()
        
        db.session.commit()
        
        # Send confirmation email
        user = approval_token.user
        location_data = {
            'city': location.city,
            'region': location.region,
            'country': location.country
        }
        
        mail_service.send_location_approved_notification(
            user.email,
            user.username,
            location_data
        )
        
        logger.info(f"Location approved for user {user.username}: {location.location_display}")
        flash('Location approved successfully! This location is now trusted.', 'success')
        
    except Exception as e:
        logger.error(f"Error approving location with token {token}: {str(e)}")
        flash('An error occurred while approving the location.', 'error')
    
    return redirect(url_for('main.index'))


@bp.route('/login-history')
@login_required
def login_history():
    """
    Display user's login history and location data.
    """
    try:
        # Get user's login locations ordered by most recent
        locations = LoginLocation.query.filter_by(
            user_id=current_user.id
        ).order_by(LoginLocation.login_time.desc()).limit(50).all()
        
        return render_template('auth/login_history.html', 
                             locations=locations, 
                             title='Login History')
        
    except Exception as e:
        logger.error(f"Error loading login history for user {current_user.username}: {str(e)}")
        flash('Error loading login history.', 'error')
        return redirect(url_for('main.dashboard'))
