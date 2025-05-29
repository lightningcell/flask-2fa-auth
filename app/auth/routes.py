from flask import render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, current_user, login_required
from urllib.parse import urlparse
from app import db
from app.auth import bp
from app.auth.forms import RegistrationForm, LoginForm, TwoFactorForm
from app.models import User
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
            
            # Update last login timestamp
            user.last_login = db.func.current_timestamp()
            db.session.commit()
            
            # Clear temp session data
            remember_me = session.pop('remember_me', False)
            session.pop('temp_user_id', None)
            
            # Complete login process
            login_user(user, remember=remember_me)
            
            # Log successful login
            logger.info(f'Successful login for user: {user.username}')
            
            flash('Login successful!', 'success')
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
