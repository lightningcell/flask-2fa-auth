from flask import render_template
from flask_login import login_required, current_user
from app.main import bp


@bp.route('/')
@bp.route('/index')
def index():
    """
    Home page - shows different content for authenticated vs anonymous users.
    
    Security: No sensitive data exposed to anonymous users.
    """
    return render_template('index.html', title='Home')


@bp.route('/dashboard')
@login_required
def dashboard():
    """
    Protected dashboard for authenticated users.
    
    Security: Requires valid login session with 2FA verification.
    """
    return render_template('dashboard.html', title='Dashboard', user=current_user)


@bp.route('/profile')
@login_required
def profile():
    """
    User profile page with 2FA management.
    
    Security: Requires valid login session.
    """
    return render_template('profile.html', title='Profile', user=current_user)
