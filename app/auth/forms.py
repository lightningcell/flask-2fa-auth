from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from app.models import User


class RegistrationForm(FlaskForm):
    """
    User registration form with validation.
    
    Security: CSRF protection enabled automatically by Flask-WTF.
    """
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=20, message='Username must be between 3 and 20 characters.')
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message='Invalid email address.')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long.')
    ])
    password2 = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        """
        Custom validator to check username uniqueness.
        
        Security: Uses parameterized query to prevent SQL injection.
        """
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')
    
    def validate_email(self, email):
        """
        Custom validator to check email uniqueness.
        
        Security: Uses parameterized query to prevent SQL injection.
        """
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please choose a different one.')


class LoginForm(FlaskForm):
    """
    User login form.
    
    Security: CSRF protection enabled automatically by Flask-WTF.
    """
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class TwoFactorForm(FlaskForm):
    """
    Two-factor authentication verification form.
    
    Security: CSRF protection enabled automatically by Flask-WTF.
    """
    token = StringField('Authentication Code', validators=[
        DataRequired(),
        Length(min=6, max=6, message='Authentication code must be 6 digits.')
    ])
    submit = SubmitField('Verify')
    
    def validate_token(self, token):
        """Validate that token contains only digits."""
        if not token.data.isdigit():
            raise ValidationError('Authentication code must contain only digits.')
