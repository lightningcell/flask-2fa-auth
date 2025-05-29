# Flask 2FA Authentication Application

A secure Flask web application implementing two-factor authentication (2FA) with industry best practices for web security.

## 🔒 Security Features

- **Two-Factor Authentication**: TOTP-based 2FA using PyOTP
- **Secure Password Storage**: Bcrypt hashing with automatic salt generation
- **CSRF Protection**: Automatic token validation on all forms
- **SQL Injection Prevention**: Parameterized queries with SQLAlchemy ORM
- **XSS Protection**: Automatic template escaping and CSP headers
- **Secure Session Management**: HTTPOnly, Secure, and SameSite cookie flags
- **Security Headers**: HSTS, X-Frame-Options, X-Content-Type-Options
- **Input Validation**: Server-side validation with WTForms
- **Secure Configuration**: Environment-based configuration management

## 🚀 Quick Start

### Prerequisites

- Python 3.9 or higher
- pip (Python package installer)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd flask-2fa-auth
   ```

2. **Create and activate virtual environment**
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate

   # macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   # Copy the example environment file
   copy .env.example .env

   # Edit .env file with your configuration
   # At minimum, change the SECRET_KEY for production
   ```

5. **Initialize the database**
   ```bash
   flask db init
   flask db migrate -m "Initial migration"
   flask db upgrade
   ```

6. **Run the application**
   ```bash
   python run.py
   ```

   The application will be available at `http://127.0.0.1:5000`

## 📱 2FA Setup Process

1. **Register**: Create a new account with username, email, and password
2. **Scan QR Code**: Use Google Authenticator, Authy, or similar app to scan the QR code
3. **Verify**: Enter the 6-digit code from your authenticator app
4. **Login**: Use your credentials + 2FA code for future logins

### Supported Authenticator Apps

- Google Authenticator
- Microsoft Authenticator  
- Authy
- 1Password
- LastPass Authenticator
- Any TOTP-compatible app

## 🛠️ Project Structure

```
flask-2fa-auth/
├── app/
│   ├── __init__.py          # Application factory
│   ├── models.py            # User model with 2FA methods
│   ├── auth/                # Authentication blueprint
│   │   ├── __init__.py
│   │   ├── routes.py        # Auth routes (register, login, verify)
│   │   └── forms.py         # WTForms form classes
│   ├── main/                # Main application blueprint
│   │   ├── __init__.py
│   │   └── routes.py        # Main routes (dashboard, profile)
│   └── templates/           # Jinja2 templates
│       ├── base.html        # Base template with security headers
│       ├── index.html       # Home page
│       ├── dashboard.html   # User dashboard
│       ├── profile.html     # User profile
│       └── auth/            # Authentication templates
│           ├── register.html
│           ├── login.html
│           ├── verify_otp.html
│           └── setup_2fa.html
├── config.py                # Configuration classes
├── requirements.txt         # Python dependencies
├── run.py                   # Application entry point
├── .env.example            # Environment variables template
└── README.md               # This file
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_CONFIG` | Configuration environment | `development` |
| `SECRET_KEY` | Flask secret key (CHANGE IN PRODUCTION!) | Auto-generated |
| `DATABASE_URL` | Database connection string | `sqlite:///app.db` |
| `DEBUG` | Enable debug mode | `True` |

### Configuration Classes

- **DevelopmentConfig**: Debug enabled, SQLite database
- **ProductionConfig**: Debug disabled, PostgreSQL recommended
- **TestingConfig**: In-memory database, CSRF disabled

## 🚀 Deployment

### Production Checklist

- [ ] Change `SECRET_KEY` to a cryptographically secure random value
- [ ] Set `FLASK_CONFIG=production`
- [ ] Use PostgreSQL or similar production database
- [ ] Enable HTTPS with valid SSL certificate
- [ ] Set secure environment variables
- [ ] Use a proper WSGI server (Gunicorn, uWSGI)
- [ ] Configure reverse proxy (Nginx, Apache)
- [ ] Set up monitoring and logging
- [ ] Regular security updates

### Example Production Deployment

```bash
# Install production dependencies
pip install gunicorn

# Set production environment
export FLASK_CONFIG=production
export SECRET_KEY="your-super-secure-random-key"
export DATABASE_URL="postgresql://user:pass@localhost/flask_2fa_prod"

# Run database migrations
flask db upgrade

# Start with Gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 run:app
```

## 🛡️ Security Considerations

### Authentication Security
- Passwords are hashed using bcrypt with automatic salt generation
- TOTP tokens expire every 30 seconds with built-in replay protection
- Failed login attempts are logged for security monitoring
- Session protection prevents session fixation attacks

### Web Security
- CSRF tokens protect against cross-site request forgery
- Security headers prevent clickjacking and XSS attacks
- Input validation prevents injection attacks
- Secure cookie settings protect session data

### Database Security
- Parameterized queries prevent SQL injection
- Connection pooling with proper timeouts
- Database credentials stored in environment variables

### Operational Security
- Security events logged for monitoring
- Environment-based configuration
- Separate development and production configurations

## 📚 API Reference

### User Model Methods

```python
user = User(username="john", email="john@example.com")

# Password management
user.set_password("secure_password")
user.check_password("password_to_verify")

# 2FA management
user.generate_totp_secret()
user.generate_totp_uri("MyApp")
user.verify_totp("123456")
user.generate_qr_code("MyApp")
user.enable_2fa()
user.disable_2fa()
```

### Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Home page |
| `/auth/register` | GET, POST | User registration |
| `/auth/login` | GET, POST | User login (first factor) |
| `/auth/verify-otp` | GET, POST | 2FA verification |
| `/auth/setup-2fa` | GET | QR code for 2FA setup |
| `/auth/logout` | GET | User logout |
| `/dashboard` | GET | User dashboard (protected) |
| `/profile` | GET | User profile (protected) |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation as needed
- Ensure security best practices are maintained

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

If you encounter any issues:

1. Check the [Issues](../../issues) page for existing solutions
2. Create a new issue with detailed information
3. Include error messages and steps to reproduce

## 🔗 Resources

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Flask-Login Documentation](https://flask-login.readthedocs.io/)
- [PyOTP Documentation](https://pypi.org/project/pyotp/)
- [OWASP Security Guidelines](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST 2FA Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

**⚠️ Security Notice**: This application implements security best practices, but security is an ongoing process. Always keep dependencies updated, monitor for vulnerabilities, and follow current security guidelines for production deployments.
