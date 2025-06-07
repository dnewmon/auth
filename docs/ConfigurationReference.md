# Configuration Reference

## Overview

This document provides comprehensive documentation for all configuration options in the authentication and credential management system. The application uses environment-based configuration with support for multiple deployment environments.

## Configuration Structure

### Environment Files

The application loads configuration from the following sources (in order of precedence):

1. **Environment variables** (highest priority)
2. **`.env` files** in the project root
3. **Default configuration values** (lowest priority)

### Configuration Classes

**File:** `config.py`

The application supports three configuration environments:

- `DevelopmentConfig` - Local development
- `ProductionConfig` - Production deployment  
- `TestingConfig` - Unit testing

## Core Configuration Options

### Application Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECRET_KEY` | String | **Required** | Flask secret key for sessions and CSRF |
| `DEBUG` | Boolean | Environment-dependent | Enable Flask debug mode |
| `TESTING` | Boolean | Environment-dependent | Enable testing mode |
| `LOG_LEVEL` | String | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |

### Database Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DATABASE_URL` | String | SQLite file | Full database connection string |
| `SQLALCHEMY_DATABASE_URI` | String | Derived from DATABASE_URL | SQLAlchemy connection string |
| `SQLALCHEMY_TRACK_MODIFICATIONS` | Boolean | `False` | Track object modifications (performance) |

#### Database URL Examples

```bash
# SQLite (Development)
DATABASE_URL=sqlite:///instance/app.db

# PostgreSQL (Production)
DATABASE_URL=postgresql://user:password@localhost:5432/authdb

# MySQL (Alternative)
DATABASE_URL=mysql://user:password@localhost:3306/authdb
```

### Security Configuration

#### Password Security

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MIN_PASSWORD_LENGTH` | Integer | `12` | Minimum password length requirement |
| `ARGON2_TIME_COST` | Integer | `3` | Argon2 time cost parameter |
| `ARGON2_MEMORY_COST` | Integer | `65536` | Argon2 memory cost (64MB) |
| `ARGON2_PARALLELISM` | Integer | `4` | Argon2 parallel threads |
| `ARGON2_HASH_LENGTH` | Integer | `32` | Argon2 hash output length |
| `ARGON2_SALT_LENGTH` | Integer | `16` | Argon2 salt length |

#### Encryption Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ENCRYPTION_KEY_LENGTH` | Integer | `32` | Master encryption key length (AES-256) |
| `ENCRYPTION_NONCE_LENGTH` | Integer | `12` | AES-GCM nonce length |
| `PBKDF2_ITERATIONS` | Integer | `600000` | PBKDF2 iteration count (OWASP 2023) |
| `PBKDF2_SALT_LENGTH` | Integer | `16` | PBKDF2 salt length |

#### Session Management

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SESSION_COOKIE_SECURE` | Boolean | Environment-dependent | Require HTTPS for cookies |
| `SESSION_COOKIE_HTTPONLY` | Boolean | `True` | Prevent JavaScript cookie access |
| `SESSION_COOKIE_SAMESITE` | String | `Lax` | SameSite cookie attribute |
| `PERMANENT_SESSION_LIFETIME` | Integer | `3600` | Session lifetime in seconds |

### Multi-Factor Authentication

#### TOTP Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `OTP_ISSUER_NAME` | String | `SecureAuth` | TOTP issuer name for authenticator apps |
| `OTP_SECRET_LENGTH` | Integer | `32` | TOTP secret length (base32) |
| `TOTP_VALIDITY_WINDOW` | Integer | `1` | Time window for TOTP validation |

#### Email MFA Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MFA_CODE_LENGTH` | Integer | `6` | Email verification code length |
| `MFA_CODE_EXPIRY_MINUTES` | Integer | `10` | Email code expiration time |
| `EMAIL_VERIFICATION_EXPIRY_HOURS` | Integer | `24` | Email verification token expiry |

### Email Configuration

#### SMTP Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MAIL_SERVER` | String | **Required** | SMTP server hostname |
| `MAIL_PORT` | Integer | `587` | SMTP server port |
| `MAIL_USE_TLS` | Boolean | `True` | Enable TLS encryption |
| `MAIL_USE_SSL` | Boolean | `False` | Enable SSL encryption |
| `MAIL_USERNAME` | String | **Required** | SMTP authentication username |
| `MAIL_PASSWORD` | String | **Required** | SMTP authentication password |
| `MAIL_DEFAULT_SENDER` | String | **Required** | Default sender email address |

#### Email Templates

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `EMAIL_WELCOME_TEMPLATE` | String | `email/welcome_verification.html` | Welcome email template |
| `EMAIL_RESET_TEMPLATE` | String | `email/reset_password.html` | Password reset template |
| `EMAIL_LOGIN_TEMPLATE` | String | `email/login_notification.html` | Login notification template |
| `EMAIL_MFA_TEMPLATE` | String | `email/mfa_login_code.html` | MFA code template |
| `EMAIL_MFA_TEST_TEMPLATE` | String | `email/mfa_test.html` | MFA test template |
| `EMAIL_MFA_DISABLE_TEMPLATE` | String | `email/mfa_disable_code.html` | MFA disable template |
| `EMAIL_MFA_ENABLED_TEMPLATE` | String | `email/mfa_enabled.html` | MFA enabled notification |
| `EMAIL_OTP_ENABLED_TEMPLATE` | String | `email/otp_enabled.html` | OTP enabled notification |
| `EMAIL_OTP_DISABLED_TEMPLATE` | String | `email/otp_disabled.html` | OTP disabled notification |

### Rate Limiting

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RATELIMIT_STORAGE_URI` | String | `memory://` | Rate limit storage backend |
| `RATELIMIT_DEFAULT` | String | `100 per hour` | Default rate limit |
| `RATELIMIT_ENABLED` | Boolean | Environment-dependent | Enable rate limiting |

#### Endpoint-Specific Limits

Rate limits are configured per endpoint in the code:

- **Registration**: `5 per hour`
- **Login**: `10 per minute`
- **Password Reset**: `3 per hour`
- **MFA Operations**: `10 per minute`
- **Credential Operations**: `100 per hour`

### Database Model Configuration

#### Field Length Limits

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MODEL_USERNAME_LENGTH` | Integer | `80` | Maximum username length |
| `MODEL_EMAIL_LENGTH` | Integer | `120` | Maximum email length |
| `MODEL_PASSWORD_HASH_LENGTH` | Integer | `128` | Password hash field length |
| `MODEL_OTP_SECRET_LENGTH` | Integer | `32` | OTP secret field length |
| `MODEL_ENCRYPTION_SALT_LENGTH` | Integer | `16` | Encryption salt field length |
| `MODEL_SERVICE_NAME_LENGTH` | Integer | `100` | Service name field length |
| `MODEL_SERVICE_URL_LENGTH` | Integer | `255` | Service URL field length |
| `MODEL_CREDENTIAL_USERNAME_LENGTH` | Integer | `100` | Credential username length |
| `MODEL_CATEGORY_LENGTH` | Integer | `50` | Category field length |

### Session Keys

#### Session Storage Keys

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SESSION_KEY_MASTER_PASSWORD` | String | `master_password_verified` | Master password verification key |
| `SESSION_KEY_MFA_USER_ID` | String | `mfa_user_id` | MFA user ID storage key |
| `SESSION_KEY_MFA_VERIFIED` | String | `mfa_verified` | MFA verification status key |
| `SESSION_KEY_TEMP_OTP_SECRET` | String | `temp_otp_secret` | Temporary OTP secret key |
| `SESSION_KEY_RECOVERY_USER_ID` | String | `recovery_user_id` | Recovery process user ID |

### Token Configuration

#### Token Expiration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `PASSWORD_RESET_TOKEN_EXPIRY_HOURS` | Integer | `1` | Password reset token expiry |
| `EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS` | Integer | `24` | Email verification token expiry |
| `MFA_CODE_EXPIRY_MINUTES` | Integer | `10` | MFA verification code expiry |
| `MASTER_PASSWORD_TIMEOUT_SECONDS` | Integer | `300` | Master password session timeout |

## Environment-Specific Configuration

### Development Configuration

```python
class DevelopmentConfig(Config):
    DEBUG = True
    DATABASE_URL = "sqlite:///instance/app.db"
    MAIL_SUPPRESS_SEND = True  # Suppress email sending
    RATELIMIT_ENABLED = False  # Disable rate limiting
```

**Key Features:**
- SQLite database for simplicity
- Email suppression for testing
- Debug mode enabled
- Rate limiting disabled

### Production Configuration

```python
class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True  # Require HTTPS
    RATELIMIT_ENABLED = True     # Enable rate limiting
    LOG_LEVEL = "WARNING"        # Reduce log verbosity
```

**Key Features:**
- PostgreSQL database recommended
- Secure cookie settings
- Rate limiting enabled
- Reduced logging for performance

### Testing Configuration

```python
class TestingConfig(Config):
    TESTING = True
    DATABASE_URL = "sqlite:///:memory:"  # In-memory database
    WTF_CSRF_ENABLED = False             # Disable CSRF for tests
    RATELIMIT_ENABLED = False            # Disable rate limiting
```

**Key Features:**
- In-memory SQLite database
- CSRF protection disabled
- Rate limiting disabled
- Fast test execution

## Configuration Examples

### Basic Development Setup

```bash
# .env file for development
SECRET_KEY=your-secret-key-here
DEBUG=True
DATABASE_URL=sqlite:///instance/app.db

# Email configuration (optional for development)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com
```

### Production Environment Setup

```bash
# Production environment variables
SECRET_KEY=strong-random-secret-key
DEBUG=False
DATABASE_URL=postgresql://user:password@db-host:5432/authdb

# Email configuration
MAIL_SERVER=smtp.company.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=noreply@company.com
MAIL_PASSWORD=secure-password
MAIL_DEFAULT_SENDER=noreply@company.com

# Security settings
SESSION_COOKIE_SECURE=True
MIN_PASSWORD_LENGTH=14
PBKDF2_ITERATIONS=600000

# Performance settings
RATELIMIT_STORAGE_URI=redis://redis-host:6379/0
LOG_LEVEL=WARNING
```

### Docker Configuration

```yaml
# docker-compose.yml environment section
environment:
  - SECRET_KEY=${SECRET_KEY}
  - DATABASE_URL=postgresql://postgres:password@db:5432/authdb
  - MAIL_SERVER=${MAIL_SERVER}
  - MAIL_USERNAME=${MAIL_USERNAME}
  - MAIL_PASSWORD=${MAIL_PASSWORD}
  - MAIL_DEFAULT_SENDER=${MAIL_DEFAULT_SENDER}
  - RATELIMIT_STORAGE_URI=redis://redis:6379/0
```

## Security Best Practices

### Required Security Configuration

1. **SECRET_KEY**: Must be cryptographically random and unique per deployment
2. **Database Credentials**: Use strong, unique credentials
3. **HTTPS**: Always enable `SESSION_COOKIE_SECURE=True` in production
4. **Email Security**: Use app-specific passwords for email providers
5. **Rate Limiting**: Enable rate limiting with persistent storage in production

### Recommended Security Settings

```bash
# Strong password requirements
MIN_PASSWORD_LENGTH=14

# Enhanced cryptography
PBKDF2_ITERATIONS=1000000  # Higher for better security
ARGON2_TIME_COST=4         # Increase for higher security

# Secure sessions
PERMANENT_SESSION_LIFETIME=1800  # 30 minutes
SESSION_COOKIE_SAMESITE=Strict   # Strict SameSite policy
```

### Environment Variable Security

1. **Never commit secrets to version control**
2. **Use environment-specific configuration files**
3. **Implement proper key rotation procedures**
4. **Monitor configuration changes**
5. **Use secrets management systems in production**

## Configuration Validation

The application validates critical configuration values at startup:

1. **SECRET_KEY**: Must be present and non-empty
2. **Database Connection**: Must be accessible
3. **Email Settings**: Validated if email features are enabled
4. **Cryptographic Parameters**: Must meet minimum security requirements

## Troubleshooting

### Common Configuration Issues

1. **Database Connection Failures**: Check DATABASE_URL format and credentials
2. **Email Sending Issues**: Verify SMTP settings and authentication
3. **Session Problems**: Ensure SECRET_KEY is consistent across deployments
4. **Rate Limiting Errors**: Check RATELIMIT_STORAGE_URI connectivity

### Configuration Debugging

Enable debug logging to troubleshoot configuration issues:

```bash
LOG_LEVEL=DEBUG
```

This will log configuration loading and validation details.

---

**Note**: This configuration reference reflects the current application version. Always refer to the `config.py` file and environment-specific documentation for the most up-to-date configuration options.