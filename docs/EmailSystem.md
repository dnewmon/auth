# Email System Documentation

## Overview

This document provides comprehensive documentation for the email notification system in the authentication and credential management application. The system uses Flask-Mail with asynchronous sending capabilities and HTML email templates.

## Email Infrastructure

### Core Components

**File:** `app/utils/email.py`

#### Email Configuration

The email system is configured through environment variables:

```python
MAIL_SERVER = "smtp.gmail.com"       # SMTP server hostname
MAIL_PORT = 587                      # SMTP port (587 for TLS, 465 for SSL)
MAIL_USE_TLS = True                  # Enable TLS encryption
MAIL_USE_SSL = False                 # Enable SSL encryption
MAIL_USERNAME = "your-email@gmail.com"  # SMTP authentication username
MAIL_PASSWORD = "your-app-password"     # SMTP authentication password
MAIL_DEFAULT_SENDER = "your-email@gmail.com"  # Default sender address
```

#### Asynchronous Email Sending

The system uses threading for non-blocking email delivery:

```python
def send_email_async(app, msg):
    """Send email asynchronously using threading."""
    with app.app_context():
        try:
            mail.send(msg)
        except Exception as e:
            app.logger.error(f"Failed to send email: {e}")

def send_email(to, subject, template, **kwargs):
    """Send HTML email with template rendering."""
    # Creates message and sends asynchronously
    thread = Thread(target=send_email_async, args=(current_app._get_current_object(), msg))
    thread.start()
```

## Email Templates

### Template Location

All email templates are stored in: `app/templates/email/`

### Template Structure

Each email template is an HTML file with Jinja2 template syntax:

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{{ subject }}</title>
    <style>
        /* Email-safe CSS styles */
    </style>
</head>
<body>
    <!-- Email content -->
</body>
</html>
```

### Available Email Templates

#### 1. Welcome & Verification Email

**Template:** `email/welcome_verification.html`  
**Purpose:** Sent to new users for email verification  
**Triggered by:** User registration  

**Template Variables:**
- `username` - User's username
- `verification_url` - Email verification link
- `app_name` - Application name

**Configuration:**
```python
EMAIL_WELCOME_TEMPLATE = "email/welcome_verification.html"
```

#### 2. Password Reset Email

**Template:** `email/reset_password.html`  
**Purpose:** Password reset instructions  
**Triggered by:** Password reset request  

**Template Variables:**
- `username` - User's username
- `reset_url` - Password reset link
- `expiry_time` - Token expiration time

**Configuration:**
```python
EMAIL_RESET_TEMPLATE = "email/reset_password.html"
```

#### 3. Login Notification Email

**Template:** `email/login_notification.html`  
**Purpose:** Security notification for successful logins  
**Triggered by:** Successful user login (when email MFA is enabled)  

**Template Variables:**
- `username` - User's username
- `login_time` - Login timestamp
- `ip_address` - Login IP address
- `user_agent` - Browser/device information

**Configuration:**
```python
EMAIL_LOGIN_TEMPLATE = "email/login_notification.html"
```

#### 4. MFA Login Code Email

**Template:** `email/mfa_login_code.html`  
**Purpose:** Email-based MFA verification code  
**Triggered by:** Login attempt when email MFA is enabled  

**Template Variables:**
- `username` - User's username
- `verification_code` - 6-digit verification code
- `expiry_minutes` - Code expiration time

**Configuration:**
```python
EMAIL_MFA_TEMPLATE = "email/mfa_login_code.html"
```

#### 5. MFA Test Email

**Template:** `email/mfa_test.html`  
**Purpose:** Test email during MFA setup  
**Triggered by:** MFA test functionality  

**Template Variables:**
- `username` - User's username
- `test_time` - Test timestamp

**Configuration:**
```python
EMAIL_MFA_TEST_TEMPLATE = "email/mfa_test.html"
```

#### 6. MFA Disable Verification Email

**Template:** `email/mfa_disable_code.html`  
**Purpose:** Verification code for disabling email MFA  
**Triggered by:** MFA disable request  

**Template Variables:**
- `username` - User's username
- `verification_code` - 6-digit verification code
- `expiry_minutes` - Code expiration time

**Configuration:**
```python
EMAIL_MFA_DISABLE_TEMPLATE = "email/mfa_disable_code.html"
```

#### 7. MFA Enabled Notification

**Template:** `email/mfa_enabled.html`  
**Purpose:** Confirmation that email MFA has been enabled  
**Triggered by:** Successful MFA activation  

**Template Variables:**
- `username` - User's username
- `enabled_time` - Activation timestamp

**Configuration:**
```python
EMAIL_MFA_ENABLED_TEMPLATE = "email/mfa_enabled.html"
```

#### 8. OTP Enabled Notification

**Template:** `email/otp_enabled.html`  
**Purpose:** Confirmation that TOTP MFA has been enabled  
**Triggered by:** Successful TOTP activation  

**Template Variables:**
- `username` - User's username
- `enabled_time` - Activation timestamp

**Configuration:**
```python
EMAIL_OTP_ENABLED_TEMPLATE = "email/otp_enabled.html"
```

#### 9. OTP Disabled Notification

**Template:** `email/otp_disabled.html`  
**Purpose:** Confirmation that TOTP MFA has been disabled  
**Triggered by:** TOTP deactivation  

**Template Variables:**
- `username` - User's username
- `disabled_time` - Deactivation timestamp

**Configuration:**
```python
EMAIL_OTP_DISABLED_TEMPLATE = "email/otp_disabled.html"
```

## Email Workflows

### User Registration Flow

1. **User Registration** → Submit registration form
2. **Email Verification Token** → Generate secure token
3. **Welcome Email** → Send verification email with link
4. **Email Verification** → User clicks verification link
5. **Account Activation** → Email verified, account activated

```python
# In auth/routes.py
verification_token = EmailVerificationToken.generate_for_user(new_user.id)
send_email(
    to=new_user.email,
    subject="Welcome! Please verify your email",
    template="email/welcome_verification.html",
    username=new_user.username,
    verification_url=url_for('auth.verify_email', token=verification_token.token, _external=True)
)
```

### Password Reset Flow

1. **Reset Request** → User requests password reset
2. **Reset Token** → Generate secure reset token
3. **Reset Email** → Send password reset link
4. **Password Reset** → User clicks link and sets new password

```python
# In auth/routes.py
reset_token = PasswordResetToken.create_for_user(user.id)
send_email(
    to=user.email,
    subject="Password Reset Instructions",
    template="email/reset_password.html",
    username=user.username,
    reset_url=url_for('auth.reset_password', token=reset_token.token, _external=True)
)
```

### MFA Email Flow

1. **Login Attempt** → User provides username/password
2. **MFA Code** → Generate 6-digit verification code
3. **Code Email** → Send verification code
4. **Code Verification** → User enters code to complete login

```python
# In auth/routes.py
mfa_code = MfaVerificationCode.create_for_user(user.id, purpose="login")
send_email(
    to=user.email,
    subject="Login Verification Code",
    template="email/mfa_login_code.html",
    username=user.username,
    verification_code=mfa_code.code
)
```

## Email Security

### Security Features

1. **Template Escaping**: All user input is automatically escaped in templates
2. **Token Security**: All email tokens are cryptographically secure and hashed
3. **Expiration**: All tokens and codes have configurable expiration times
4. **One-Time Use**: Security tokens can only be used once
5. **Rate Limiting**: Email sending is rate-limited to prevent abuse

### Anti-Spam Measures

1. **Sender Authentication**: SPF, DKIM, and DMARC configuration recommended
2. **Rate Limiting**: Built-in rate limiting for email endpoints
3. **Unsubscribe Support**: Optional unsubscribe functionality
4. **Content Filtering**: Email-safe HTML and CSS only

### Privacy Protection

1. **Minimal Data Exposure**: Only necessary information included in emails
2. **Secure Links**: All links use HTTPS in production
3. **No Sensitive Data**: Passwords and encryption keys never included
4. **IP Logging**: Login notifications include IP for security awareness

## Email Configuration

### SMTP Providers

#### Gmail Configuration

```python
MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = "your-email@gmail.com"
MAIL_PASSWORD = "your-app-password"  # Use app-specific password
```

#### SendGrid Configuration

```python
MAIL_SERVER = "smtp.sendgrid.net"
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = "apikey"
MAIL_PASSWORD = "your-sendgrid-api-key"
```

#### Amazon SES Configuration

```python
MAIL_SERVER = "email-smtp.us-east-1.amazonaws.com"
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = "your-ses-username"
MAIL_PASSWORD = "your-ses-password"
```

### Development Configuration

For development, email sending can be suppressed:

```python
MAIL_SUPPRESS_SEND = True  # Suppress actual email sending
TESTING = True             # Enable test mode
```

### Production Configuration

For production, ensure proper SMTP configuration:

```python
MAIL_DEBUG = False         # Disable debug mode
MAIL_SUPPRESS_SEND = False # Enable email sending
MAIL_ASCII_ATTACHMENTS = False  # Support Unicode attachments
```

## Email Testing

### Manual Testing

Use the MFA test email functionality to verify email configuration:

```python
# In security/routes.py
@security_bp.route("/mfa/email/test", methods=["POST"])
def test_email_mfa():
    send_email(
        to=current_user.email,
        subject="Email MFA Test",
        template="email/mfa_test.html",
        username=current_user.username
    )
```

### Automated Testing

Email functionality is tested in the test suite:

```python
# In tests/test_email.py
def test_send_email_async(self, app, mock_mail):
    """Test asynchronous email sending."""
    with app.app_context():
        send_email(
            to="test@example.com",
            subject="Test Email",
            template="email/mfa_test.html",
            username="testuser"
        )
    # Verify email was sent
```

### Email Preview

During development, you can preview email templates:

```bash
# Start development server
python run.py

# Navigate to preview URLs (if implemented)
http://localhost:5002/preview/email/welcome
http://localhost:5002/preview/email/reset
```

## Troubleshooting

### Common Issues

#### 1. Email Not Sending

**Symptoms**: Emails are not being delivered
**Causes**:
- Incorrect SMTP configuration
- Authentication failures
- Network connectivity issues
- Provider rate limiting

**Solutions**:
- Verify SMTP settings
- Check authentication credentials
- Test network connectivity
- Review provider logs

#### 2. Authentication Errors

**Symptoms**: SMTP authentication failures
**Causes**:
- Incorrect username/password
- Two-factor authentication required
- App-specific passwords needed

**Solutions**:
- Verify credentials
- Enable app-specific passwords
- Configure OAuth if supported

#### 3. Template Rendering Errors

**Symptoms**: Email content appears broken
**Causes**:
- Template syntax errors
- Missing template variables
- CSS compatibility issues

**Solutions**:
- Validate template syntax
- Ensure all variables are provided
- Use email-safe CSS

### Debug Configuration

Enable email debugging:

```python
MAIL_DEBUG = True          # Enable Flask-Mail debug mode
LOG_LEVEL = "DEBUG"        # Enable debug logging
```

### Monitoring

Monitor email system health:

1. **Delivery Rates**: Track successful/failed email deliveries
2. **Response Times**: Monitor SMTP response times
3. **Error Rates**: Track authentication and sending errors
4. **User Engagement**: Monitor email verification rates

## Best Practices

### Template Design

1. **Email-Safe HTML**: Use table-based layouts for compatibility
2. **Inline CSS**: Use inline styles for maximum compatibility
3. **Alt Text**: Provide alt text for images
4. **Mobile-Friendly**: Design for mobile email clients
5. **Plain Text Fallback**: Consider plain text versions

### Security Best Practices

1. **Token Expiration**: Use short expiration times for security tokens
2. **Rate Limiting**: Implement proper rate limiting
3. **Input Validation**: Validate all email addresses
4. **Secure Headers**: Include security headers in email HTML
5. **Link Validation**: Ensure all links are HTTPS in production

### Performance Optimization

1. **Asynchronous Sending**: Always send emails asynchronously
2. **Connection Pooling**: Use SMTP connection pooling if available
3. **Template Caching**: Cache compiled templates
4. **Batch Sending**: Consider batch sending for bulk operations
5. **Error Handling**: Implement robust error handling and retry logic

---

**Note**: This documentation covers the current email system implementation. For specific template customization or SMTP provider configuration, refer to the respective provider documentation and the template files in `app/templates/email/`.