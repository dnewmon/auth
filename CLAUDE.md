# Project Structure Documentation

## Overview

This is a full-stack authentication and credential management system built with Flask (backend) and React (frontend). The application provides secure user authentication, multi-factor authentication (MFA), and encrypted credential storage capabilities.

## High-Level Architecture

```
┌─────────────────┐    HTTP/REST    ┌─────────────────┐
│   React SPA     │ ◄──────────────► │   Flask API     │
│   (Frontend)    │                  │   (Backend)     │
│   Port: 5000    │                  │   Port: 5002    │
└─────────────────┘                  └─────────────────┘
                                              │
                                              ▼
                                     ┌─────────────────┐
                                     │   SQLAlchemy    │
                                     │   Database      │
                                     └─────────────────┘
```

### Technology Stack

**Backend:**
- Flask with Blueprint architecture
- SQLAlchemy ORM with Flask-Migrate
- JWT authentication with Flask-JWT-Extended
- Argon2 password hashing
- Flask-Login for session management
- Flask-Mail for email notifications
- TOTP/OTP support with pyotp
- Rate limiting with Flask-Limiter

**Frontend:**
- React 19 with TypeScript
- Vite build system
- React Router for navigation
- Bootstrap 5 + React Bootstrap for UI
- Axios for HTTP client
- SCSS for styling

## Directory Structure

### Root Level

| Directory/File | Description |
|----------------|-------------|
| `app/` | Main Flask application package containing all backend code |
| `ui/` | React frontend application |
| `docs/` | API documentation files |
| `tests/` | Test files and test configuration |
| `instance/` | Instance-specific configuration files |
| `config.py` | Main configuration file for Flask application |
| `run.py` | Application entry point for development server |
| `init-db.py` | Database initialization script |
| `init-env.py` | Environment setup script |
| `requirements.txt` | Python dependencies |
| `requirements-pytest.txt` | Testing dependencies |

### Backend (`app/`) Structure

| Directory | Description |
|-----------|-------------|
| `auth/` | Authentication endpoints (login, register, logout, password reset) |
| `credentials/` | Credential management endpoints (CRUD operations for stored credentials) |
| `users/` | User management endpoints (profile, settings, account operations) |
| `security/` | Security-related endpoints (MFA setup, recovery keys, security logs) |
| `models/` | SQLAlchemy database models and configuration |
| `middleware/` | Flask middleware including error handlers |
| `templates/` | Email templates for notifications |
| `utils/` | Utility functions (email, encryption, responses, exceptions) |

### Frontend (`ui/`) Structure

| Directory | Description |
|-----------|-------------|
| `src/components/` | Reusable React components (modals, layout, navigation) |
| `src/pages/` | Page-level components (login, register, credentials management) |
| `src/services/` | API service classes for backend communication |
| `public/` | Static assets (fonts, icons) |

### Key Models

| Model | Purpose |
|-------|---------|
| `User` | Core user accounts with authentication data |
| `Credential` | Encrypted credential storage (passwords, API keys, etc.) |
| `PasswordResetToken` | Temporary tokens for password reset flows |
| `RecoveryKey` | Backup authentication keys for account recovery |

### Security Features

- **Password Security**: Argon2 hashing with configurable parameters
- **Multi-Factor Authentication**: TOTP-based 2FA with QR code setup
- **Session Management**: Secure session handling with version tracking
- **Rate Limiting**: Configurable rate limits on authentication endpoints
- **Encryption**: Client-side encryption for credential storage
- **Email Notifications**: Login alerts and security event notifications
- **Recovery Mechanisms**: Account recovery via email and backup keys

### API Structure

The Flask application uses Blueprint-based routing:

- `/api/auth/*` - Authentication operations
- `/api/credentials/*` - Credential management
- `/api/users/*` - User profile operations
- `/api/security/*` - Security settings and MFA
- `/api/utils/*` - Utility endpoints

### Development Workflow

1. **Backend Setup**: Install Python dependencies, configure environment, initialize database
2. **Frontend Setup**: Install Node.js dependencies, configure build system
3. **Development**: Run Flask dev server (port 5002) and Vite dev server (port 5000)
4. **Testing**: Use pytest for backend testing

### Configuration

The application uses environment-based configuration with support for:
- Development, production, and testing environments
- Database configuration
- Email/SMTP settings
- Security parameters (JWT secrets, session keys)
- Feature toggles and rate limiting

### Key Features

- Secure user registration and authentication
- Encrypted password/credential storage
- Multi-factor authentication (TOTP)
- Account recovery mechanisms
- Email notifications for security events
- Responsive web interface
- RESTful API design
- Comprehensive error handling
- Rate limiting and security monitoring