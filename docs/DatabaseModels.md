# Database Models Documentation

## Overview

This document provides comprehensive documentation for all database models in the authentication and credential management system. The system uses SQLAlchemy ORM with Flask-Migrate for database management.

## Model Relationships

```
User (1) ──────────── (Many) Credential
 │
 ├── (Many) RecoveryKey
 ├── (Many) PasswordResetToken
 ├── (Many) EmailVerificationToken
 └── (Many) MfaVerificationCode
```

## Core Models

### User Model

**File:** `app/models/user.py`  
**Table:** `users`

The central user account model with authentication and encryption capabilities.

#### Fields

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | Integer | Primary Key | Unique user identifier |
| `username` | String(80) | Unique, Not Null, Indexed | User's login username |
| `email` | String(120) | Unique, Not Null | User's email address |
| `email_verified` | Boolean | Default: False | Email verification status |
| `password_hash` | String(128) | Not Null | Argon2 hashed password |
| `encryption_salt` | LargeBinary(16) | Not Null | Salt for encryption key derivation |
| `encrypted_master_key` | Text | Nullable | Encrypted master encryption key |
| `otp_secret` | String(configurable) | Unique, Nullable | Base32 TOTP secret |
| `otp_enabled` | Boolean | Default: False | TOTP MFA status |
| `email_mfa_enabled` | Boolean | Default: False | Email MFA status |
| `session_version` | Integer | Default: 1 | Session invalidation version |
| `last_login` | DateTime | Nullable | Last successful login timestamp |
| `created_at` | DateTime | UTC Default | Account creation timestamp |
| `updated_at` | DateTime | UTC Default, Auto-update | Last modification timestamp |

#### Relationships

- **credentials**: One-to-many with `Credential` (cascade delete)
- **recovery_keys**: One-to-many with `RecoveryKey` (cascade delete)

#### Key Methods

- `set_password(password)`: Hash password with Argon2, increment session version
- `check_password(password)`: Verify password, auto-rehash if needed
- `initialize_encryption(password, master_key=None)`: Setup two-tier encryption
- `get_master_key(password)`: Decrypt and return master encryption key
- `recover_with_recovery_key(recovery_key, new_password)`: Account recovery
- `regenerate_recovery_keys(password)`: Generate new recovery keys

### Credential Model

**File:** `app/models/credential.py`  
**Table:** `credentials`

Stores encrypted user credentials with metadata.

#### Fields

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | Integer | Primary Key | Unique credential identifier |
| `user_id` | Integer | Foreign Key, Not Null, Indexed | Owner user ID |
| `service_name` | String(100) | Not Null | Name of the service |
| `service_url` | String(255) | Nullable | Service website URL |
| `username` | String(100) | Not Null | Username for the service |
| `encrypted_password` | Text | Not Null | AES-GCM encrypted password |
| `notes` | Text | Nullable | Additional notes (unencrypted) |
| `category` | String(50) | Nullable, Indexed | Organization category |
| `created_at` | DateTime | UTC Default, Indexed | Creation timestamp |
| `updated_at` | DateTime | UTC Default, Auto-update, Indexed | Last modification timestamp |

#### Composite Indexes

- `idx_user_category`: (user_id, category) - Category filtering
- `idx_user_service`: (user_id, service_name) - Service name searches
- `idx_user_created`: (user_id, created_at) - Chronological ordering

#### Relationships

- **owner**: Many-to-one with `User`

## Security Models

### RecoveryKey Model

**File:** `app/models/user.py`  
**Table:** `recovery_keys`

Manages account recovery keys for password reset with credential preservation.

#### Fields

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | Integer | Primary Key | Unique recovery key identifier |
| `user_id` | Integer | Foreign Key, Not Null, Cascade Delete | Owner user ID |
| `key_hash` | String(64) | Not Null, Indexed | SHA-256 hash of recovery key |
| `salt` | LargeBinary(16) | Not Null | Cryptographic salt |
| `encrypted_master_key` | Text | Not Null | Master key encrypted with recovery key |
| `created_at` | DateTime | UTC Default | Creation timestamp |
| `used_at` | DateTime | Nullable | Usage timestamp (one-time use) |

#### Key Methods

- `mark_as_used()`: Mark recovery key as used with timestamp

#### Relationships

- **user**: Many-to-one with `User`

### PasswordResetToken Model

**File:** `app/models/password_reset_token.py`  
**Table:** `password_reset_tokens`

Manages secure password reset tokens sent via email.

#### Fields

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | Integer | Primary Key | Unique token identifier |
| `user_id` | Integer | Foreign Key, Not Null | Target user ID |
| `token_hash` | String(64) | Not Null, Unique | SHA-256 hashed token |
| `created_at` | DateTime | UTC Default | Token creation timestamp |
| `expires_at` | DateTime | Not Null | Token expiration timestamp |
| `used_at` | DateTime | Nullable | Token usage timestamp |

#### Key Methods

- `is_expired()`: Check if token has expired
- `is_used()`: Check if token has been used
- `mark_as_used()`: Mark token as used

### EmailVerificationToken Model

**File:** `app/models/email_verification_token.py`  
**Table:** `email_verification_tokens`

Manages email verification tokens for new user registration.

#### Fields

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | Integer | Primary Key | Unique token identifier |
| `user_id` | Integer | Foreign Key, Not Null | Target user ID |
| `token_hash` | String(64) | Not Null, Unique | SHA-256 hashed token |
| `created_at` | DateTime | UTC Default | Token creation timestamp |
| `expires_at` | DateTime | Not Null | Token expiration timestamp |
| `used_at` | DateTime | Nullable | Token usage timestamp |

#### Configuration

- **Expiration**: Configurable via `EMAIL_VERIFICATION_EXPIRY_HOURS` (default: 24 hours)
- **Auto-cleanup**: Expired tokens are automatically cleaned up

### MfaVerificationCode Model

**File:** `app/models/mfa_verification_code.py`  
**Table:** `mfa_verification_codes`

Manages email-based MFA verification codes.

#### Fields

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | Integer | Primary Key | Unique code identifier |
| `user_id` | Integer | Foreign Key, Not Null | Target user ID |
| `code` | String(6) | Not Null | 6-digit verification code |
| `purpose` | String(50) | Not Null | Code purpose (login, disable_mfa) |
| `created_at` | DateTime | UTC Default | Code creation timestamp |
| `expires_at` | DateTime | Not Null | Code expiration timestamp |
| `used_at` | DateTime | Nullable | Code usage timestamp |

#### Configuration

- **Code Length**: 6 digits
- **Expiration**: Configurable (default: 10 minutes)
- **Purposes**: `login`, `disable_mfa`

## Database Configuration

### Connection Settings

The database configuration is managed through environment variables:

- `DATABASE_URL`: Full database connection string
- `SQLALCHEMY_DATABASE_URI`: Alternative connection string format
- `SQLALCHEMY_TRACK_MODIFICATIONS`: Set to `False` for performance

### Migration Management

Database schema changes are managed using Flask-Migrate:

```bash
# Create migration
flask db migrate -m "Description"

# Apply migration
flask db upgrade

# Downgrade migration
flask db downgrade
```

### Performance Considerations

#### Indexing Strategy

1. **Primary Keys**: Automatic clustered indexes
2. **Foreign Keys**: Automatic indexes for referential integrity
3. **Unique Constraints**: Automatic unique indexes
4. **Custom Indexes**: 
   - User lookup fields (username, email)
   - Temporal fields (created_at, updated_at)
   - Composite indexes for common query patterns

#### Query Optimization

1. **Pagination**: All list endpoints support pagination
2. **Eager Loading**: Relationships loaded efficiently
3. **Query Filtering**: Indexed fields used for filtering
4. **Connection Pooling**: Configured for concurrent access

## Security Considerations

### Data Protection

1. **Encryption at Rest**: Sensitive data encrypted before storage
2. **Password Hashing**: Argon2 with secure parameters
3. **Token Hashing**: SHA-256 for all security tokens
4. **Salt Usage**: Unique salts for all cryptographic operations

### Access Control

1. **User Isolation**: All queries filtered by user_id
2. **Authorization Checks**: Ownership verified for all operations
3. **Session Management**: Version-based session invalidation
4. **Rate Limiting**: Applied to all sensitive operations

### Data Integrity

1. **Foreign Key Constraints**: Referential integrity enforced
2. **Check Constraints**: Data validation at database level
3. **Cascade Deletes**: Automatic cleanup of related records
4. **Transaction Management**: ACID compliance for all operations

## Common Query Patterns

### User Management

```python
# Find user by username or email
user = User.query.filter(
    (User.username == identifier) | (User.email == identifier)
).first()

# Update last login
user.update_last_login()
```

### Credential Operations

```python
# List user credentials with pagination
credentials = Credential.query.filter_by(user_id=user.id)\
    .order_by(Credential.category.asc(), Credential.service_name.asc())\
    .paginate(page=1, per_page=20)

# Search credentials
credentials = Credential.query.filter_by(user_id=user.id)\
    .filter(Credential.service_name.ilike(f"%{search}%"))\
    .all()
```

### Security Operations

```python
# Find valid recovery keys
recovery_keys = RecoveryKey.query.filter_by(
    user_id=user.id, used_at=None
).all()

# Clean up expired tokens
expired_tokens = PasswordResetToken.query.filter(
    PasswordResetToken.expires_at < datetime.utcnow()
).all()
```

## Database Schema Evolution

### Version History

The database schema evolves through Flask-Migrate migrations:

1. **Initial Schema**: Basic user and credential models
2. **MFA Support**: Added TOTP and email MFA fields
3. **Recovery System**: Added recovery keys and reset tokens
4. **Email Verification**: Added email verification workflow
5. **Performance Optimization**: Added indexes and composite keys

### Future Considerations

1. **Archival Strategy**: Long-term data retention policies
2. **Partitioning**: Table partitioning for large datasets
3. **Sharding**: Horizontal scaling strategies
4. **Backup/Recovery**: Automated backup and recovery procedures

---

**Note**: This documentation reflects the current database schema. For the most up-to-date information, refer to the migration files in the `migrations/` directory and the model definitions in `app/models/`.