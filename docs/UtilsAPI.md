# Utils API Documentation

This document details the API endpoints available in the `utils` blueprint, which provides utility functions for password management and credential export/import operations.

## Password Management

### Forgot Password

Initiates the password reset process by generating a reset token and sending an email with the reset link.

-   **URL**: `/utils/forgot-password`
-   **Method**: `POST`
-   **Rate Limit**: 3 requests per hour

**Request Body**:

```json
{
    "email": "user@example.com"
}
```

**Response**:

```json
{
    "success": true,
    "message": "If an account with that email exists, a password reset link has been sent."
}
```

**Error Responses**:

```json
{
    "success": false,
    "error": "Email is required."
}
```

```json
{
    "success": false,
    "error": "An error occurred during the password reset process."
}
```

### Reset Password

Resets the user's password using a valid token received via email. If a recovery key is provided, attempts to preserve encrypted credentials.

-   **URL**: `/utils/reset-password/<token>`
-   **Method**: `POST`
-   **Rate Limit**: 3 requests per hour

**Request Body**:

```json
{
    "new_password": "SecurePassword123!",
    "recovery_key": "your-recovery-key" // Optional
}
```

**Response**:

If credentials are preserved with recovery key:

```json
{
    "success": true,
    "message": "Password has been reset successfully and your credentials have been preserved.",
    "credentials_migrated": true
}
```

If credentials could not be preserved (no recovery key):

```json
{
    "success": true,
    "message": "Password has been reset successfully, but you cannot access your previous credentials. New recovery keys have been generated.",
    "recovery_keys": ["key1", "key2", "key3"],
    "recovery_message": "IMPORTANT: Please save these recovery keys in a secure location. They will be needed to recover your account if you forget your password again.",
    "credentials_migrated": false
}
```

If no credentials existed:

```json
{
    "success": true,
    "message": "Password has been reset successfully.",
    "credentials_migrated": true
}
```

**Error Responses**:

```json
{
    "success": false,
    "error": "Invalid or expired password reset token."
}
```

```json
{
    "success": false,
    "error": "New password is required."
}
```

```json
{
    "success": false,
    "error": "Password must be at least X characters long."
}
```

### Recover With Key

Recover account using a recovery key without requiring a reset token.

-   **URL**: `/utils/recover-with-key`
-   **Method**: `POST`
-   **Rate Limit**: 5 requests per hour

**Request Body**:

```json
{
    "email": "user@example.com",
    "recovery_key": "your-recovery-key",
    "new_password": "SecurePassword123!"
}
```

**Response**:

```json
{
    "success": true,
    "message": "Account recovered successfully. You can now log in with your new password.",
    "credentials_preserved": true
}
```

**Error Responses**:

```json
{
    "success": false,
    "error": "Email, recovery key, and new password are required"
}
```

```json
{
    "success": false,
    "error": "Invalid email or recovery key"
}
```

```json
{
    "success": false,
    "error": "Password must be at least X characters long"
}
```

## Credential Management

### Export Credentials

Exports the user's credentials as a password-protected ZIP file containing a CSV.

-   **URL**: `/utils/export`
-   **Method**: `POST`
-   **Authentication**: Required
-   **Rate Limit**: 3 requests per hour

**Request Body**:

```json
{
    "master_password": "YourMasterPassword",
    "export_password": "PasswordToProtectZip"
}
```

**Response**:
A binary file download (ZIP) with Content-Type "application/zip" and Content-Disposition "attachment", filename="credentials_export.zip"

If no credentials exist:

```json
{
    "success": true,
    "message": "You have no credentials stored to export."
}
```

**Error Responses**:

```json
{
    "success": false,
    "error": "Master password is required."
}
```

```json
{
    "success": false,
    "error": "Export password is required to protect the ZIP file."
}
```

```json
{
    "success": false,
    "error": "Failed to decrypt one or more credentials."
}
```

### Import Credentials

Imports credentials from a JSON structure.

-   **URL**: `/utils/import`
-   **Method**: `POST`
-   **Authentication**: Required
-   **Rate Limit**: 3 requests per hour

**Request Body**:

```json
{
    "master_password": "YourMasterPassword",
    "credentials": [
        {
            "service_name": "Example Service",
            "service_url": "https://example.com",
            "username": "username123",
            "password": "password123",
            "category": "Personal",
            "notes": "Optional notes"
        },
        {
            "service_name": "Another Service",
            "service_url": "https://another-example.com",
            "username": "user456",
            "password": "pass456",
            "category": null,
            "notes": null
        }
    ]
}
```

**Response**:

```json
{
    "success": true,
    "message": "Credentials imported successfully."
}
```

**Error Responses**:

```json
{
    "success": false,
    "error": "Master password is required."
}
```

```json
{
    "success": false,
    "error": "Credentials data is required."
}
```

```json
{
    "success": false,
    "error": "Failed to import credentials."
}
```

## Password Management Tools

### Password Generator

Generate secure passwords with customizable options.

-   **URL**: `/utils/password-generator`
-   **Method**: `POST`
-   **Authentication**: Required
-   **Rate Limit**: 50 requests per minute

**Request Body**:

```json
{
    "length": 16,
    "character_sets": {
        "lowercase": true,
        "uppercase": true,
        "digits": true,
        "symbols": true
    },
    "safe_symbols_only": false,
    "exclude_ambiguous": true,
    "minimum_requirements": {
        "lowercase": 1,
        "uppercase": 1,
        "digits": 1,
        "symbols": 1
    },
    "exclude_characters": "optional_string",
    "require_characters": "optional_string",
    "count": 1
}
```

**Response**:

```json
{
    "success": true,
    "data": {
        "password": "GeneratedPassword123!",
        "strength": {
            "score": 85,
            "category": "Strong",
            "feedback": ["Good length", "Good character variety"]
        },
        "length": 20
    }
}
```

## Data Management

### Backup User Data

Creates a comprehensive backup of user data including credentials, shared credentials metadata, and user settings. Returns a password-protected ZIP file.

-   **URL**: `/utils/backup`
-   **Method**: `POST`
-   **Authentication**: Required
-   **Rate Limit**: 3 requests per hour

**Request Body**:

```json
{
    "master_password": "user_master_password",
    "backup_password": "protection_password_for_zip"
}
```

**Response**:

Binary ZIP file download with headers:
- `Content-Type`: `application/zip`
- `Content-Disposition`: `attachment; filename="backup_username_YYYYMMDD_HHMMSS.zip"`

**Backup Contents**:

The ZIP file contains a JSON file with:

```json
{
    "version": "1.0",
    "created_at": "2024-01-15T10:30:00Z",
    "user_info": {
        "username": "user123",
        "email": "user@example.com",
        "created_at": "2024-01-01T00:00:00Z",
        "otp_enabled": false,
        "email_mfa_enabled": true
    },
    "credentials": [
        {
            "service_name": "Gmail",
            "service_url": "https://gmail.com",
            "username": "user@gmail.com",
            "password": "decrypted_password",
            "notes": "Personal email",
            "category": "email",
            "created_at": "2024-01-01T12:00:00Z",
            "updated_at": "2024-01-01T12:00:00Z"
        }
    ],
    "shared_credentials_sent": [
        {
            "credential_service_name": "Shared Service",
            "recipient_email": "friend@example.com",
            "status": "accepted",
            "can_view": true,
            "can_edit": false,
            "message": "Sharing message",
            "created_at": "2024-01-01T15:00:00Z",
            "expires_at": "2024-02-01T15:00:00Z"
        }
    ],
    "shared_credentials_received": [
        {
            "credential_service_name": "Received Service",
            "owner_email": "colleague@example.com",
            "status": "accepted",
            "can_view": true,
            "can_edit": false,
            "message": "Received message",
            "created_at": "2024-01-01T16:00:00Z",
            "accepted_at": "2024-01-01T16:30:00Z"
        }
    ]
}
```

### Restore User Data

Restores user data from a backup file. Supports merging or replacing existing credentials.

-   **URL**: `/utils/restore`
-   **Method**: `POST`
-   **Authentication**: Required
-   **Rate Limit**: 2 requests per hour

**Request Body**:

```json
{
    "master_password": "user_master_password",
    "backup_data": {
        "version": "1.0",
        "credentials": [
            {
                "service_name": "Gmail",
                "username": "user@gmail.com",
                "password": "password_to_restore",
                "category": "email",
                "notes": "Restored credential"
            }
        ]
    },
    "merge_credentials": true,
    "skip_existing": true
}
```

**Parameters**:
- `backup_data`: JSON object containing the backup data structure
- `merge_credentials`: Optional. If true (default), merge with existing credentials. If false, replace all credentials
- `skip_existing`: Optional. If true (default), skip credentials that already exist. If false, update existing credentials

**Response**:

```json
{
    "success": true,
    "data": {
        "message": "Backup restored successfully",
        "restored_count": 5,
        "skipped_count": 2,
        "error_count": 0,
        "backup_version": "1.0",
        "backup_created_at": "2024-01-15T10:30:00Z"
    }
}
```

**Notes**:
- Credentials are matched by `service_name` and `username` for duplicate detection
- All passwords are re-encrypted with the user's current master key
- The restore operation is logged in the audit log
- Shared credentials metadata is included in backups but not restored (metadata only)

## Password Policy Management

### Get Password Policy Configuration

Retrieves the current password policy configuration that governs credential password requirements.

-   **URL**: `/utils/password-policy`
-   **Method**: `GET`
-   **Authentication**: Required
-   **Rate Limit**: No specific limit

**Response**:

```json
{
    "success": true,
    "data": {
        "enabled": true,
        "min_length": 8,
        "max_length": 128,
        "require_uppercase": true,
        "require_lowercase": true,
        "require_digits": true,
        "require_symbols": true,
        "min_uppercase": 1,
        "min_lowercase": 1,
        "min_digits": 1,
        "min_symbols": 1,
        "forbid_common_patterns": true,
        "forbid_personal_info": true,
        "enforce_on_creation": true,
        "enforce_on_update": true,
        "warn_only": false
    }
}
```

**Policy Configuration**:

| Setting | Description |
|---------|-------------|
| `enabled` | Whether password policy is enabled |
| `min_length` | Minimum password length |
| `max_length` | Maximum password length |
| `require_uppercase` | Require uppercase letters |
| `require_lowercase` | Require lowercase letters |
| `require_digits` | Require numeric digits |
| `require_symbols` | Require special characters |
| `min_*` | Minimum count for each character type |
| `forbid_common_patterns` | Block common weak patterns (sequential chars, keyboard patterns) |
| `forbid_personal_info` | Block passwords containing username, email parts, etc. |
| `enforce_on_creation` | Apply policy when creating credentials |
| `enforce_on_update` | Apply policy when updating credentials |
| `warn_only` | Show warnings but allow saving (if true) |

**Notes**:
- Password policy is automatically enforced on credential creation and updates
- When `warn_only` is true, policy violations generate warnings but don't block operations
- Policy violations return 400 Bad Request with detailed error messages
- Successful operations with warnings include `password_policy_warnings` in the response

**Common Policy Violations**:

1. **Length Issues**: Password too short or too long
2. **Character Requirements**: Missing required character types
3. **Forbidden Passwords**: Using common passwords (password, 123456, etc.)
4. **Common Patterns**: Sequential characters (abc, 123), repeated characters (aaa), keyboard patterns (qwerty)
5. **Personal Information**: Using username, email parts, or personal names in password

### Password Analyzer

Analyze password strength and provide feedback.

-   **URL**: `/utils/password-analyzer`
-   **Method**: `POST`
-   **Authentication**: Required
-   **Rate Limit**: 100 requests per minute

**Request Body**:

```json
{
    "password": "password_to_analyze"
}
```

**Response**:

```json
{
    "success": true,
    "data": {
        "score": 75,
        "category": "Good",
        "feedback": ["Consider adding symbols", "Good length"],
        "entropy": 42.5,
        "time_to_crack": "3 days"
    }
}
```

### Password Presets

Get predefined password generation presets.

-   **URL**: `/utils/password-presets`
-   **Method**: `GET`
-   **Authentication**: Required

**Response**:

```json
{
    "success": true,
    "data": {
        "presets": {
            "strong": {
                "name": "Strong Password",
                "description": "Balanced security and usability",
                "length": 16,
                "character_sets": {
                    "lowercase": true,
                    "uppercase": true,
                    "digits": true,
                    "symbols": true
                }
            }
        }
    }
}
```

### Password Health Report

Generate a comprehensive password health report for user's credentials.

-   **URL**: `/utils/password-health-report`
-   **Method**: `POST`
-   **Authentication**: Required
-   **Rate Limit**: 5 requests per minute

**Request Body**:

```json
{
    "master_password": "YourMasterPassword"
}
```

**Response**:

```json
{
    "success": true,
    "data": {
        "total_credentials": 15,
        "health_score": 75,
        "summary": {
            "weak_passwords": 3,
            "reused_passwords": 2,
            "old_passwords": 1,
            "strong_passwords": 9
        },
        "recommendations": [
            "Update 3 weak password(s) with stronger alternatives",
            "Create unique passwords for 2 credential(s) that share passwords"
        ],
        "credentials_analysis": [
            {
                "id": 1,
                "service_name": "Gmail",
                "username": "user@example.com",
                "last_updated": "2024-01-15T10:30:00Z",
                "strength": {
                    "score": 45,
                    "category": "Weak"
                },
                "issues": ["Weak password", "Password reused"]
            }
        ]
    }
}
```

## Security and Monitoring

### Audit Logs

Get audit logs for the current user.

-   **URL**: `/utils/audit-logs`
-   **Method**: `GET`
-   **Authentication**: Required
-   **Rate Limit**: 30 requests per minute

**Query Parameters**:
- `limit`: Number of logs to return (max 100, default 50)
- `page`: Page number for pagination (default 1)
- `event_types`: Array of event types to filter by

**Response**:

```json
{
    "success": true,
    "data": {
        "logs": [
            {
                "id": 1,
                "event_type": "LOGIN",
                "severity": "INFO",
                "message": "User logged in successfully",
                "created_at": "2024-01-15T10:30:00Z",
                "ip_address": "192.168.1.1"
            }
        ],
        "pagination": {
            "page": 1,
            "per_page": 50,
            "total": 25,
            "pages": 1,
            "has_next": false,
            "has_prev": false
        }
    }
}
```

### Security Summary

Get security summary and recent alerts for the current user.

-   **URL**: `/utils/security-summary`
-   **Method**: `GET`
-   **Authentication**: Required
-   **Rate Limit**: 10 requests per minute

**Response**:

```json
{
    "success": true,
    "data": {
        "recent_activity": [
            {
                "event_type": "LOGIN",
                "created_at": "2024-01-15T10:30:00Z",
                "message": "Successful login"
            }
        ],
        "statistics": {
            "successful_logins": 15,
            "failed_logins": 2,
            "credential_actions": 8,
            "security_warnings": 0
        },
        "summary": {
            "account_secure": true,
            "recent_activity_count": 5,
            "period_days": 30
        }
    }
}
```

## Password Manager Import

### Get Import Formats

Get list of supported password manager import formats.

-   **URL**: `/utils/import/formats`
-   **Method**: `GET`
-   **Authentication**: Required

**Response**:

```json
{
    "success": true,
    "data": {
        "supported_formats": [
            "Chrome/Edge/Firefox CSV",
            "LastPass CSV",
            "1Password CSV",
            "Bitwarden JSON",
            "Bitwarden CSV",
            "KeePass XML"
        ],
        "format_descriptions": {
            "Chrome/Edge/Firefox CSV": "Browser saved passwords export",
            "LastPass CSV": "LastPass vault export",
            "1Password CSV": "1Password vault export",
            "Bitwarden JSON": "Bitwarden vault export (JSON format)",
            "Bitwarden CSV": "Bitwarden vault export (CSV format)",
            "KeePass XML": "KeePass database export"
        }
    }
}
```

### Preview Import

Preview credentials from password manager export files before importing. Supports automatic format detection and validation.

-   **URL**: `/utils/import/preview`
-   **Method**: `POST`
-   **Authentication**: Required
-   **Rate Limit**: 10 requests per hour

**Request Body**:

```json
{
    "content": "CSV/JSON/XML content from password manager export",
    "format": "Chrome/Edge/Firefox CSV"  // Optional format hint
}
```

**Response**:

```json
{
    "success": true,
    "data": {
        "detected_format": "Chrome/Edge/Firefox CSV",
        "credential_count": 3,
        "credentials": [
            {
                "service_name": "Gmail",
                "service_url": "https://gmail.com",
                "username": "user@gmail.com",
                "password": "password123",
                "category": "imported",
                "notes": "Imported from Chrome/Edge/Firefox"
            }
        ],
        "validation_issues": [
            {
                "index": 1,
                "service_name": "WeakService",
                "issues": ["Weak password (less than 8 characters)"]
            }
        ],
        "supported_formats": [
            "Chrome/Edge/Firefox CSV",
            "LastPass CSV",
            "1Password CSV",
            "Bitwarden JSON",
            "Bitwarden CSV",
            "KeePass XML"
        ]
    }
}
```

**Error Responses**:

```json
{
    "success": false,
    "error": "Could not detect import format. Supported formats: Chrome/Edge/Firefox CSV, LastPass CSV, 1Password CSV, Bitwarden JSON/CSV, KeePass XML"
}
```

### Import from Password Manager

Import credentials from popular password manager export files with support for duplicate detection and password policy enforcement.

-   **URL**: `/utils/import/password-manager`
-   **Method**: `POST`
-   **Authentication**: Required
-   **Rate Limit**: 5 requests per hour

**Request Body**:

```json
{
    "content": "CSV/JSON/XML content from password manager export",
    "master_password": "YourMasterPassword",
    "format": "Chrome/Edge/Firefox CSV",  // Optional format hint
    "skip_duplicates": true,              // Optional, default: true
    "enforce_policy": false               // Optional, default: false
}
```

**Parameters**:
- `content`: The raw export data from your password manager
- `master_password`: Your current master password for encryption
- `format`: Optional format hint (auto-detected if not provided)
- `skip_duplicates`: Skip credentials that already exist (matched by service name + username)
- `enforce_policy`: Apply password policy validation during import

**Response**:

```json
{
    "success": true,
    "data": {
        "message": "Password manager import completed",
        "detected_format": "Chrome/Edge/Firefox CSV",
        "imported_count": 2,
        "skipped_count": 1,
        "error_count": 0,
        "policy_violations": [
            {
                "service_name": "WeakService",
                "username": "user",
                "errors": ["Password too weak"]
            }
        ]
    }
}
```

**Error Responses**:

```json
{
    "success": false,
    "error": "Master password is required."
}
```

```json
{
    "success": false,
    "error": "Import content is required."
}
```

```json
{
    "success": false,
    "error": "No valid credentials found in import data."
}
```

## Supported Password Manager Formats

### Chrome/Edge/Firefox CSV
Browser saved passwords export format with columns: name, url, username, password

**Example**:
```csv
name,url,username,password
Gmail,https://gmail.com,user@gmail.com,password123
Facebook,https://facebook.com,myuser,fb_password
```

### LastPass CSV
LastPass vault export with columns: url, username, password, extra, name, grouping, fav

**Example**:
```csv
url,username,password,extra,name,grouping,fav
https://gmail.com,user@gmail.com,password123,Notes here,Gmail,Email,0
https://facebook.com,myuser,fb_password,,Facebook,Social,1
```

### 1Password CSV
1Password vault export with columns: Title, Website, Username, Password, Notes

**Example**:
```csv
Title,Website,Username,Password,Notes
Gmail,https://gmail.com,user@gmail.com,password123,Work email
Facebook,https://facebook.com,myuser,fb_password,Social media
```

### Bitwarden JSON
Bitwarden JSON vault export with full metadata structure

**Example**:
```json
{
    "encrypted": false,
    "folders": [{"id": "folder1", "name": "Work"}],
    "items": [
        {
            "id": "item1",
            "type": 1,
            "name": "Gmail",
            "folderId": "folder1",
            "login": {
                "username": "user@gmail.com",
                "password": "password123",
                "uris": [{"uri": "https://gmail.com"}]
            }
        }
    ]
}
```

### Bitwarden CSV
Bitwarden CSV vault export with columns: folder, favorite, type, name, notes, fields, login_uri, login_username, login_password, login_totp

**Example**:
```csv
folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp
Work,0,login,Gmail,Work email,,https://gmail.com,user@gmail.com,password123,
Personal,1,login,Facebook,Social,,https://facebook.com,myuser,fb_password,
```

### KeePass XML
KeePass database XML export with Entry elements containing String key-value pairs

**Example**:
```xml
<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
    <Root>
        <Group>
            <Entry>
                <String><Key>Title</Key><Value>Gmail</Value></String>
                <String><Key>UserName</Key><Value>user@gmail.com</Value></String>
                <String><Key>Password</Key><Value>password123</Value></String>
                <String><Key>URL</Key><Value>https://gmail.com</Value></String>
                <String><Key>Notes</Key><Value>Work email</Value></String>
            </Entry>
        </Group>
    </Root>
</KeePassFile>
```

## Import Process

### Step 1: Export from Your Password Manager
1. **Chrome/Edge/Firefox**: Go to Settings > Passwords > Export passwords
2. **LastPass**: Vault > Advanced Options > Export > LastPass CSV File
3. **1Password**: Export > All Items > CSV format
4. **Bitwarden**: Tools > Export Vault > JSON or CSV format
5. **KeePass**: File > Export > XML format

### Step 2: Preview Your Import
Use the `/utils/import/preview` endpoint to:
- Verify format detection works correctly
- Check how many credentials will be imported
- Review validation issues or warnings
- See how credentials will be organized

### Step 3: Configure Import Options
- **Skip Duplicates**: Prevent importing credentials that already exist
- **Enforce Policy**: Apply password policy validation during import
- **Format Override**: Specify format if auto-detection fails

### Step 4: Import Your Data
Use the `/utils/import/password-manager` endpoint to complete the import process. The system will:
- Parse your export data using the appropriate parser
- Validate credentials according to your settings
- Encrypt passwords using your master key
- Skip or report duplicates based on your configuration
- Log the import operation for security auditing

### Security Considerations
- All passwords are re-encrypted with your current master key during import
- Import operations are logged in the audit trail
- Rate limiting prevents bulk import abuse
- Duplicate detection helps prevent credential bloat
- Password policy enforcement maintains security standards
- Original export files should be securely deleted after import
