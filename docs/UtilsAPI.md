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
