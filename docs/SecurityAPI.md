# Security API Documentation

This document outlines the API endpoints for the security-related functionality in the Password Manager application. All endpoints are prefixed with `/api/security` (assuming the security_bp blueprint is registered with the `/api/security` prefix).

## Authentication and Authorization

All endpoints require authentication via session-based authentication (Flask-Login). The endpoints are protected with `@login_required` decorator.

Rate limiting is applied to sensitive operations to prevent abuse.

## Endpoints

### OTP (One-Time Password) Management

#### Setup OTP

Generates an OTP secret and provisioning URI for the current user.

**Endpoint:** `POST /otp/setup`

**Rate Limit:** 5 requests per hour

**Request Body:**

```json
{
    "password": "current_user_password"
}
```

**Success Response (200 OK):**

```json
{
    "status": "success",
    "data": {
        "provisioning_uri": "otpauth://totp/user@example.com?secret=BASE32SECRET&issuer=PasswordManagerApp",
        "qr_code_png_base64": "base64_encoded_qr_code_image",
        "message": "Scan the QR code with your authenticator app and verify below."
    }
}
```

**Error Responses:**

-   400 Bad Request: If password is missing or OTP is already enabled
-   401 Unauthorized: If password is incorrect

**Implementation Notes:**

-   The OTP secret is temporarily stored in the user's session under a key defined by the `SESSION_KEY_OTP_SECRET_TEMP` configuration value
-   The issuer name in the provisioning URI is specified by the `OTP_ISSUER_NAME` configuration value, defaulting to "PasswordManagerApp"

#### Verify and Enable OTP

Verifies the OTP token provided by the user and enables OTP for their account.

**Endpoint:** `POST /otp/verify-enable`

**Request Body:**

```json
{
    "otp_token": "123456"
}
```

**Success Response (200 OK):**

```json
{
    "status": "success",
    "data": {
        "message": "OTP has been successfully enabled."
    }
}
```

**Error Responses:**

-   400 Bad Request: If OTP token is missing or setup process was not initiated/session expired
-   401 Unauthorized: If OTP token is invalid

**Implementation Notes:**

-   Upon successful verification, the temporary OTP secret is removed from the session and stored in the user's database record
-   The `otp_enabled` flag is set to true in the user's database record

#### Disable OTP

Disables OTP for the current user.

**Endpoint:** `POST /otp/disable`

**Rate Limit:** 5 requests per hour

**Request Body:**

```json
{
    "password": "current_user_password"
}
```

**Success Response (200 OK):**

```json
{
    "status": "success",
    "data": {
        "message": "OTP has been successfully disabled."
    }
}
```

**Error Responses:**

-   400 Bad Request: If password is missing or OTP is not currently enabled
-   401 Unauthorized: If password is incorrect

### Email MFA Management

#### Enable Email MFA

Enables email notifications for login for the current user.

**Endpoint:** `POST /mfa/email/enable`

**Rate Limit:** 5 requests per hour

**Request Body:**

```json
{
    "password": "current_user_password"
}
```

**Success Response (200 OK):**

```json
{
    "status": "success",
    "data": {
        "message": "Email MFA notification has been enabled."
    }
}
```

**Error Responses:**

-   400 Bad Request: If password is missing or email MFA is already enabled
-   401 Unauthorized: If password is incorrect
-   500 Internal Server Error: If test email sending fails

**Implementation Notes:**

-   Before enabling, the endpoint sends a test email to verify that the email functionality is working
-   The test email uses a template specified by the `EMAIL_MFA_TEST_TEMPLATE` configuration value
-   The login notification emails will be sent upon successful authentication
-   The template for login notifications is the same one used by the login verification process

#### Disable Email MFA

Disables email notifications for login for the current user.

**Endpoint:** `POST /mfa/email/disable`

**Rate Limit:** 5 requests per hour

**Request Body:**

```json
{
    "password": "current_user_password"
}
```

**Success Response (200 OK):**

```json
{
    "status": "success",
    "data": {
        "message": "Email MFA notification has been disabled."
    }
}
```

**Error Responses:**

-   400 Bad Request: If password is missing or email MFA is not currently enabled
-   401 Unauthorized: If password is incorrect

### MFA Status

Gets the MFA configuration status for the current user.

**Endpoint:** `GET /mfa/status`

**Request Body:** None

**Success Response (200 OK):**

```json
{
    "status": "success",
    "data": {
        "otp_enabled": true,
        "email_mfa_enabled": false
    }
}
```

## Response Structure

All responses follow a standard format:

### Success Responses

```json
{
    "status": "success",
    "data": {
        // Response data specific to the endpoint
    }
}
```

### Error Responses

```json
{
    "status": "error",
    "message": "Error message describing what went wrong"
}
```

## Status Codes

-   **200 OK**: Request successful
-   **400 Bad Request**: Invalid request parameters or state
-   **401 Unauthorized**: Authentication failure
-   **500 Internal Server Error**: Server-side error

## Notes

-   All sensitive operations require password confirmation
-   OTP setup is a two-step process:
    1. Generate a secret and QR code (`/otp/setup`)
    2. Verify the user can generate a valid token (`/otp/verify-enable`)
-   When Email MFA is enabled:
    1. A test email is sent to verify email delivery works
    2. After enabling, login notification emails will be sent whenever the user successfully logs in
    3. The login notification uses a template specified by the `EMAIL_LOGIN_NOTIFICATION_TEMPLATE` configuration value
-   All endpoints automatically log important security events
