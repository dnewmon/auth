# Authentication API Documentation

This document outlines the authentication endpoints provided by the Password Manager API.

## Base URL

All endpoints are prefixed with `/auth`.

## Rate Limiting

-   Registration: 5 requests per hour
-   Login operations: 10 requests per minute
-   Recovery key operations:
    -   Status check: 10 requests per hour
    -   Regeneration: 5 requests per day

## Endpoints

### 1. Register User

Register a new user account.

-   **URL:** `/register`
-   **Method:** `POST`
-   **Rate Limit:** 5 requests per hour

#### Request Body

```json
{
    "username": "string",
    "email": "string",
    "password": "string"
}
```

#### Success Response (201 Created)

```json
{
  "success": true,
  "data": {
    "id": integer,
    "username": "string",
    "email": "string",
    "recovery_keys": ["string", "string", ...],
    "recovery_message": "IMPORTANT: Please save these recovery keys in a secure location. They will be needed to recover your account if you forget your password. They will NOT be shown again."
  }
}
```

#### Error Responses

-   **400 Bad Request**

    ```json
    {
        "success": false,
        "error": "Request must be JSON"
    }
    ```

    ```json
    {
        "success": false,
        "error": "Missing username, email, or password"
    }
    ```

    ```json
    {
        "success": false,
        "error": "Invalid email address: [specific error]"
    }
    ```

    ```json
    {
        "success": false,
        "error": "Password must be at least [min_length] characters long"
    }
    ```

-   **409 Conflict**

    ```json
    {
        "success": false,
        "error": "Username or email already exists"
    }
    ```

    ```json
    {
        "success": false,
        "error": "Registration failed due to a database conflict."
    }
    ```

-   **500 Internal Server Error**
    ```json
    {
        "success": false,
        "error": "An unexpected error occurred during registration."
    }
    ```

### 2. Login

Authenticate a user.

-   **URL:** `/login`
-   **Method:** `POST`
-   **Rate Limit:** 10 requests per minute

#### Request Body

```json
{
    "username": "string",
    "password": "string"
}
```

#### Success Responses

-   **200 OK** (Standard login)

    ```json
    {
        "success": true,
        "data": {
            "message": "Login successful"
        }
    }
    ```

-   **202 Accepted** (OTP required)
    ```json
    {
        "success": true,
        "data": {
            "mfa_required": "otp"
        }
    }
    ```

#### Error Responses

-   **400 Bad Request**

    ```json
    {
        "success": false,
        "error": "Request must be JSON"
    }
    ```

    ```json
    {
        "success": false,
        "error": "Missing username or password"
    }
    ```

-   **401 Unauthorized**
    ```json
    {
        "success": false,
        "error": "Invalid username or password"
    }
    ```

### 3. Verify OTP

Complete authentication with One-Time Password after initial login.

-   **URL:** `/login/verify-otp`
-   **Method:** `POST`
-   **Rate Limit:** 10 requests per minute

#### Request Body

```json
{
    "otp_token": "string"
}
```

#### Success Response (200 OK)

```json
{
    "success": true,
    "data": {
        "message": "Login successful"
    }
}
```

#### Error Responses

-   **400 Bad Request**

    ```json
    {
        "success": false,
        "error": "Missing OTP token."
    }
    ```

    ```json
    {
        "success": false,
        "error": "OTP is not configured for this user or user not found."
    }
    ```

-   **401 Unauthorized**
    ```json
    {
        "success": false,
        "error": "Primary authentication step not completed or session expired."
    }
    ```
    ```json
    {
        "success": false,
        "error": "Invalid OTP token."
    }
    ```

### 4. Logout

Logout the currently authenticated user.

-   **URL:** `/logout`
-   **Method:** `POST`
-   **Authentication Required:** Yes

#### Request Body

No request body required.

#### Success Response (200 OK)

```json
{
    "success": true,
    "data": {
        "message": "Successfully logged out"
    }
}
```

### 5. Current User

Get information about the currently authenticated user.

-   **URL:** `/me`
-   **Method:** `GET`
-   **Authentication Required:** Yes

#### Success Response (200 OK)

```json
{
    "success": true,
    "data": {
        "username": "string"
    }
}
```

### 6. Recovery Key Status

Get the status of recovery keys for the authenticated user.

-   **URL:** `/recovery-keys`
-   **Method:** `GET`
-   **Authentication Required:** Yes
-   **Rate Limit:** 10 requests per hour

#### Success Response (200 OK)

```json
{
    "success": true,
    "data": {
        "total_keys": integer,
        "unused_keys": integer,
        "has_keys": boolean
    }
}
```

### 7. Regenerate Recovery Keys

Generate new recovery keys for the authenticated user. This invalidates all existing recovery keys.

-   **URL:** `/recovery-keys`
-   **Method:** `POST`
-   **Authentication Required:** Yes
-   **Rate Limit:** 5 requests per day

#### Request Body

```json
{
    "password": "string"
}
```

#### Success Response (200 OK)

```json
{
    "success": true,
    "data": {
        "recovery_keys": ["string", "string", ...],
        "recovery_message": "IMPORTANT: Please save these new recovery keys in a secure location. Your old keys are no longer valid."
    }
}
```

#### Error Responses

-   **400 Bad Request**

    ```json
    {
        "success": false,
        "error": "Current password is required"
    }
    ```

    ```json
    {
        "success": false,
        "error": "[specific error message from ValueError]"
    }
    ```

-   **500 Internal Server Error**
    ```json
    {
        "success": false,
        "error": "An unexpected error occurred"
    }
    ```

## Authentication Notes

1. The API uses session-based authentication.
2. After successful login, the server manages the user session.
3. OTP verification is required for users who have enabled two-factor authentication.
4. Email notifications may be sent for login events if the user has enabled email MFA.
5. Recovery keys are generated during registration and can be regenerated later if needed.
6. Recovery keys should be stored securely as they're only shown once at generation time.
