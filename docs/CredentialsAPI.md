# Password Manager API Documentation

This document outlines the API endpoints available in the Password Manager application, including their request and response data structures.

## Credentials API (`/credentials`)

### Verify Master Password

**Endpoint:** `POST /credentials/verify-master`

**Authentication Required:** Yes

**Rate Limit:** 10 requests per minute

**Request:**

```json
{
    "master_password": "string"
}
```

**Response (200 OK):**

```json
{
    "status": "success",
    "data": "Master password verified."
}
```

**Error Responses:**

-   400: Missing master password
-   401: Invalid master password

### Check Master Password Verification Status

**Endpoint:** `GET /credentials/verify-master/status`

**Authentication Required:** Yes

**Response (200 OK):**

```json
{
    "status": "success",
    "data": {
        "verified": "boolean",
        "expires_at": "integer or null",
        "time_remaining": "integer"
    }
}
```

**Notes:**

-   Verification is valid for 5 minutes (300 seconds)
-   `time_remaining` is in seconds

### Create Credential

**Endpoint:** `POST /credentials/`

**Authentication Required:** Yes
**Master Password Verification Required:** Yes

**Request:**

```json
{
    "service_name": "string",
    "username": "string",
    "password": "string",
    "master_password": "string",
    "service_url": "string (optional)",
    "notes": "string (optional)",
    "category": "string (optional)"
}
```

**Notes:**

-   This endpoint requires both:
    -   A prior call to `/credentials/verify-master` within the last 5 minutes
    -   The `master_password` in the request body for encryption purposes

**Response (201 Created):**

```json
{
    "status": "success",
    "data": {
        "id": "integer",
        "service_name": "string",
        "username": "string",
        "category": "string or null",
        "created_at": "datetime"
    }
}
```

**Error Responses:**

-   400: Missing required fields
-   401: Master password verification required or invalid master password
-   500: Encryption or database error

### List Credentials

**Endpoint:** `GET /credentials/`

**Authentication Required:** Yes

**Query Parameters:**

-   `category` (optional): Filter by category

**Response (200 OK):**

```json
{
    "status": "success",
    "data": [
        {
            "id": "integer",
            "service_name": "string",
            "username": "string",
            "service_url": "string or null",
            "category": "string or null"
        }
    ]
}
```

### Get Specific Credential

**Endpoint:** `POST /credentials/<credential_id>`

**Authentication Required:** Yes

**Request:**

```json
{
    "master_password": "string"
}
```

**Response (200 OK):**

```json
{
    "status": "success",
    "data": {
        "id": "integer",
        "service_name": "string",
        "service_url": "string or null",
        "username": "string",
        "password": "string",
        "notes": "string or null",
        "category": "string or null",
        "created_at": "datetime",
        "updated_at": "datetime"
    }
}
```

**Error Responses:**

-   400: Missing master password
-   401: Invalid master password
-   403: Permission denied (credential belongs to another user)
-   404: Credential not found
-   500: Decryption error

### Update Credential

**Endpoint:** `PUT /credentials/<credential_id>`

**Authentication Required:** Yes

**Request:**

```json
{
    "master_password": "string",
    "service_name": "string (optional)",
    "service_url": "string (optional)",
    "username": "string (optional)",
    "password": "string (optional)",
    "notes": "string (optional)",
    "category": "string (optional)"
}
```

**Response (200 OK):**

```json
{
    "status": "success",
    "data": {
        "id": "integer",
        "service_name": "string",
        "username": "string",
        "category": "string or null",
        "updated_at": "datetime"
    }
}
```

**Error Responses:**

-   400: Missing master password
-   401: Invalid master password
-   403: Permission denied (credential belongs to another user)
-   404: Credential not found
-   500: Encryption or database error

### Delete Credential

**Endpoint:** `DELETE /credentials/<credential_id>`

**Authentication Required:** Yes

**Notes:**

-   No master password is required for deletion operations

**Response (200 OK):**

```json
{
    "status": "success",
    "data": "Credential deleted successfully"
}
```

**Error Responses:**

-   403: Permission denied (credential belongs to another user)
-   404: Credential not found
-   500: Database error
