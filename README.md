# Project Setup Instructions

## Prerequisites

-   Python 3.8+
-   Node.js 18+
-   npm or yarn

## Initial Setup

1. Clone the repository
2. Create a Python virtual environment:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use: venv\Scripts\activate
    ```
3. Install Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```
4. Install UI dependencies:
    ```bash
    cd ui
    npm install
    ```

## Configuration

1. Initialize the environment configuration:

    ```bash
    python init-env.py
    ```

    This script will:

    - Generate secure random keys
    - Set up database configuration
    - Configure email settings (optional)
    - Create a `.env` file from `.env.example`

2. Initialize the database:
    ```bash
    python init-db.py
    ```

## Running the Application

1. Start the backend server:

    ```bash
    python run.py
    ```

    The API will be available at http://127.0.0.1:5002

2. Start the frontend development server:
    ```bash
    cd ui
    npm run dev
    ```
    The UI will be available at http://localhost:5000

## Development Configuration Options

The following environment variables can be configured in `.env`:

### Required Settings

-   `FLASK_ENV`: development/production/testing
-   `SECRET_KEY`: Session management key
-   `JWT_SECRET_KEY`: JWT token signing key
-   `DATABASE_URL`: Database connection string

### Optional Settings

-   Email Configuration (SMTP)
-   Security Settings
-   OTP Configuration
-   Logging Options
-   Session Keys
-   Model Configuration
-   Template Paths
-   Export Settings

See `.env.example` for all available configuration options.
