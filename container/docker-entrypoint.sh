#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Starting Auth Application Container...${NC}"

# Fix volume mount permissions
echo -e "${YELLOW}Setting up volume mount permissions...${NC}"
sudo chown -R appuser:appuser /app/config /app/db /app/ssl /app/instance 2>/dev/null || true
echo -e "${GREEN}Volume permissions updated${NC}"

# Default paths
ENV_FILE_PATH=${ENV_FILE_PATH:-/app/config/.env}
SSL_CERT_PATH=${SSL_CERT_PATH:-/app/ssl/cert.pem}
SSL_KEY_PATH=${SSL_KEY_PATH:-/app/ssl/key.pem}

# Function to generate self-signed SSL certificate
generate_ssl_cert() {
    echo -e "${YELLOW}Generating self-signed SSL certificate...${NC}"
    
    # Create SSL directory if it doesn't exist
    mkdir -p "$(dirname "$SSL_CERT_PATH")"
    
    # Generate private key and certificate
    openssl req -x509 -newkey rsa:4096 -keyout "$SSL_KEY_PATH" -out "$SSL_CERT_PATH" \
        -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
    
    # Set appropriate permissions
    chmod 600 "$SSL_KEY_PATH"
    chmod 644 "$SSL_CERT_PATH"
    
    echo -e "${GREEN}SSL certificate generated successfully${NC}"
}

# Function to run environment initialization
init_environment() {
    echo -e "${YELLOW}No .env file found. Running environment initialization...${NC}"
    
    # Create config directory if it doesn't exist
    mkdir -p "$(dirname "$ENV_FILE_PATH")"
    
    # Set default values for non-interactive initialization
    export FLASK_ENV=${FLASK_ENV:-production}
    
    # Create a basic .env file for Docker with essential settings
    cat > "$ENV_FILE_PATH" << EOF
# Flask Configuration
FLASK_ENV=${FLASK_ENV}
SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
JWT_SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")

# Database Configuration
DATABASE_URL=sqlite:///db/local.db

# Mail Configuration (Update these with your actual mail server settings)
# MAIL_SERVER=smtp.gmail.com
# MAIL_PORT=587
# MAIL_USE_TLS=true
# MAIL_USE_SSL=false
# MAIL_USERNAME=your-email@gmail.com
# MAIL_PASSWORD=your-app-password
# MAIL_DEFAULT_SENDER=noreply@yourdomain.com

# OTP Configuration
OTP_ISSUER_NAME=AuthApp

# Session Configuration
SESSION_KEY_OTP_USER_ID=otp_user_id
SESSION_KEY_OTP_SECRET_TEMP=otp_secret_temp
SESSION_KEY_EMAIL_MFA_USER_ID=email_mfa_user_id

# Template Paths
EMAIL_LOGIN_NOTIFICATION_TEMPLATE=email/login_notification.html
EMAIL_RESET_PASSWORD_TEMPLATE=email/reset_password.html
EMAIL_MFA_TEST_TEMPLATE=email/mfa_test.html

# File Names
EXPORT_CSV_FILENAME=credentials_export.csv

# Model Configuration
MODEL_ENCRYPTION_SALT_LENGTH=16
MODEL_OTP_SECRET_LENGTH=32

# Security Configuration
MIN_PASSWORD_LENGTH=12
LOG_LEVEL=INFO
EOF

    echo -e "${GREEN}Environment file created at: $ENV_FILE_PATH${NC}"
    echo -e "${YELLOW}Note: Please update mail server settings in the .env file for email functionality${NC}"
}

# Function to initialize database
init_database() {
    echo -e "${YELLOW}Initializing database...${NC}"
    
    # Create db directory if it doesn't exist
    mkdir -p /app/db
    touch /app/db/local.db
    
    # Run database initialization
    cd /app
    python init-db.py
    
    echo -e "${GREEN}Database initialized successfully${NC}"
}

# Check if .env file exists
if [ ! -f "$ENV_FILE_PATH" ]; then
    init_environment
    FIRST_RUN=true
else
    echo -e "${GREEN}Environment file found at: $ENV_FILE_PATH${NC}"
    FIRST_RUN=false
fi

# Load environment variables from the specified path
if [ -f "$ENV_FILE_PATH" ]; then
    echo -e "${BLUE}Loading environment variables from: $ENV_FILE_PATH${NC}"
    # Export all variables from the .env file
    set -a
    source "$ENV_FILE_PATH"
    set +a
fi

# Initialize database if this is the first run or if database doesn't exist
DB_PATH="/app/db/local.db"
if [ "$FIRST_RUN" = true ] || [ ! -f "$DB_PATH" ]; then
    init_database
fi

# Generate SSL certificate if it doesn't exist
if [ ! -f "$SSL_CERT_PATH" ] || [ ! -f "$SSL_KEY_PATH" ]; then
    generate_ssl_cert
else
    echo -e "${GREEN}SSL certificate found${NC}"
fi

# Verify SSL certificate exists and is readable
if [ ! -r "$SSL_CERT_PATH" ] || [ ! -r "$SSL_KEY_PATH" ]; then
    echo -e "${RED}Error: SSL certificate files are not readable${NC}"
    echo -e "${RED}Certificate path: $SSL_CERT_PATH${NC}"
    echo -e "${RED}Key path: $SSL_KEY_PATH${NC}"
    exit 1
fi

echo -e "${GREEN}Starting Flask application with SSL on port ${FLASK_RUN_PORT:-8443}...${NC}"
echo -e "${BLUE}Application will be available at: https://localhost:${FLASK_RUN_PORT:-8443}${NC}"

# Update run.py to use SSL if not already configured
cd /app

# Start the application with SSL
exec python -c "
import os
import sys
from app import create_app

env_name = os.getenv('FLASK_ENV', 'production')
app = create_app(env_name)

if __name__ == '__main__':
    import logging
    import ssl
    
    # Set up logging
    console_handler = logging.StreamHandler(stream=sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(
        logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    )
    logging.root.addHandler(console_handler)
    
    # Get configuration
    host = os.getenv('FLASK_RUN_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_RUN_PORT', 8443))
    ssl_cert = os.getenv('SSL_CERT_PATH', '/app/ssl/cert.pem')
    ssl_key = os.getenv('SSL_KEY_PATH', '/app/ssl/key.pem')
    
    # Create SSL context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(ssl_cert, ssl_key)
    
    print(f'Starting server on https://{host}:{port}')
    
    # Start the Flask app with SSL
    app.run(
        host=host,
        port=port,
        ssl_context=ssl_context,
        debug=False
    )
"