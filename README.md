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

## Docker Setup

### Prerequisites for Docker

-   Docker Engine 20.10+
-   Docker Compose 2.0+

### Quick Start with Docker

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd auth
   ```

2. **Build and run with Docker Compose**
   ```bash
   cd container
   docker-compose up -d
   ```

   The application will be available at: **https://localhost:8443**

### Docker Configuration

#### Environment Variables

The Docker setup supports the following environment variables:

- `ENV_FILE_PATH`: Path to mount your custom `.env` file (default: `./docker-volumes/config`)
- `DB_VOLUME_PATH`: Path for database persistence (default: `./docker-volumes/db`)  
- `SSL_VOLUME_PATH`: Path for SSL certificates (default: `./docker-volumes/ssl`)
- `INSTANCE_VOLUME_PATH`: Path for instance files (default: `./docker-volumes/instance`)

#### Volume Mounts

The Docker setup uses the following volume mounts:

```yaml
volumes:
  # Environment configuration
  - ${ENV_FILE_PATH:-./docker-volumes/config}:/app/config
  # Database files  
  - ${DB_VOLUME_PATH:-./docker-volumes/db}:/app/db
  # SSL certificates
  - ${SSL_VOLUME_PATH:-./docker-volumes/ssl}:/app/ssl
  # Instance configuration
  - ${INSTANCE_VOLUME_PATH:-./docker-volumes/instance}:/app/instance
```

### Custom Environment File

To use a custom `.env` file:

1. **Create your configuration directory**
   ```bash
   mkdir -p /path/to/your/config
   ```

2. **Create your `.env` file**
   ```bash
   # Example: /path/to/your/config/.env
   FLASK_ENV=production
   SECRET_KEY=your-secret-key
   JWT_SECRET_KEY=your-jwt-secret
   DATABASE_URL=sqlite:///db/local.db
   
   # Mail Configuration
   MAIL_SERVER=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USE_TLS=true
   MAIL_USERNAME=your-email@gmail.com
   MAIL_PASSWORD=your-app-password
   MAIL_DEFAULT_SENDER=noreply@yourdomain.com
   ```

3. **Run with custom environment file**
   ```bash
   ENV_FILE_PATH=/path/to/your/config docker-compose up -d
   ```

### SSL Certificates

#### Automatic SSL Certificate Generation

On first run, the container automatically generates a self-signed SSL certificate. The certificate will be stored in the SSL volume mount and reused on subsequent runs.

#### Using Custom SSL Certificates

To use your own SSL certificates:

1. **Place your certificates in the SSL volume directory**
   ```bash
   mkdir -p docker-volumes/ssl
   cp your-cert.pem docker-volumes/ssl/cert.pem
   cp your-private-key.pem docker-volumes/ssl/key.pem
   ```

2. **Ensure proper permissions**
   ```bash
   chmod 644 docker-volumes/ssl/cert.pem
   chmod 600 docker-volumes/ssl/key.pem
   ```

3. **Start the container**
   ```bash
   docker-compose up -d
   ```

### Database Persistence

The database files are stored in the database volume mount. To backup or restore:

```bash
# Backup
cp docker-volumes/db/local.db backup-$(date +%Y%m%d).db

# Restore  
cp backup-20241201.db docker-volumes/db/local.db
```

### Development with Docker

For development with live code reloading:

```bash
# Mount the source code as a volume for development
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up
```

### Logs and Monitoring

View application logs:
```bash
docker-compose logs -f auth-app
```

Check health status:
```bash
docker-compose ps
```

The container includes a health check that verifies the HTTPS endpoint every 30 seconds.

### Customizing Docker Configuration

#### Environment-Specific Configurations

Create different compose files for different environments:

```bash
# Production
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Development  
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

#### Port Configuration

To use a different port:

```bash
# Use port 9443 instead of 8443
docker-compose up -d --env FLASK_RUN_PORT=9443
```

Or modify the `docker-compose.yml` file to change the port mapping.

### Troubleshooting

#### Common Issues

1. **Permission Errors**
   ```bash
   # Fix volume permissions
   sudo chown -R 1000:1000 docker-volumes/
   ```

2. **SSL Certificate Issues**  
   ```bash
   # Regenerate SSL certificates
   rm docker-volumes/ssl/cert.pem docker-volumes/ssl/key.pem
   docker-compose restart auth-app
   ```

3. **Database Issues**
   ```bash
   # Reset database
   rm docker-volumes/db/local.db  
   docker-compose restart auth-app
   ```

4. **Environment File Not Found**
   ```bash
   # Check mount path
   docker-compose exec auth-app ls -la /app/config/
   ```
