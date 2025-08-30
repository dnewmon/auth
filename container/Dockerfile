FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Create a non-root user
RUN groupadd -r appuser && useradd --no-log-init -r -g appuser -u 1000 appuser

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Upgrade pip
RUN pip install --upgrade pip

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Copy the entrypoint script
COPY container/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create directories that might be needed
RUN mkdir -p /app/db /app/ssl

# Configure sudo for appuser (no password required for chown commands)
RUN echo "appuser ALL=(root) NOPASSWD: /bin/chown" >> /etc/sudoers

# Switch to non-root user
USER appuser

# Expose port 8443 for HTTPS
EXPOSE 8443

# Set entrypoint
ENTRYPOINT ["docker-entrypoint.sh"]

# Default command
CMD ["python", "run.py"]