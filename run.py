import os
from app import create_app

# Load configuration based on FLASK_ENV environment variable
# Defaults to 'development' if not set
env_name = os.getenv("FLASK_ENV", "development")
app = create_app(env_name)

if __name__ == "__main__":
    # Get host and port from environment variables or use defaults
    host = os.getenv("FLASK_RUN_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_RUN_PORT", 5002))

    print(app.url_map)

    # Use app.run() for development server
    # For production, use a proper WSGI server like Gunicorn or uWSGI
    app.run(host=host, port=port)
