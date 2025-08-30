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