"""
Pytest configuration and fixtures for the auth application test suite.
"""

import pytest
import os
import tempfile
from app import create_app, db
from config import TestingConfig


@pytest.fixture(scope='session')
def app():
    """Create a Flask application configured for testing."""
    # Set required environment variables for testing
    os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-testing')
    os.environ.setdefault('JWT_SECRET_KEY', 'test-jwt-secret-key-for-testing')
    os.environ.setdefault('DATABASE_URL', 'sqlite:///:memory:')
    os.environ.setdefault('MAIL_SERVER', 'localhost')
    os.environ.setdefault('MAIL_USERNAME', 'test@example.com')
    os.environ.setdefault('MAIL_PASSWORD', 'testpassword')
    
    # Create a temporary database file for testing
    db_fd, db_path = tempfile.mkstemp()
    
    # Override database URI to use temporary file
    os.environ['DATABASE_URL'] = f'sqlite:///{db_path}'
    
    app = create_app('testing')
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()
    
    # Clean up the temporary database file
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture(scope='function')
def client(app):
    """Create a test client for the Flask application."""
    return app.test_client()


@pytest.fixture(scope='function')
def app_context(app):
    """Create an application context for tests that need it."""
    with app.app_context():
        yield app


@pytest.fixture(scope='function')
def request_context(app):
    """Create a request context for tests that need it."""
    with app.test_request_context():
        yield app