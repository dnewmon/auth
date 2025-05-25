"""
Basic tests for the Flask application setup and routing.
"""

import pytest
from app import create_app


def test_config():
    """Test that the testing configuration is being used."""
    assert not create_app('testing').testing
    app = create_app('testing')
    assert app.config['TESTING']


def test_ping_route(client):
    """Test the ping route returns expected response."""
    response = client.get('/ping')
    assert response.status_code == 200
    assert response.data == b'Pong!'


def test_app_context(app_context):
    """Test that app context is working."""
    from flask import current_app
    assert current_app.config['TESTING']


def test_database_connection(app_context):
    """Test that database connection works."""
    from app.models import db
    
    # Try a simple database operation
    result = db.engine.execute('SELECT 1 as test').fetchone()
    assert result['test'] == 1