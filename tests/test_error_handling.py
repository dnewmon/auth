"""
Unit tests for comprehensive error handling middleware.

Tests various error scenarios and ensures appropriate responses.
"""

import pytest
import json
from unittest.mock import patch, Mock
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound

from app.middleware.error_handlers import (
    handle_bad_request, handle_unauthorized, handle_forbidden, handle_not_found,
    handle_integrity_error, handle_value_error, handle_key_error, handle_generic_exception
)


class TestErrorHandlers:
    """Tests for individual error handler functions."""
    
    def test_handle_bad_request(self, client, app_context):
        """Test bad request error handler."""
        with client.application.test_request_context():
            error = BadRequest("Invalid input")
            response = handle_bad_request(error)
            
            assert response.status_code == 400
            data = json.loads(response.data)
            assert data['status'] == 'error'
            assert 'invalid request data' in data['message'].lower()
    
    def test_handle_unauthorized(self, app_context):
        """Test unauthorized error handler."""
        with patch('app.middleware.error_handlers.request') as mock_request:
            mock_request.url = "http://example.com/test"
            mock_request.remote_addr = "127.0.0.1"
            
            error = Unauthorized("Authentication required")
            response = handle_unauthorized(error)
            
            assert response.status_code == 401
            data = json.loads(response.data)
            assert data['status'] == 'error'
            assert 'authentication required' in data['message'].lower()
    
    def test_handle_forbidden(self, app_context):
        """Test forbidden error handler."""
        with patch('app.middleware.error_handlers.request') as mock_request:
            mock_request.url = "http://example.com/test"
            mock_request.current_user = "testuser"
            
            error = Forbidden("Access denied")
            response = handle_forbidden(error)
            
            assert response.status_code == 403
            data = json.loads(response.data)
            assert data['status'] == 'error'
            assert 'permission' in data['message'].lower()
    
    def test_handle_not_found(self, app_context):
        """Test not found error handler."""
        with patch('app.middleware.error_handlers.request') as mock_request:
            mock_request.url = "http://example.com/test"
            
            error = NotFound("Resource not found")
            response = handle_not_found(error)
            
            assert response.status_code == 404
            data = json.loads(response.data)
            assert data['status'] == 'error'
            assert 'not found' in data['message'].lower()
    
    def test_handle_integrity_error_unique_username(self, app_context):
        """Test integrity error handler for unique username constraint."""
        with patch('app.middleware.error_handlers.request') as mock_request:
            mock_request.url = "http://example.com/test"
            
            # Mock IntegrityError with username constraint violation
            orig_error = Mock()
            orig_error.__str__ = lambda self: "UNIQUE constraint failed: users.username"
            
            error = IntegrityError("statement", "params", orig_error)
            response = handle_integrity_error(error)
            
            assert response.status_code == 409
            data = json.loads(response.data)
            assert data['status'] == 'error'
            assert 'username already exists' in data['message'].lower()
    
    def test_handle_integrity_error_unique_email(self, app_context):
        """Test integrity error handler for unique email constraint."""
        with patch('app.middleware.error_handlers.request') as mock_request:
            mock_request.url = "http://example.com/test"
            
            # Mock IntegrityError with email constraint violation
            orig_error = Mock()
            orig_error.__str__ = lambda self: "UNIQUE constraint failed: users.email"
            
            error = IntegrityError("statement", "params", orig_error)
            response = handle_integrity_error(error)
            
            assert response.status_code == 409
            data = json.loads(response.data)
            assert data['status'] == 'error'
            assert 'email address already registered' in data['message'].lower()
    
    def test_handle_value_error_password(self, app_context):
        """Test value error handler for password-related errors."""
        with patch('app.middleware.error_handlers.request') as mock_request:
            mock_request.url = "http://example.com/test"
            
            error = ValueError("Invalid password format")
            response = handle_value_error(error)
            
            assert response.status_code == 400
            data = json.loads(response.data)
            assert data['status'] == 'error'
            assert 'password' in data['message'].lower()
    
    def test_handle_value_error_encryption(self, app_context):
        """Test value error handler for encryption-related errors."""
        with patch('app.middleware.error_handlers.request') as mock_request:
            mock_request.url = "http://example.com/test"
            
            error = ValueError("Decryption failed - data may be corrupt")
            response = handle_value_error(error)
            
            assert response.status_code == 400
            data = json.loads(response.data)
            assert data['status'] == 'error'
            assert 'encryption' in data['message'].lower()
    
    def test_handle_key_error(self, app_context):
        """Test key error handler for missing fields."""
        with patch('app.middleware.error_handlers.request') as mock_request:
            mock_request.url = "http://example.com/test"
            
            error = KeyError("'master_password'")
            response = handle_key_error(error)
            
            assert response.status_code == 400
            data = json.loads(response.data)
            assert data['status'] == 'error'
            assert 'master_password' in data['message']
    
    def test_handle_generic_exception_development(self, app_context):
        """Test generic exception handler in development mode."""
        with patch('app.middleware.error_handlers.request') as mock_request, \
             patch('app.middleware.error_handlers.current_app') as mock_app:
            
            mock_request.url = "http://example.com/test"
            mock_request.method = "POST"
            mock_request.remote_addr = "127.0.0.1"
            mock_app.config.get.return_value = "development"
            mock_app.logger.error = Mock()
            
            error = Exception("Test exception")
            response = handle_generic_exception(error)
            
            assert response.status_code == 500
            data = json.loads(response.data)
            assert data['status'] == 'error'
            assert 'test exception' in data['message'].lower()
            assert 'id:' in data['message'].lower()
    
    def test_handle_generic_exception_production(self, app_context):
        """Test generic exception handler in production mode."""
        with patch('app.middleware.error_handlers.request') as mock_request, \
             patch('app.middleware.error_handlers.current_app') as mock_app:
            
            mock_request.url = "http://example.com/test"
            mock_request.method = "POST"
            mock_request.remote_addr = "127.0.0.1"
            mock_app.config.get.return_value = "production"
            mock_app.logger.error = Mock()
            
            error = Exception("Test exception")
            response = handle_generic_exception(error)
            
            assert response.status_code == 500
            data = json.loads(response.data)
            assert data['status'] == 'error'
            # Should not expose internal error details in production
            assert 'test exception' not in data['message'].lower()
            assert 'error id:' in data['message'].lower()


class TestErrorHandlerIntegration:
    """Integration tests for error handling in actual endpoints."""
    
    def test_missing_json_body_error(self, client, app_context):
        """Test error handling for missing JSON body."""
        response = client.post('/api/auth/login',
                             content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['status'] == 'error'
        assert 'required' in data['message'].lower()
    
    def test_invalid_endpoint_error(self, client, app_context):
        """Test error handling for invalid endpoint."""
        response = client.get('/api/nonexistent/endpoint')
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert data['status'] == 'error'
        assert 'not found' in data['message'].lower()
    
    def test_method_not_allowed_error(self, client, app_context):
        """Test error handling for wrong HTTP method."""
        response = client.put('/api/auth/login')  # Login only accepts POST
        
        assert response.status_code == 405
        data = json.loads(response.data)
        assert data['status'] == 'error'
        assert 'not allowed' in data['message'].lower()


class TestErrorLogging:
    """Tests for error logging functionality."""
    
    def test_error_logging_includes_context(self, app_context):
        """Test that error logging includes request context."""
        with patch('app.middleware.error_handlers.request') as mock_request, \
             patch('app.middleware.error_handlers.current_app') as mock_app:
            
            mock_request.url = "http://example.com/test"
            mock_request.method = "POST"
            mock_request.remote_addr = "192.168.1.1"
            mock_app.logger.warning = Mock()
            
            error = ValueError("Test error")
            handle_value_error(error)
            
            # Verify logging was called with context
            mock_app.logger.warning.assert_called_once()
            log_call = mock_app.logger.warning.call_args[0][0]
            assert "test error" in log_call.lower()
            assert "http://example.com/test" in log_call
    
    def test_generic_exception_logging_includes_traceback(self, app_context):
        """Test that generic exceptions are logged with full traceback."""
        with patch('app.middleware.error_handlers.request') as mock_request, \
             patch('app.middleware.error_handlers.current_app') as mock_app:
            
            mock_request.url = "http://example.com/test"
            mock_request.method = "GET"
            mock_request.remote_addr = "10.0.0.1"
            mock_app.config.get.return_value = "development"
            mock_app.logger.error = Mock()
            
            error = Exception("Critical error")
            handle_generic_exception(error)
            
            # Verify error logging was called with exc_info=True for traceback
            mock_app.logger.error.assert_called_once()
            call_args, call_kwargs = mock_app.logger.error.call_args
            assert call_kwargs.get('exc_info') is True
            assert "critical error" in call_args[0].lower()