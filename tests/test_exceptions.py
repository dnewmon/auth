"""
Unit tests for app.utils.exceptions module.

Tests all custom exception classes including APIException base class
and its specialized subclasses.
"""

import pytest
from app.utils.exceptions import (
    APIException,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict
)


class TestAPIException:
    """Tests for the base APIException class."""
    
    def test_default_initialization(self):
        """Test APIException with default parameters."""
        exc = APIException()
        
        assert exc.status_code == 500
        assert exc.message == "An unexpected error occurred."
        assert exc.payload is None
    
    def test_custom_message_initialization(self):
        """Test APIException with custom message."""
        custom_message = "Something went wrong"
        exc = APIException(message=custom_message)
        
        assert exc.status_code == 500
        assert exc.message == custom_message
        assert exc.payload is None
    
    def test_custom_status_code_initialization(self):
        """Test APIException with custom status code."""
        custom_status = 418
        exc = APIException(status_code=custom_status)
        
        assert exc.status_code == custom_status
        assert exc.message == "An unexpected error occurred."
        assert exc.payload is None
    
    def test_custom_payload_initialization(self):
        """Test APIException with custom payload."""
        custom_payload = {"details": "Additional error info"}
        exc = APIException(payload=custom_payload)
        
        assert exc.status_code == 500
        assert exc.message == "An unexpected error occurred."
        assert exc.payload == custom_payload
    
    def test_full_custom_initialization(self):
        """Test APIException with all custom parameters."""
        custom_message = "Custom error"
        custom_status = 422
        custom_payload = {"field": "username", "error": "required"}
        
        exc = APIException(
            message=custom_message,
            status_code=custom_status,
            payload=custom_payload
        )
        
        assert exc.status_code == custom_status
        assert exc.message == custom_message
        assert exc.payload == custom_payload
    
    def test_to_dict_default(self):
        """Test to_dict method with default parameters."""
        exc = APIException()
        result = exc.to_dict()
        
        expected = {
            'message': "An unexpected error occurred.",
            'status': 'error'
        }
        assert result == expected
    
    def test_to_dict_with_custom_message(self):
        """Test to_dict method with custom message."""
        custom_message = "Custom error message"
        exc = APIException(message=custom_message)
        result = exc.to_dict()
        
        expected = {
            'message': custom_message,
            'status': 'error'
        }
        assert result == expected
    
    def test_to_dict_with_payload(self):
        """Test to_dict method with payload."""
        custom_payload = {"field": "email", "code": "invalid_format"}
        exc = APIException(payload=custom_payload)
        result = exc.to_dict()
        
        expected = {
            'field': 'email',
            'code': 'invalid_format',
            'message': "An unexpected error occurred.",
            'status': 'error'
        }
        assert result == expected
    
    def test_to_dict_payload_overrides_message(self):
        """Test that payload values don't override message in to_dict."""
        # Payload with 'message' key should not override the exception message
        custom_payload = {"message": "payload message"}
        custom_message = "exception message"
        exc = APIException(message=custom_message, payload=custom_payload)
        result = exc.to_dict()
        
        # Exception message should take precedence
        expected = {
            'message': custom_message,
            'status': 'error'
        }
        assert result == expected
    
    def test_to_dict_payload_overrides_status(self):
        """Test that payload values don't override status in to_dict."""
        # Payload with 'status' key should not override the default status
        custom_payload = {"status": "payload_status"}
        exc = APIException(payload=custom_payload)
        result = exc.to_dict()
        
        # Default status should take precedence
        expected = {
            'message': "An unexpected error occurred.",
            'status': 'error'
        }
        assert result == expected
    
    def test_inheritance_from_exception(self):
        """Test that APIException properly inherits from Exception."""
        exc = APIException("Test message")
        
        assert isinstance(exc, Exception)
        assert isinstance(exc, APIException)
    
    def test_none_payload_handling(self):
        """Test that None payload is handled correctly in to_dict."""
        exc = APIException(payload=None)
        result = exc.to_dict()
        
        expected = {
            'message': "An unexpected error occurred.",
            'status': 'error'
        }
        assert result == expected


class TestBadRequest:
    """Tests for the BadRequest exception class."""
    
    def test_default_initialization(self):
        """Test BadRequest with default parameters."""
        exc = BadRequest()
        
        assert exc.status_code == 400
        assert exc.message == "Bad Request"
        assert exc.payload is None
    
    def test_custom_message_override(self):
        """Test BadRequest with custom message override."""
        custom_message = "Invalid input data"
        exc = BadRequest(message=custom_message)
        
        assert exc.status_code == 400
        assert exc.message == custom_message
        assert exc.payload is None
    
    def test_custom_status_code_override(self):
        """Test BadRequest with custom status code override."""
        custom_status = 422
        exc = BadRequest(status_code=custom_status)
        
        assert exc.status_code == custom_status
        assert exc.message == "Bad Request"
    
    def test_to_dict(self):
        """Test BadRequest to_dict method."""
        exc = BadRequest()
        result = exc.to_dict()
        
        expected = {
            'message': "Bad Request",
            'status': 'error'
        }
        assert result == expected
    
    def test_inheritance(self):
        """Test BadRequest inheritance."""
        exc = BadRequest()
        
        assert isinstance(exc, APIException)
        assert isinstance(exc, Exception)


class TestUnauthorized:
    """Tests for the Unauthorized exception class."""
    
    def test_default_initialization(self):
        """Test Unauthorized with default parameters."""
        exc = Unauthorized()
        
        assert exc.status_code == 401
        assert exc.message == "Authentication required."
        assert exc.payload is None
    
    def test_custom_message_override(self):
        """Test Unauthorized with custom message override."""
        custom_message = "Invalid credentials"
        exc = Unauthorized(message=custom_message)
        
        assert exc.status_code == 401
        assert exc.message == custom_message
        assert exc.payload is None
    
    def test_to_dict(self):
        """Test Unauthorized to_dict method."""
        exc = Unauthorized()
        result = exc.to_dict()
        
        expected = {
            'message': "Authentication required.",
            'status': 'error'
        }
        assert result == expected
    
    def test_inheritance(self):
        """Test Unauthorized inheritance."""
        exc = Unauthorized()
        
        assert isinstance(exc, APIException)
        assert isinstance(exc, Exception)


class TestForbidden:
    """Tests for the Forbidden exception class."""
    
    def test_default_initialization(self):
        """Test Forbidden with default parameters."""
        exc = Forbidden()
        
        assert exc.status_code == 403
        assert exc.message == "You do not have permission to perform this action."
        assert exc.payload is None
    
    def test_custom_message_override(self):
        """Test Forbidden with custom message override."""
        custom_message = "Access denied for this resource"
        exc = Forbidden(message=custom_message)
        
        assert exc.status_code == 403
        assert exc.message == custom_message
        assert exc.payload is None
    
    def test_to_dict(self):
        """Test Forbidden to_dict method."""
        exc = Forbidden()
        result = exc.to_dict()
        
        expected = {
            'message': "You do not have permission to perform this action.",
            'status': 'error'
        }
        assert result == expected
    
    def test_inheritance(self):
        """Test Forbidden inheritance."""
        exc = Forbidden()
        
        assert isinstance(exc, APIException)
        assert isinstance(exc, Exception)


class TestNotFound:
    """Tests for the NotFound exception class."""
    
    def test_default_initialization(self):
        """Test NotFound with default parameters."""
        exc = NotFound()
        
        assert exc.status_code == 404
        assert exc.message == "Resource not found."
        assert exc.payload is None
    
    def test_custom_message_override(self):
        """Test NotFound with custom message override."""
        custom_message = "User not found"
        exc = NotFound(message=custom_message)
        
        assert exc.status_code == 404
        assert exc.message == custom_message
        assert exc.payload is None
    
    def test_to_dict(self):
        """Test NotFound to_dict method."""
        exc = NotFound()
        result = exc.to_dict()
        
        expected = {
            'message': "Resource not found.",
            'status': 'error'
        }
        assert result == expected
    
    def test_inheritance(self):
        """Test NotFound inheritance."""
        exc = NotFound()
        
        assert isinstance(exc, APIException)
        assert isinstance(exc, Exception)


class TestConflict:
    """Tests for the Conflict exception class."""
    
    def test_default_initialization(self):
        """Test Conflict with default parameters."""
        exc = Conflict()
        
        assert exc.status_code == 409
        assert exc.message == "Conflict occurred."
        assert exc.payload is None
    
    def test_custom_message_override(self):
        """Test Conflict with custom message override."""
        custom_message = "Email already exists"
        exc = Conflict(message=custom_message)
        
        assert exc.status_code == 409
        assert exc.message == custom_message
        assert exc.payload is None
    
    def test_to_dict(self):
        """Test Conflict to_dict method."""
        exc = Conflict()
        result = exc.to_dict()
        
        expected = {
            'message': "Conflict occurred.",
            'status': 'error'
        }
        assert result == expected
    
    def test_inheritance(self):
        """Test Conflict inheritance."""
        exc = Conflict()
        
        assert isinstance(exc, APIException)
        assert isinstance(exc, Exception)


class TestExceptionIntegration:
    """Integration tests for exception behavior."""
    
    def test_all_exceptions_have_correct_status_codes(self):
        """Test that all exception classes have the correct status codes."""
        exceptions_and_codes = [
            (APIException, 500),
            (BadRequest, 400),
            (Unauthorized, 401),
            (Forbidden, 403),
            (NotFound, 404),
            (Conflict, 409)
        ]
        
        for exception_class, expected_code in exceptions_and_codes:
            exc = exception_class()
            assert exc.status_code == expected_code
    
    def test_all_exceptions_implement_to_dict(self):
        """Test that all exception classes implement to_dict method."""
        exception_classes = [
            APIException,
            BadRequest,
            Unauthorized,
            Forbidden,
            NotFound,
            Conflict
        ]
        
        for exception_class in exception_classes:
            exc = exception_class()
            result = exc.to_dict()
            
            assert isinstance(result, dict)
            assert 'message' in result
            assert 'status' in result
            assert result['status'] == 'error'
    
    def test_exception_raising_and_catching(self):
        """Test that exceptions can be raised and caught properly."""
        exception_classes = [
            APIException,
            BadRequest,
            Unauthorized,
            Forbidden,
            NotFound,
            Conflict
        ]
        
        for exception_class in exception_classes:
            with pytest.raises(exception_class):
                raise exception_class("Test message")
            
            # Test catching as APIException
            try:
                raise exception_class("Test message")
            except APIException as e:
                assert isinstance(e, exception_class)
                assert e.message == "Test message"
            
            # Test catching as Exception
            try:
                raise exception_class("Test message")
            except Exception as e:
                assert isinstance(e, exception_class)
    
    def test_payload_with_complex_data(self):
        """Test exceptions with complex payload data."""
        complex_payload = {
            "errors": [
                {"field": "email", "message": "Invalid format"},
                {"field": "password", "message": "Too short"}
            ],
            "timestamp": "2023-01-01T00:00:00Z",
            "request_id": "req_123456"
        }
        
        exc = BadRequest(
            message="Validation failed",
            payload=complex_payload
        )
        
        result = exc.to_dict()
        
        # Check that all payload data is included
        assert result["errors"] == complex_payload["errors"]
        assert result["timestamp"] == complex_payload["timestamp"]
        assert result["request_id"] == complex_payload["request_id"]
        
        # Check that standard fields are still present
        assert result["message"] == "Validation failed"
        assert result["status"] == "error"