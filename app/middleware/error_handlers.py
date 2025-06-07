from flask import Flask, current_app, request
from werkzeug.exceptions import HTTPException, BadRequest, Unauthorized, Forbidden, NotFound, MethodNotAllowed, TooManyRequests
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
import traceback
from ..utils.responses import error_response
from ..utils.exceptions import APIException


def handle_api_exception(error: APIException):
    """Handles custom APIExceptions."""
    current_app.logger.warning(f"API Exception: {error.message} (Status: {error.status_code})")
    response = error_response(error.message, error.status_code)
    return response


def handle_bad_request(error: BadRequest):
    """Handles 400 Bad Request errors."""
    current_app.logger.warning(f"Bad Request: {error.description} - URL: {request.url}")
    return error_response("Invalid request data. Please check your input and try again.", 400)


def handle_unauthorized(error: Unauthorized):
    """Handles 401 Unauthorized errors."""
    current_app.logger.warning(f"Unauthorized access attempt - URL: {request.url} - IP: {request.remote_addr}")
    return error_response("Authentication required. Please log in and try again.", 401)


def handle_forbidden(error: Forbidden):
    """Handles 403 Forbidden errors."""
    current_app.logger.warning(f"Forbidden access attempt - URL: {request.url} - User: {getattr(request, 'current_user', 'Anonymous')}")
    return error_response("You do not have permission to access this resource.", 403)


def handle_not_found(error: NotFound):
    """Handles 404 Not Found errors."""
    current_app.logger.info(f"Resource not found - URL: {request.url}")
    return error_response("The requested resource was not found.", 404)


def handle_method_not_allowed(error: MethodNotAllowed):
    """Handles 405 Method Not Allowed errors."""
    current_app.logger.warning(f"Method not allowed: {request.method} - URL: {request.url}")
    return error_response(f"Method {request.method} is not allowed for this endpoint.", 405)


def handle_too_many_requests(error: TooManyRequests):
    """Handles 429 Too Many Requests errors."""
    current_app.logger.warning(f"Rate limit exceeded - URL: {request.url} - IP: {request.remote_addr}")
    return error_response("Too many requests. Please slow down and try again later.", 429)




def handle_integrity_error(error: IntegrityError):
    """Handles database integrity constraint violations."""
    current_app.logger.warning(f"Database integrity error: {str(error.orig)} - URL: {request.url}")
    
    # Extract meaningful error messages from common integrity violations
    error_msg = str(error.orig).lower()
    if "unique constraint" in error_msg:
        if "username" in error_msg:
            return error_response("Username already exists. Please choose a different username.", 409)
        elif "email" in error_msg:
            return error_response("Email address already registered. Please use a different email.", 409)
        else:
            return error_response("A record with this information already exists.", 409)
    elif "foreign key constraint" in error_msg:
        return error_response("Referenced resource not found or has been deleted.", 400)
    elif "not null constraint" in error_msg:
        return error_response("Required field missing. Please check your input.", 400)
    else:
        return error_response("Database constraint violation. Please check your input.", 400)


def handle_sqlalchemy_error(error: SQLAlchemyError):
    """Handles general SQLAlchemy database errors."""
    current_app.logger.error(f"Database error: {str(error)} - URL: {request.url}", exc_info=True)
    return error_response("A database error occurred. Please try again later.", 500)


def handle_value_error(error: ValueError):
    """Handles ValueError exceptions (often from validation)."""
    current_app.logger.warning(f"Value error: {str(error)} - URL: {request.url}")
    
    # Common value errors in our application
    error_msg = str(error).lower()
    if "password" in error_msg:
        return error_response("Invalid password or password format.", 400)
    elif "email" in error_msg:
        return error_response("Invalid email format.", 400)
    elif "encryption" in error_msg or "decrypt" in error_msg:
        return error_response("Encryption/decryption error. Please verify your credentials.", 400)
    else:
        return error_response("Invalid input value. Please check your data.", 400)


def handle_key_error(error: KeyError):
    """Handles KeyError exceptions (missing required fields)."""
    current_app.logger.warning(f"Missing required field: {str(error)} - URL: {request.url}")
    return error_response(f"Missing required field: {str(error).strip('\"\'')}", 400)


def handle_type_error(error: TypeError):
    """Handles TypeError exceptions."""
    current_app.logger.warning(f"Type error: {str(error)} - URL: {request.url}")
    return error_response("Invalid data type in request. Please check your input format.", 400)


def handle_http_exception(error: HTTPException):
    """Handles standard HTTPExceptions from Werkzeug (fallback)."""
    current_app.logger.warning(f"HTTP Exception: {error.name} (Status: {error.code}) - {error.description}")
    response = error_response(error.description or error.name, error.code)
    return response


def handle_generic_exception(error: Exception):
    """Handles unexpected errors (500 Internal Server Error)."""
    # Generate a unique error ID for tracking
    import uuid
    error_id = str(uuid.uuid4())[:8]
    
    # Log the full exception with traceback
    current_app.logger.error(
        f"Unhandled Exception [ID: {error_id}]: {str(error)} - URL: {request.url} - "
        f"Method: {request.method} - IP: {request.remote_addr}",
        exc_info=True
    )
    
    # In production, don't expose internal error details
    if current_app.config.get('ENV') == 'production':
        message = f"An internal server error occurred. Error ID: {error_id}"
    else:
        message = f"An internal server error occurred: {str(error)} (ID: {error_id})"
    
    return error_response(message, 500)

def register_error_handlers(app: Flask):
    """Registers comprehensive error handlers with the Flask app."""
    # Custom API exceptions
    app.register_error_handler(APIException, handle_api_exception)
    
    # HTTP exceptions (specific)
    app.register_error_handler(BadRequest, handle_bad_request)
    app.register_error_handler(Unauthorized, handle_unauthorized)
    app.register_error_handler(Forbidden, handle_forbidden)
    app.register_error_handler(NotFound, handle_not_found)
    app.register_error_handler(MethodNotAllowed, handle_method_not_allowed)
    app.register_error_handler(TooManyRequests, handle_too_many_requests)
    
    # Database errors
    app.register_error_handler(IntegrityError, handle_integrity_error)
    app.register_error_handler(SQLAlchemyError, handle_sqlalchemy_error)
    
    
    # Python built-in exceptions
    app.register_error_handler(ValueError, handle_value_error)
    app.register_error_handler(KeyError, handle_key_error)
    app.register_error_handler(TypeError, handle_type_error)
    
    # Fallback handlers (order matters - more specific first)
    app.register_error_handler(HTTPException, handle_http_exception)
    app.register_error_handler(Exception, handle_generic_exception)
    
    app.logger.info("Comprehensive error handlers registered successfully")
