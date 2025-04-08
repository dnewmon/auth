from flask import Flask, current_app
from werkzeug.exceptions import HTTPException
from ..utils.responses import error_response
from ..utils.exceptions import APIException


def handle_api_exception(error: APIException):
    """Handles custom APIExceptions."""
    current_app.logger.warning(f"API Exception: {error.message} (Status: {error.status_code})")
    response = error_response(error.message, error.status_code)
    # You could add more details from error.to_dict() if needed
    return response

def handle_http_exception(error: HTTPException):
    """Handles standard HTTPExceptions from Werkzeug."""
    current_app.logger.warning(f"HTTP Exception: {error.name} (Status: {error.code}) - {error.description}")
    response = error_response(error.description or error.name, error.code)
    return response

def handle_generic_exception(error: Exception):
    """Handles unexpected errors (500 Internal Server Error)."""
    current_app.logger.error(f"Unhandled Exception: {error}", exc_info=True)
    response = error_response("An internal server error occurred.", 500)
    return response

def register_error_handlers(app: Flask):
    """Registers error handlers with the Flask app."""
    app.register_error_handler(APIException, handle_api_exception)
    app.register_error_handler(HTTPException, handle_http_exception)
    app.register_error_handler(Exception, handle_generic_exception)
