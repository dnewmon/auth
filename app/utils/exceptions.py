class APIException(Exception):
    """Base class for custom API exceptions."""
    status_code = 500
    message = "An unexpected error occurred."

    def __init__(self, message=None, status_code=None, payload=None):
        super().__init__()
        if message is not None:
            self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        rv['status'] = 'error'
        return rv

class BadRequest(APIException):
    """Custom exception for 400 Bad Request."""
    status_code = 400
    message = "Bad Request"

class Unauthorized(APIException):
    """Custom exception for 401 Unauthorized."""
    status_code = 401
    message = "Authentication required."

class Forbidden(APIException):
    """Custom exception for 403 Forbidden."""
    status_code = 403
    message = "You do not have permission to perform this action."

class NotFound(APIException):
    """Custom exception for 404 Not Found."""
    status_code = 404
    message = "Resource not found."

class Conflict(APIException):
    """Custom exception for 409 Conflict."""
    status_code = 409
    message = "Conflict occurred." 