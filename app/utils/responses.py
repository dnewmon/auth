from flask import jsonify, make_response

def success_response(data=None, message="Success", status_code=200):
    """Creates a standard success JSON response."""
    response_object = {
        'status': 'success',
        'message': message
    }
    if data is not None:
        response_object['data'] = data
    return make_response(jsonify(response_object), status_code)

def error_response(message, status_code):
    """Creates a standard error JSON response."""
    response_object = {
        'status': 'error',
        'message': message
    }
    return make_response(jsonify(response_object), status_code) 