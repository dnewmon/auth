from flask import Blueprint

users_bp = Blueprint('users', __name__)

# Import routes after blueprint creation
from . import routes 