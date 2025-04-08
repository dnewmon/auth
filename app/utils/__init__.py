from flask import Blueprint

# Placeholder for utility functions and potentially utility routes
utils_bp = Blueprint("utils", __name__)

# Import routes or functions if any exist within this blueprint's directory
from . import routes
