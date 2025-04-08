from flask import Blueprint

# Define the blueprint
# The first argument is the blueprint name, the second is the import name,
# and the third is the URL prefix for all routes in this blueprint.
credentials_bp = Blueprint('credentials', __name__, url_prefix='/api/credentials')

# Import the routes module at the end to avoid circular dependencies
# This line should be uncommented or added after routes.py is created
from . import routes 