from flask import Blueprint

security_bp = Blueprint('security', __name__)

# Import routes after blueprint creation
from . import routes 