import logging
from flask import Flask, session
from config import config_by_name
from .models import db
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_login import LoginManager, user_loaded_from_request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logger = logging.getLogger(__name__)

# Initialize Flask-Migrate
migrate = Migrate()

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.session_protection = "strong"

# Initialize Flask-Mail
mail = Mail()

# Initialize Flask-Limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://",
)


def create_app(config_name: str = "development") -> Flask:
    """Application factory function."""
    app = Flask(__name__)
    config_obj = config_by_name[config_name]
    app.config.from_object(config_obj)

    # Ensure SECRET_KEY is set (used by Flask-Login for sessions)
    if not config_obj.SECRET_KEY:
        raise RuntimeError("SECRET_KEY not set in configuration!")

    # Configure logging
    logging.basicConfig(level=getattr(logging, config_obj.LOG_LEVEL.upper(), logging.INFO))
    app.logger.info(f"Starting app with '{config_name}' config.")

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    mail.init_app(app)
    
    # Always initialize limiter, but disable it for testing
    limiter.init_app(app)
    
    # Disable rate limiting in testing mode
    if config_obj.TESTING:
        limiter.enabled = False

    # Load user callback for Flask-Login
    from .models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    @user_loaded_from_request.connect
    def check_session_version(sender, user):
        """Check if the user's session version matches their current version."""
        if user and hasattr(user, "session_version"):
            session_ver = session.get("session_version")
            if not session_ver or session_ver != user.session_version:
                # Session version mismatch, force logout
                return None
        return user

    # Register Blueprints
    from .auth import auth_bp
    from .credentials import credentials_bp
    from .users import users_bp
    from .security import security_bp
    from .utils import utils_bp  # Assuming utils might have routes later

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(credentials_bp, url_prefix="/api/credentials")
    app.register_blueprint(users_bp, url_prefix="/api/users")
    app.register_blueprint(security_bp, url_prefix="/api/security")
    app.register_blueprint(utils_bp, url_prefix="/api/utils")

    # Register error handlers
    from .middleware.error_handlers import register_error_handlers

    register_error_handlers(app)

    @app.route("/ping")
    def ping():
        return "Pong!"

    return app
