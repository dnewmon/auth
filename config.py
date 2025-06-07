import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))

# print(' Environment Variables '.center(80, '-'))
# for key, value in os.environ.items():
#     print(f"{key}: {value}")
# print(' Environment Variables '.center(80, '-'))


class Config:
    """Base configuration."""

    TESTING = False
    # Core Flask settings - Enforce via environment variables
    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")

    # Optional / Defaultable Settings
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    MIN_PASSWORD_LENGTH = int(os.environ.get("MIN_PASSWORD_LENGTH", 12))

    # Mail Configuration (enforce credentials via env)
    MAIL_SERVER = os.environ.get("MAIL_SERVER")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "true").lower() in ["true", "1", "t"]
    MAIL_USE_SSL = os.environ.get("MAIL_USE_SSL", "false").lower() in ["true", "1", "t"]
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.environ.get(
        "MAIL_DEFAULT_SENDER", "noreply@example.com"
    )  # Keep default for convenience, but recommend override

    # OTP Configuration
    OTP_ISSUER_NAME = os.environ.get(
        "OTP_ISSUER_NAME", "PasswordManagerApp"
    )  # Keep default for convenience

    # Session Keys
    SESSION_KEY_OTP_USER_ID = os.environ.get("SESSION_KEY_OTP_USER_ID", "otp_user_id")
    SESSION_KEY_OTP_SECRET_TEMP = os.environ.get(
        "SESSION_KEY_OTP_SECRET_TEMP", "otp_secret_temp"
    )
    SESSION_KEY_EMAIL_MFA_USER_ID = os.environ.get("SESSION_KEY_EMAIL_MFA_USER_ID", "email_mfa_user_id")

    # Template Paths
    EMAIL_LOGIN_NOTIFICATION_TEMPLATE = os.environ.get(
        "EMAIL_LOGIN_NOTIFICATION_TEMPLATE", "email/login_notification.html"
    )
    EMAIL_RESET_PASSWORD_TEMPLATE = os.environ.get(
        "EMAIL_RESET_PASSWORD_TEMPLATE", "email/reset_password.html"
    )
    EMAIL_MFA_TEST_TEMPLATE = os.environ.get(
        "EMAIL_MFA_TEST_TEMPLATE", "email/mfa_test.html"
    )

    # File Names
    EXPORT_CSV_FILENAME = os.environ.get(
        "EXPORT_CSV_FILENAME", "credentials_export.csv"
    )

    # Model Configuration
    MODEL_ENCRYPTION_SALT_LENGTH = int(
        os.environ.get("MODEL_ENCRYPTION_SALT_LENGTH", 16)
    )
    MODEL_OTP_SECRET_LENGTH = int(os.environ.get("MODEL_OTP_SECRET_LENGTH", 32))

    # Add other configurations here


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True
    TESTING = False
    FLASK_ENV = "development"


class TestingConfig(Config):
    """Testing configuration."""

    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "TEST_DATABASE_URL", "sqlite:///:memory:"
    )  # Allow in-memory for testing default
    WTF_CSRF_ENABLED = False  # Disable CSRF forms validation for testing
    LOG_LEVEL = "DEBUG"

    # Override SECRET_KEY and JWT_SECRET_KEY with defaults for testing
    SECRET_KEY = os.environ.get("SECRET_KEY", "test-secret-key-for-testing")
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "test-jwt-secret-key-for-testing")

    # Mail configuration for testing
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "localhost")
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "test@example.com")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "testpassword")


class ProductionConfig(Config):
    """Production configuration."""

    FLASK_ENV = "production"
    DEBUG = False
    TESTING = False
    # Add production-specific settings like secure session cookies, etc.


# Dictionary to easily access config classes by name
config_by_name = dict(
    development=DevelopmentConfig,
    testing=TestingConfig,
    production=ProductionConfig,
    default=DevelopmentConfig,
)


def get_config():
    """Helper function to get the configuration object based on FLASK_ENV."""
    env = os.getenv("FLASK_ENV", "default")
    return config_by_name.get(env, DevelopmentConfig)
