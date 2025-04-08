from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import os
from flask_login import UserMixin
from .database import db
from .config import get_config_value, DEFAULT_CONFIG
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Initialize the Argon2 password hasher with secure defaults
_password_hasher = PasswordHasher(
    time_cost=3,  # Number of iterations
    memory_cost=65536,  # Memory usage in KiB (64 MB)
    parallelism=4,  # Number of parallel threads
    hash_len=32,  # Length of the hash in bytes
    salt_len=16  # Length of the random salt in bytes
)

class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    # Salt for deriving the user-specific credential encryption key
    # Generated once during user registration
    encryption_salt = db.Column(db.LargeBinary(get_config_value("MODEL_ENCRYPTION_SALT_LENGTH", DEFAULT_CONFIG["MODEL_ENCRYPTION_SALT_LENGTH"])), nullable=False)

    # --- MFA Fields ---
    # Store the base32 encoded secret for TOTP
    otp_secret = db.Column(db.String(get_config_value("MODEL_OTP_SECRET_LENGTH", DEFAULT_CONFIG["MODEL_OTP_SECRET_LENGTH"])), nullable=True, unique=True)
    otp_enabled = db.Column(db.Boolean, default=False, nullable=False)
    email_mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    # --- End MFA Fields ---

    # Session management
    session_version = db.Column(db.Integer, default=1, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    # Relationships (e.g., with credentials)
    credentials = db.relationship("Credential", backref="owner", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        # Use argon2-cffi directly for password hashing
        self.password_hash = _password_hasher.hash(password)
        # Increment session version to invalidate existing sessions
        self.increment_session_version()

    def check_password(self, password):
        try:
            # Verify password using argon2-cffi
            _password_hasher.verify(self.password_hash, password)
            # Check if the hash needs to be updated to a newer format/parameters
            if _password_hasher.check_needs_rehash(self.password_hash):
                self.set_password(password)
            return True
        except VerifyMismatchError:
            return False

    def increment_session_version(self):
        """Increment the session version to invalidate all existing sessions."""
        self.session_version = (self.session_version or 1) + 1

    def update_last_login(self):
        """Update the last login timestamp."""
        self.last_login = datetime.datetime.utcnow()
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return f"<User {self.username}>"
