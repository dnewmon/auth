from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from datetime import timezone
import os
from flask_login import UserMixin
from .database import db
from .config import get_config_value, DEFAULT_CONFIG
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import json

# Initialize the Argon2 password hasher with secure defaults
_password_hasher = PasswordHasher(
    time_cost=3,  # Number of iterations
    memory_cost=65536,  # Memory usage in KiB (64 MB)
    parallelism=4,  # Number of parallel threads
    hash_len=32,  # Length of the hash in bytes
    salt_len=16,  # Length of the random salt in bytes
)


# Model for recovery keys
class RecoveryKey(db.Model):
    __tablename__ = "recovery_keys"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    key_hash = db.Column(db.String(64), nullable=False, index=True)
    salt = db.Column(db.LargeBinary(16), nullable=False)
    encrypted_master_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(timezone.utc))
    used_at = db.Column(db.DateTime, nullable=True)

    def mark_as_used(self):
        """Mark this recovery key as used."""
        self.used_at = datetime.datetime.now(timezone.utc)


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    # Salt for deriving the user-specific credential encryption key
    # Generated once during user registration
    encryption_salt = db.Column(db.LargeBinary(get_config_value("MODEL_ENCRYPTION_SALT_LENGTH", DEFAULT_CONFIG["MODEL_ENCRYPTION_SALT_LENGTH"])), nullable=False)

    # Master Encryption Key (encrypted with KEK derived from password)
    encrypted_master_key = db.Column(db.Text, nullable=True)

    # --- MFA Fields ---
    # Store the base32 encoded secret for TOTP
    otp_secret = db.Column(db.String(get_config_value("MODEL_OTP_SECRET_LENGTH", DEFAULT_CONFIG["MODEL_OTP_SECRET_LENGTH"])), nullable=True, unique=True)
    otp_enabled = db.Column(db.Boolean, default=False, nullable=False)
    email_mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    # --- End MFA Fields ---

    # Session management
    session_version = db.Column(db.Integer, default=1, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(timezone.utc), onupdate=lambda: datetime.datetime.now(timezone.utc))

    # Relationships (e.g., with credentials)
    credentials = db.relationship("Credential", backref="owner", lazy=True, cascade="all, delete-orphan")
    recovery_keys = db.relationship("RecoveryKey", backref="user", lazy=True, cascade="all, delete-orphan")

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
        self.last_login = datetime.datetime.now(timezone.utc)
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return f"<User {self.username}>"

    # Recovery key and MEK management methods

    def initialize_encryption(self, password, master_key=None):
        """
        Initialize the two-tier encryption system.
        Generates MEK, encrypts with password, and creates recovery keys.

        Args:
            password: User's password
            master_key: Optional pre-generated master key (for tests or migrations)

        Returns:
            List of recovery keys generated
        """
        from ..utils.encryption import (
            generate_master_encryption_key,
            encrypt_master_key,
            generate_recovery_keys,
            encrypt_master_key_with_recovery_key,
        )

        # Generate or use provided master key
        mek = master_key or generate_master_encryption_key()

        # Encrypt with password-derived key
        self.encrypted_master_key = encrypt_master_key(mek, password, self.encryption_salt)

        # Generate and store recovery keys
        recovery_keys = generate_recovery_keys(5)  # Generate 5 recovery keys
        for key in recovery_keys:
            salt, encrypted_mek, key_hash = encrypt_master_key_with_recovery_key(mek, key)
            recovery_key = RecoveryKey(user_id=self.id, key_hash=key_hash, salt=salt, encrypted_master_key=encrypted_mek)
            db.session.add(recovery_key)

        return recovery_keys

    def get_master_key(self, password):
        """
        Get the master encryption key using the user's password.

        Args:
            password: User's password

        Returns:
            bytes: Master encryption key

        Raises:
            ValueError: If password is incorrect or master key cannot be decrypted
        """
        if not self.check_password(password):
            raise ValueError("Invalid password")

        if not self.encrypted_master_key:
            raise ValueError("Encryption has not been initialized")

        from ..utils.encryption import decrypt_master_key

        return decrypt_master_key(self.encrypted_master_key, password, self.encryption_salt)

    def find_recovery_key_entry(self, recovery_key):
        """
        Find the RecoveryKey entry associated with the provided recovery key.

        Args:
            recovery_key: The recovery key string (e.g., XXXX-XXXX-XXXX-XXXX)

        Returns:
            RecoveryKey or None: The recovery key entry if found
        """
        from ..utils.encryption import hash_recovery_key

        key_hash = hash_recovery_key(recovery_key)
        return RecoveryKey.query.filter_by(user_id=self.id, key_hash=key_hash).first()

    def recover_with_recovery_key(self, recovery_key, new_password):
        """
        Recover account access using a recovery key and set a new password.
        Decrypts MEK with recovery key, then re-encrypts with new password.

        Args:
            recovery_key: Recovery key string
            new_password: New password to set

        Returns:
            bool: True if recovery was successful

        Raises:
            ValueError: If recovery key is invalid or recovery fails
        """
        # Find recovery key entry
        key_entry = self.find_recovery_key_entry(recovery_key)
        if not key_entry:
            raise ValueError("Invalid recovery key")

        # Decrypt master key using recovery key
        from ..utils.encryption import decrypt_master_key_with_recovery_key, encrypt_master_key

        try:
            master_key = decrypt_master_key_with_recovery_key(key_entry.encrypted_master_key, recovery_key, key_entry.salt)

            # Set new password
            self.set_password(new_password)

            # Re-encrypt master key with new password
            self.encrypted_master_key = encrypt_master_key(master_key, new_password, self.encryption_salt)

            # Mark recovery key as used
            key_entry.mark_as_used()

            return True
        except Exception as e:
            raise ValueError(f"Recovery failed: {str(e)}")

    def regenerate_recovery_keys(self, password):
        """
        Regenerate all recovery keys.

        Args:
            password: Current password to verify and decrypt the MEK

        Returns:
            list: New recovery keys

        Raises:
            ValueError: If password is invalid
        """
        # Get master key using password
        try:
            master_key = self.get_master_key(password)
        except ValueError as e:
            raise ValueError(f"Cannot regenerate recovery keys: {str(e)}")

        # Delete existing recovery keys
        RecoveryKey.query.filter_by(user_id=self.id).delete()

        # Generate new recovery keys
        from ..utils.encryption import generate_recovery_keys, encrypt_master_key_with_recovery_key

        recovery_keys = generate_recovery_keys(5)
        for key in recovery_keys:
            salt, encrypted_mek, key_hash = encrypt_master_key_with_recovery_key(master_key, key)
            recovery_key = RecoveryKey(user_id=self.id, key_hash=key_hash, salt=salt, encrypted_master_key=encrypted_mek)
            db.session.add(recovery_key)

        return recovery_keys
