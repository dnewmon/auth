import datetime
import secrets
import hashlib
from . import db
from flask import current_app


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    token_hash = db.Column(db.String(128), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)

    user = db.relationship("User")

    def __init__(self, user_id, token, **kwargs):
        self.user_id = user_id
        self.token_hash = self._hash_token(token)
        # Use Flask app context to get configuration for expiration delta
        expires_delta = current_app.config.get("PASSWORD_RESET_TOKEN_EXPIRATION", datetime.timedelta(hours=1))
        self.expires_at = datetime.datetime.now(datetime.timezone.utc) + expires_delta
        super().__init__(**kwargs)

    @staticmethod
    def _hash_token(token):
        # Use SHA-256 for hashing the token before storing
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @classmethod
    def generate_token(cls):
        # Generate a URL-safe token
        return secrets.token_urlsafe(32)

    @classmethod
    def find_by_token(cls, token):
        hashed_token = cls._hash_token(token)
        return cls.query.filter_by(token_hash=hashed_token).first()

    def is_valid(self):
        return not self.used and self.expires_at > datetime.datetime.now(datetime.timezone.utc)

    def mark_as_used(self):
        self.used = True
        db.session.add(self)

    def __repr__(self):
        return f"<PasswordResetToken for User {self.user_id}>"
