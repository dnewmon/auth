from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from datetime import timezone
import secrets
from .database import db


class EmailVerificationToken(db.Model):
    __tablename__ = "email_verification_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token = db.Column(db.String(64), nullable=False, unique=True, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)

    def __init__(self, user_id, expiry_minutes=15):
        self.user_id = user_id
        self.token = secrets.token_urlsafe(32)
        now = datetime.datetime.now(timezone.utc)
        self.created_at = now
        self.expires_at = now + datetime.timedelta(minutes=expiry_minutes)

    def is_expired(self):
        """Check if the token has expired."""
        now = datetime.datetime.now(timezone.utc)
        expires_at = self.expires_at.replace(tzinfo=timezone.utc) if self.expires_at.tzinfo is None else self.expires_at
        return now > expires_at

    def is_used(self):
        """Check if the token has been used."""
        return self.used_at is not None

    def mark_as_used(self):
        """Mark this token as used."""
        self.used_at = datetime.datetime.now(timezone.utc)

    def is_valid(self):
        """Check if the token is valid (not expired and not used)."""
        return not self.is_expired() and not self.is_used()

    @classmethod
    def create_for_user(cls, user_id, expiry_minutes=15):
        """Create a new email verification token for a user."""
        # Clean up any existing unused tokens for this user
        cls.query.filter_by(user_id=user_id, used_at=None).delete()
        db.session.commit()
        
        # Create new token
        token = cls(user_id=user_id, expiry_minutes=expiry_minutes)
        db.session.add(token)
        db.session.commit()
        return token

    @classmethod
    def find_valid_token(cls, token_string):
        """Find a valid token by token string."""
        token = cls.query.filter_by(token=token_string).first()
        if token and token.is_valid():
            return token
        return None