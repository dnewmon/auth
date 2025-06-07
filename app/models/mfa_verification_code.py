import datetime
from datetime import timezone
import secrets
import string
from .database import db


class MfaVerificationCode(db.Model):
    __tablename__ = "mfa_verification_codes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    code = db.Column(db.String(10), nullable=False, index=True)
    purpose = db.Column(db.String(20), nullable=False)  # 'login' or 'disable_mfa'
    created_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)

    def __init__(self, user_id, purpose, expiry_minutes=15):
        self.user_id = user_id
        self.purpose = purpose
        self.code = self._generate_code()
        self.created_at = datetime.datetime.now(timezone.utc)
        self.expires_at = self.created_at + datetime.timedelta(minutes=expiry_minutes)

    def _generate_code(self):
        """Generate a 6-digit verification code."""
        return ''.join(secrets.choice(string.digits) for _ in range(6))

    def is_expired(self):
        """Check if the code has expired."""
        now = datetime.datetime.now(timezone.utc)
        expires_at = self.expires_at.replace(tzinfo=timezone.utc) if self.expires_at.tzinfo is None else self.expires_at
        return now > expires_at

    def is_used(self):
        """Check if the code has been used."""
        return self.used_at is not None

    def mark_as_used(self):
        """Mark this code as used."""
        self.used_at = datetime.datetime.now(timezone.utc)

    def is_valid(self):
        """Check if the code is valid (not expired and not used)."""
        return not self.is_expired() and not self.is_used()

    @classmethod
    def create_for_user(cls, user_id, purpose, expiry_minutes=15):
        """Create a new MFA verification code for a user."""
        # Clean up any existing unused codes for this user and purpose
        cls.query.filter_by(user_id=user_id, purpose=purpose, used_at=None).delete()
        db.session.commit()
        
        # Create new code
        code = cls(user_id=user_id, purpose=purpose, expiry_minutes=expiry_minutes)
        db.session.add(code)
        db.session.commit()
        return code

    @classmethod
    def find_valid_code(cls, user_id, code_string, purpose):
        """Find a valid code by user ID, code string, and purpose."""
        code = cls.query.filter_by(user_id=user_id, code=code_string, purpose=purpose).first()
        if code and code.is_valid():
            return code
        return None