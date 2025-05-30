from . import db
from datetime import datetime, timezone


class Credential(db.Model):
    __tablename__ = "credentials"
    __mapper_args__ = {"confirm_deleted_rows": False}

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    # Fields for the credential itself
    service_name = db.Column(db.String(100), nullable=False)
    service_url = db.Column(db.String(255), nullable=True)
    username = db.Column(db.String(100), nullable=False)
    # Store encrypted password as text (base64 encoded result from encryption)
    encrypted_password = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text, nullable=True)  # Also potentially encrypt this?
    category = db.Column(db.String(50), nullable=True, index=True)  # New category field

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<Credential for {self.service_name} (User {self.user_id})>"
