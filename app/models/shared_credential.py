from . import db
from datetime import datetime, timezone


class SharedCredential(db.Model):
    """
    Model for managing credential sharing between users.
    Allows secure sharing of credentials without exposing raw data.
    """
    __tablename__ = "shared_credentials"

    id = db.Column(db.Integer, primary_key=True)
    
    # The credential being shared
    credential_id = db.Column(db.Integer, db.ForeignKey("credentials.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # User who owns the credential (sharer)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # User who receives the shared credential (recipient)
    recipient_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Encrypted copy of the credential data for the recipient
    # This allows the recipient to decrypt it with their own master key
    encrypted_data_for_recipient = db.Column(db.Text, nullable=False)
    
    # Sharing permissions
    can_view = db.Column(db.Boolean, default=True, nullable=False)
    can_edit = db.Column(db.Boolean, default=False, nullable=False)
    
    # Optional expiration date for the share
    expires_at = db.Column(db.DateTime, nullable=True)
    
    # Status tracking
    status = db.Column(db.String(20), default='pending', nullable=False)  # pending, accepted, rejected, revoked
    
    # Optional message from sharer to recipient
    message = db.Column(db.Text, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    accepted_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    credential = db.relationship("Credential", backref="shares")
    owner = db.relationship("User", foreign_keys=[owner_id], backref="shared_credentials")
    recipient = db.relationship("User", foreign_keys=[recipient_id], backref="received_credentials")
    
    # Indexes for common queries
    __table_args__ = (
        db.Index('idx_owner_recipient', 'owner_id', 'recipient_id'),
        db.Index('idx_recipient_status', 'recipient_id', 'status'),
        db.Index('idx_credential_recipient', 'credential_id', 'recipient_id'),
        # Ensure a credential can only be shared once with each recipient
        db.UniqueConstraint('credential_id', 'recipient_id', name='unique_credential_recipient'),
    )

    def __repr__(self):
        return f"<SharedCredential {self.id}: Credential {self.credential_id} from User {self.owner_id} to User {self.recipient_id}>"

    def is_expired(self):
        """Check if the shared credential has expired."""
        if not self.expires_at:
            return False
        # Ensure expires_at is timezone-aware for comparison
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > expires_at

    def is_active(self):
        """Check if the shared credential is active (accepted and not expired)."""
        return self.status == 'accepted' and not self.is_expired()

    def accept(self):
        """Accept the shared credential."""
        if self.status == 'pending':
            self.status = 'accepted'
            self.accepted_at = datetime.now(timezone.utc)
            return True
        return False

    def reject(self):
        """Reject the shared credential."""
        if self.status == 'pending':
            self.status = 'rejected'
            return True
        return False

    def revoke(self):
        """Revoke the shared credential (can be done by owner)."""
        if self.status in ['pending', 'accepted']:
            self.status = 'revoked'
            return True
        return False

    def to_dict(self, include_encrypted_data=False):
        """Convert to dictionary for API responses."""
        data = {
            'id': self.id,
            'credential_id': self.credential_id,
            'owner_id': self.owner_id,
            'recipient_id': self.recipient_id,
            'can_view': self.can_view,
            'can_edit': self.can_edit,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'status': self.status,
            'message': self.message,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'accepted_at': self.accepted_at.isoformat() if self.accepted_at else None,
            'is_expired': self.is_expired(),
            'is_active': self.is_active()
        }
        
        if include_encrypted_data:
            data['encrypted_data_for_recipient'] = self.encrypted_data_for_recipient
            
        return data