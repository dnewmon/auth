"""
Audit logging model for tracking security events and user actions.

This model provides comprehensive audit logging capabilities for compliance
and security monitoring purposes.
"""

from . import db
from datetime import datetime, timezone
from flask import request
from flask_login import current_user
import json


class AuditLog(db.Model):
    """Model for storing audit log entries."""
    
    __tablename__ = "audit_logs"
    
    # Event types
    EVENT_LOGIN = "login"
    EVENT_LOGOUT = "logout"
    EVENT_REGISTRATION = "registration"
    EVENT_PASSWORD_CHANGE = "password_change"
    EVENT_PASSWORD_RESET = "password_reset"
    EVENT_MFA_ENABLED = "mfa_enabled"
    EVENT_MFA_DISABLED = "mfa_disabled"
    EVENT_MFA_LOGIN = "mfa_login"
    EVENT_CREDENTIAL_CREATED = "credential_created"
    EVENT_CREDENTIAL_VIEWED = "credential_viewed"
    EVENT_CREDENTIAL_UPDATED = "credential_updated"
    EVENT_CREDENTIAL_DELETED = "credential_deleted"
    EVENT_EXPORT = "export"
    EVENT_IMPORT = "import"
    EVENT_RECOVERY_KEY_USED = "recovery_key_used"
    EVENT_RECOVERY_KEYS_REGENERATED = "recovery_keys_regenerated"
    EVENT_EMAIL_VERIFICATION = "email_verification"
    EVENT_ACCOUNT_RECOVERY = "account_recovery"
    EVENT_SESSION_INVALIDATED = "session_invalidated"
    EVENT_FAILED_LOGIN = "failed_login"
    EVENT_SUSPICIOUS_ACTIVITY = "suspicious_activity"
    
    # Severity levels
    SEVERITY_INFO = "info"
    SEVERITY_WARNING = "warning"
    SEVERITY_ERROR = "error"
    SEVERITY_CRITICAL = "critical"
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Event information
    event_type = db.Column(db.String(50), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, default=SEVERITY_INFO, index=True)
    message = db.Column(db.Text, nullable=False)
    
    # User information
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    username = db.Column(db.String(80), nullable=True)  # Store username for deleted users
    
    # Request information
    ip_address = db.Column(db.String(45), nullable=True, index=True)  # IPv6 support
    user_agent = db.Column(db.Text, nullable=True)
    endpoint = db.Column(db.String(100), nullable=True)
    method = db.Column(db.String(10), nullable=True)
    
    # Additional data (JSON)
    additional_data = db.Column(db.Text, nullable=True)  # JSON string for additional data
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    # Composite indexes for common queries
    __table_args__ = (
        db.Index('idx_audit_user_event', 'user_id', 'event_type'),
        db.Index('idx_audit_time_severity', 'created_at', 'severity'),
        db.Index('idx_audit_ip_time', 'ip_address', 'created_at'),
    )
    
    def __repr__(self):
        return f"<AuditLog {self.event_type} by {self.username or 'Unknown'} at {self.created_at}>"
    
    @classmethod
    def log_event(cls, event_type, message, severity=None, user_id=None, username=None, 
                  additional_data=None, ip_address=None, user_agent=None, endpoint=None, method=None):
        """Log an audit event with automatic context detection."""
        
        # Auto-detect user information if not provided
        if user_id is None and current_user and hasattr(current_user, 'id'):
            user_id = current_user.id
            username = current_user.username
        
        # Auto-detect request information if not provided
        if request:
            if ip_address is None:
                ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
                if ip_address and ',' in ip_address:
                    ip_address = ip_address.split(',')[0].strip()
            
            if user_agent is None:
                user_agent = request.headers.get('User-Agent', '')[:500]  # Limit length
            
            if endpoint is None:
                endpoint = request.endpoint
            
            if method is None:
                method = request.method
        
        # Set default severity
        if severity is None:
            severity = cls.SEVERITY_INFO
        
        # Convert additional_data to JSON string if it's a dict
        if additional_data and isinstance(additional_data, dict):
            additional_data = json.dumps(additional_data, default=str)
        
        # Create audit log entry
        audit_entry = cls(
            event_type=event_type,
            severity=severity,
            message=message,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            endpoint=endpoint,
            method=method,
            additional_data=additional_data
        )
        
        try:
            db.session.add(audit_entry)
            db.session.commit()
        except Exception as e:
            # Don't let audit logging failure break the main application
            db.session.rollback()
            import logging
            logging.error(f"Failed to write audit log: {e}")
    
    @classmethod
    def log_login(cls, user_id, username, success=True, ip_address=None, user_agent=None, 
                  reason=None):
        """Log a login attempt."""
        if success:
            cls.log_event(
                event_type=cls.EVENT_LOGIN,
                message=f"Successful login for user {username}",
                severity=cls.SEVERITY_INFO,
                user_id=user_id,
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                additional_data={"success": True}
            )
        else:
            cls.log_event(
                event_type=cls.EVENT_FAILED_LOGIN,
                message=f"Failed login attempt for user {username}: {reason or 'Invalid credentials'}",
                severity=cls.SEVERITY_WARNING,
                user_id=user_id,
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                additional_data={"success": False, "reason": reason}
            )
    
    @classmethod
    def log_logout(cls, user_id, username):
        """Log a logout event."""
        cls.log_event(
            event_type=cls.EVENT_LOGOUT,
            message=f"User {username} logged out",
            user_id=user_id,
            username=username
        )
    
    @classmethod
    def log_registration(cls, user_id, username, email):
        """Log a new user registration."""
        cls.log_event(
            event_type=cls.EVENT_REGISTRATION,
            message=f"New user registered: {username} ({email})",
            user_id=user_id,
            username=username,
            additional_data={"email": email}
        )
    
    @classmethod
    def log_password_change(cls, user_id, username):
        """Log a password change event."""
        cls.log_event(
            event_type=cls.EVENT_PASSWORD_CHANGE,
            message=f"Password changed for user {username}",
            severity=cls.SEVERITY_INFO,
            user_id=user_id,
            username=username
        )
    
    @classmethod
    def log_mfa_change(cls, user_id, username, mfa_type, enabled):
        """Log MFA enable/disable events."""
        action = "enabled" if enabled else "disabled"
        event_type = cls.EVENT_MFA_ENABLED if enabled else cls.EVENT_MFA_DISABLED
        
        cls.log_event(
            event_type=event_type,
            message=f"{mfa_type.upper()} MFA {action} for user {username}",
            severity=cls.SEVERITY_INFO,
            user_id=user_id,
            username=username,
            additional_data={"mfa_type": mfa_type, "enabled": enabled}
        )
    
    @classmethod
    def log_credential_access(cls, user_id, username, credential_id, service_name, action):
        """Log credential access events."""
        event_types = {
            "created": cls.EVENT_CREDENTIAL_CREATED,
            "viewed": cls.EVENT_CREDENTIAL_VIEWED,
            "updated": cls.EVENT_CREDENTIAL_UPDATED,
            "deleted": cls.EVENT_CREDENTIAL_DELETED
        }
        
        cls.log_event(
            event_type=event_types.get(action, cls.EVENT_CREDENTIAL_VIEWED),
            message=f"Credential {action} for {service_name} by user {username}",
            user_id=user_id,
            username=username,
            additional_data={
                "credential_id": credential_id,
                "service_name": service_name,
                "action": action
            }
        )
    
    @classmethod
    def log_export_import(cls, user_id, username, action, count=None):
        """Log data export/import events."""
        event_type = cls.EVENT_EXPORT if action == "export" else cls.EVENT_IMPORT
        message = f"Credentials {action} by user {username}"
        if count:
            message += f" ({count} credentials)"
        
        cls.log_event(
            event_type=event_type,
            message=message,
            severity=cls.SEVERITY_INFO,
            user_id=user_id,
            username=username,
            additional_data={"action": action, "count": count}
        )
    
    @classmethod
    def log_security_event(cls, user_id, username, event_description, severity=None):
        """Log general security events."""
        cls.log_event(
            event_type=cls.EVENT_SUSPICIOUS_ACTIVITY,
            message=event_description,
            severity=severity or cls.SEVERITY_WARNING,
            user_id=user_id,
            username=username
        )
    
    @classmethod
    def get_user_activity(cls, user_id, limit=50, event_types=None):
        """Get recent activity for a specific user."""
        query = cls.query.filter_by(user_id=user_id)
        
        if event_types:
            query = query.filter(cls.event_type.in_(event_types))
        
        return query.order_by(cls.created_at.desc()).limit(limit).all()
    
    @classmethod
    def get_security_alerts(cls, severity_threshold="warning", hours=24):
        """Get recent security alerts above a certain severity level."""
        from datetime import timedelta
        
        severity_order = {
            "info": 0,
            "warning": 1, 
            "error": 2,
            "critical": 3
        }
        
        threshold_num = severity_order.get(severity_threshold, 1)
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        return cls.query.filter(
            cls.created_at >= since,
            cls.severity.in_([k for k, v in severity_order.items() if v >= threshold_num])
        ).order_by(cls.created_at.desc()).all()
    
    @classmethod
    def cleanup_old_logs(cls, days=90):
        """Clean up audit logs older than specified days."""
        from datetime import timedelta
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        deleted_count = cls.query.filter(cls.created_at < cutoff_date).delete()
        db.session.commit()
        
        return deleted_count
    
    def get_additional_data_dict(self):
        """Get additional_data as a Python dictionary."""
        if self.additional_data:
            try:
                return json.loads(self.additional_data)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}
    
    def to_dict(self):
        """Convert audit log entry to dictionary."""
        return {
            "id": self.id,
            "event_type": self.event_type,
            "severity": self.severity,
            "message": self.message,
            "user_id": self.user_id,
            "username": self.username,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "endpoint": self.endpoint,
            "method": self.method,
            "additional_data": self.get_additional_data_dict(),
            "created_at": self.created_at.isoformat() if self.created_at else None
        }