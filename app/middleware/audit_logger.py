"""
Audit logging middleware for automatic security event tracking.

This middleware integrates with Flask routes to automatically log
security-relevant events and user actions.
"""

import functools
from flask import request, current_app
from flask_login import current_user
from ..models.audit_log import AuditLog


def audit_event(event_type, message=None, severity=None, include_additional_data=False):
    """
    Decorator for automatically logging events when functions are called.
    
    Args:
        event_type: Type of event to log
        message: Custom message (can be a format string with {username}, {endpoint})
        severity: Event severity level
        include_additional_data: Include request additional_data in the log
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Execute the original function first
            result = func(*args, **kwargs)
            
            try:
                # Prepare log message
                log_message = message
                if log_message is None:
                    log_message = f"{event_type} event triggered"
                
                # Format message with context
                if hasattr(current_user, 'username'):
                    log_message = log_message.format(
                        username=current_user.username,
                        endpoint=request.endpoint if request else 'unknown'
                    )
                
                # Prepare additional_data
                additional_data = None
                if include_additional_data and request:
                    additional_data = {
                        "function": func.__name__,
                        "args_count": len(args),
                        "kwargs_keys": list(kwargs.keys()) if kwargs else []
                    }
                
                # Log the event
                AuditLog.log_event(
                    event_type=event_type,
                    message=log_message,
                    severity=severity,
                    additional_data=additional_data
                )
                
            except Exception as e:
                # Don't let audit logging break the main function
                current_app.logger.error(f"Audit logging failed: {e}")
            
            return result
        return wrapper
    return decorator


def audit_login_attempt(func):
    """Decorator specifically for login attempts."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        
        try:
            # Determine if login was successful based on response
            success = False
            username = "unknown"
            reason = None
            
            if hasattr(result, 'json') and result.json:
                success = result.status_code == 200
                # Try to get username from request data
                if request and request.json:
                    username = request.json.get('username', 'unknown')
            
            if not success and hasattr(result, 'json') and result.json:
                reason = result.json.get('message', 'Authentication failed')
            
            # Get IP and user agent from request
            ip_address = None
            user_agent = None
            if request:
                ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
                if ip_address and ',' in ip_address:
                    ip_address = ip_address.split(',')[0].strip()
                user_agent = request.headers.get('User-Agent', '')
            
            # Log the login attempt
            AuditLog.log_login(
                user_id=current_user.id if success and hasattr(current_user, 'id') else None,
                username=username,
                success=success,
                ip_address=ip_address,
                user_agent=user_agent,
                reason=reason
            )
            
        except Exception as e:
            current_app.logger.error(f"Login audit logging failed: {e}")
        
        return result
    return wrapper


def audit_credential_access(action):
    """Decorator for credential access operations."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            
            try:
                if hasattr(current_user, 'id') and hasattr(current_user, 'username'):
                    # Try to extract credential information from the result or request
                    credential_id = None
                    service_name = "unknown"
                    
                    # Check if credential_id is in the URL path
                    if request and 'credential_id' in request.view_args:
                        credential_id = request.view_args['credential_id']
                    
                    # Try to get service name from request data or response
                    if request and request.json:
                        service_name = request.json.get('service_name', service_name)
                    
                    # Log only if the operation was successful
                    if hasattr(result, 'status_code') and result.status_code in [200, 201]:
                        AuditLog.log_credential_access(
                            user_id=current_user.id,
                            username=current_user.username,
                            credential_id=credential_id,
                            service_name=service_name,
                            action=action
                        )
                
            except Exception as e:
                current_app.logger.error(f"Credential audit logging failed: {e}")
            
            return result
        return wrapper
    return decorator


class AuditMiddleware:
    """Middleware class for comprehensive audit logging."""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the audit middleware with the Flask app."""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        
        # Store failed requests for analysis
        self.failed_requests = []
    
    def before_request(self):
        """Log request start if it's a sensitive endpoint."""
        if not request:
            return
        
        sensitive_endpoints = [
            'auth.login',
            'auth.register',
            'auth.reset_password',
            'credentials.create_credential',
            'credentials.delete_credential',
            'utils.export_credentials',
            'utils.import_credentials',
            'security.enable_mfa',
            'security.disable_mfa'
        ]
        
        if request.endpoint in sensitive_endpoints:
            # Log that a sensitive operation was attempted
            AuditLog.log_event(
                event_type="sensitive_request",
                message=f"Sensitive endpoint accessed: {request.endpoint}",
                severity=AuditLog.SEVERITY_INFO,
                additional_data={
                    "endpoint": request.endpoint,
                    "method": request.method,
                    "user_authenticated": bool(current_user and hasattr(current_user, 'id'))
                }
            )
    
    def after_request(self, response):
        """Log request completion and analyze for suspicious patterns."""
        if not request:
            return response
        
        try:
            # Log failed authentication attempts
            if (request.endpoint in ['auth.login', 'auth.register'] and 
                response.status_code >= 400):
                
                ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
                if ip_address and ',' in ip_address:
                    ip_address = ip_address.split(',')[0].strip()
                
                # Check for suspicious patterns
                self.check_suspicious_activity(ip_address, request.endpoint, response.status_code)
            
            # Log successful sensitive operations
            if (response.status_code in [200, 201] and 
                request.endpoint in ['utils.export_credentials', 'utils.import_credentials']):
                
                if hasattr(current_user, 'username'):
                    action = "export" if "export" in request.endpoint else "import"
                    AuditLog.log_export_import(
                        user_id=current_user.id,
                        username=current_user.username,
                        action=action
                    )
        
        except Exception as e:
            current_app.logger.error(f"After request audit logging failed: {e}")
        
        return response
    
    def check_suspicious_activity(self, ip_address, endpoint, status_code):
        """Check for suspicious activity patterns."""
        try:
            # Count recent failed attempts from this IP
            from datetime import datetime, timezone, timedelta
            since = datetime.now(timezone.utc) - timedelta(minutes=15)
            
            recent_failures = AuditLog.query.filter(
                AuditLog.ip_address == ip_address,
                AuditLog.event_type == AuditLog.EVENT_FAILED_LOGIN,
                AuditLog.created_at >= since
            ).count()
            
            # Log suspicious activity if too many failures
            if recent_failures >= 5:
                AuditLog.log_event(
                    event_type=AuditLog.EVENT_SUSPICIOUS_ACTIVITY,
                    message=f"Multiple failed login attempts from IP {ip_address} ({recent_failures} in 15 minutes)",
                    severity=AuditLog.SEVERITY_WARNING,
                    ip_address=ip_address,
                    additional_data={
                        "recent_failures": recent_failures,
                        "pattern": "brute_force_attempt"
                    }
                )
        
        except Exception as e:
            current_app.logger.error(f"Suspicious activity check failed: {e}")


# Convenience functions for manual audit logging
def log_security_event(event_description, severity="warning", additional_data=None):
    """Manually log a security event."""
    user_id = None
    username = "system"
    
    if current_user and hasattr(current_user, 'id'):
        user_id = current_user.id
        username = current_user.username
    
    AuditLog.log_event(
        event_type=AuditLog.EVENT_SUSPICIOUS_ACTIVITY,
        message=event_description,
        severity=severity,
        user_id=user_id,
        username=username,
        additional_data=additional_data
    )


def log_admin_action(action_description, target_user=None, additional_data=None):
    """Log administrative actions."""
    if current_user and hasattr(current_user, 'username'):
        message = f"Admin action by {current_user.username}: {action_description}"
        if target_user:
            message += f" (target: {target_user})"
        
        AuditLog.log_event(
            event_type="admin_action",
            message=message,
            severity=AuditLog.SEVERITY_INFO,
            user_id=current_user.id,
            username=current_user.username,
            additional_data=additional_data
        )