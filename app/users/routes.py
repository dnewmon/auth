from flask import request, jsonify, current_app, render_template, url_for
from flask_login import login_required, current_user
from . import users_bp
from ..models import db, User
from ..models.email_verification_token import EmailVerificationToken
from ..utils.responses import success_response, error_response
from ..utils.email import send_email
from .. import limiter, csrf
from email_validator import validate_email, EmailNotValidError
from ..models.config import get_config_value
from datetime import datetime, timezone
import os


@users_bp.route("/profile", methods=["GET"])
@login_required
def get_profile():
    """Get user profile information."""
    try:
        profile_data = {
            "id": current_user.id,
            "username": current_user.username,
            "email": current_user.email,
            "email_verified": current_user.email_verified,
            "otp_enabled": current_user.otp_enabled,
            "email_mfa_enabled": current_user.email_mfa_enabled,
            "created_at": current_user.created_at.isoformat() if current_user.created_at else None,
            "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
            "session_version": current_user.session_version
        }
        
        return success_response(profile_data)
        
    except Exception as e:
        current_app.logger.error(f"Error getting profile for user {current_user.id}: {e}", exc_info=True)
        return error_response("Failed to get profile information", 500)


@users_bp.route("/profile", methods=["PUT"])
@csrf.exempt
@login_required
@limiter.limit("10 per hour")
def update_profile():
    """Update user profile information."""
    data = request.get_json()
    if not data:
        return error_response("Request data is required", 400)
    
    try:
        updated = False
        
        # Update username if provided
        if "username" in data:
            new_username = data["username"]
            if not new_username or len(new_username.strip()) < 3:
                return error_response("Username must be at least 3 characters long", 400)
            
            # Check if username is already taken
            if new_username != current_user.username:
                existing_user = User.query.filter_by(username=new_username).first()
                if existing_user:
                    return error_response("Username is already taken", 409)
                
                current_user.username = new_username
                updated = True
        
        if updated:
            db.session.commit()
            current_app.logger.info(f"Profile updated for user {current_user.id}")
            
            # Return updated profile
            profile_data = {
                "id": current_user.id,
                "username": current_user.username,
                "email": current_user.email,
                "email_verified": current_user.email_verified
            }
            
            return success_response(profile_data, "Profile updated successfully")
        else:
            return success_response({"message": "No changes made"})
            
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating profile for user {current_user.id}: {e}", exc_info=True)
        return error_response("Failed to update profile", 500)


@users_bp.route("/change-email", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("5 per hour")
def change_email():
    """Request email change (requires verification)."""
    data = request.get_json()
    if not data:
        return error_response("Request data is required", 400)
    
    new_email = data.get("email")
    current_password = data.get("current_password")
    
    if not new_email or not current_password:
        return error_response("New email and current password are required", 400)
    
    # Verify current password
    if not current_user.check_password(current_password):
        return error_response("Current password is incorrect", 401)
    
    # Validate new email
    try:
        email_info = validate_email(new_email, check_deliverability=False)
        new_email = email_info.normalized
    except EmailNotValidError as e:
        return error_response(f"Invalid email address: {str(e)}", 400)
    
    # Check if email is already taken
    existing_user = User.query.filter_by(email=new_email).first()
    if existing_user and existing_user.id != current_user.id:
        return error_response("Email address is already in use", 409)
    
    if new_email == current_user.email:
        return error_response("New email is the same as current email", 400)
    
    try:
        # Update email and mark as unverified
        old_email = current_user.email
        current_user.email = new_email
        current_user.email_verified = False  # Require re-verification
        db.session.commit()
        
        # Send verification email for the new email address
        
        try:
            # Create verification token for new email
            verification_token = EmailVerificationToken.create_for_user(current_user.id)
            verification_url = url_for('auth.verify_email', token=verification_token.token, _external=True)
            
            # Send verification email to new address
            email_html = render_template('email/welcome_verification.html', 
                                       user=current_user, 
                                       verification_url=verification_url)
            send_email(new_email, "Please Verify Your New Email Address", email_html)
            
            current_app.logger.info(f"Email changed for user {current_user.id} from {old_email} to {new_email}, verification email sent")
            
        except Exception as email_error:
            current_app.logger.error(f"Failed to send verification email to {new_email}: {email_error}", exc_info=True)
            # Don't fail the email change if verification email fails
        
        return success_response({
            "message": "Email address updated successfully. A verification email has been sent to your new email address.",
            "email": new_email,
            "email_verified": False
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error changing email for user {current_user.id}: {e}", exc_info=True)
        return error_response("Failed to change email address", 500)


@users_bp.route("/change-password", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("5 per hour")
def change_password():
    """Change user password."""
    data = request.get_json()
    if not data:
        return error_response("Request data is required", 400)
    
    current_password = data.get("current_password")
    new_password = data.get("new_password")
    
    if not current_password or not new_password:
        return error_response("Current password and new password are required", 400)
    
    # Verify current password
    if not current_user.check_password(current_password):
        return error_response("Current password is incorrect", 401)
    
    # Validate new password
    min_length = get_config_value("MIN_PASSWORD_LENGTH")
    if len(new_password) < min_length:
        return error_response(f"New password must be at least {min_length} characters long", 400)
    
    if new_password == current_password:
        return error_response("New password must be different from current password", 400)
    
    try:
        # Update password
        current_user.set_password(new_password)
        
        # Increment session version to invalidate other sessions
        current_user.increment_session_version()
        
        db.session.commit()
        
        current_app.logger.info(f"Password changed for user {current_user.id}")
        
        return success_response({"message": "Password changed successfully. Other sessions have been logged out."})
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error changing password for user {current_user.id}: {e}", exc_info=True)
        return error_response("Failed to change password", 500)


@users_bp.route("/delete-account", methods=["DELETE"])
@csrf.exempt
@login_required
@limiter.limit("3 per day")
def delete_account():
    """Delete user account (requires password confirmation)."""
    data = request.get_json()
    if not data:
        return error_response("Request data is required", 400)
    
    current_password = data.get("current_password")
    confirmation = data.get("confirmation")
    
    if not current_password:
        return error_response("Current password is required", 400)
    
    if confirmation != "DELETE":
        return error_response("Confirmation must be 'DELETE'", 400)
    
    # Verify current password
    if not current_user.check_password(current_password):
        return error_response("Current password is incorrect", 401)
    
    try:
        user_id = current_user.id
        username = current_user.username
        
        # Delete user (this will cascade delete all related data due to foreign key constraints)
        db.session.delete(current_user)
        db.session.commit()
        
        current_app.logger.info(f"Account deleted for user {user_id} (username: {username})")
        
        return success_response({"message": "Account deleted successfully"})
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting account for user {current_user.id}: {e}", exc_info=True)
        return error_response("Failed to delete account", 500)


@users_bp.route("/statistics", methods=["GET"])
@login_required
def get_statistics():
    """Get user account statistics."""
    try:
        from ..models.credential import Credential
        from ..models.shared_credential import SharedCredential
        from ..models.audit_log import AuditLog
        
        # Get credential statistics
        total_credentials = Credential.query.filter_by(user_id=current_user.id).count()
        
        # Get sharing statistics
        shared_by_user = SharedCredential.query.filter_by(owner_id=current_user.id).count()
        shared_to_user = SharedCredential.query.filter_by(recipient_id=current_user.id, status='accepted').count()
        
        # Get recent activity count (last 30 days)
        thirty_days_ago = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        thirty_days_ago = thirty_days_ago.replace(day=thirty_days_ago.day - 30) if thirty_days_ago.day > 30 else thirty_days_ago.replace(month=thirty_days_ago.month - 1, day=30)
        
        recent_activity = AuditLog.query.filter(
            AuditLog.user_id == current_user.id,
            AuditLog.timestamp >= thirty_days_ago
        ).count()
        
        statistics = {
            "total_credentials": total_credentials,
            "credentials_shared_by_user": shared_by_user,
            "credentials_shared_to_user": shared_to_user,
            "recent_activity_count": recent_activity,
            "account_created": current_user.created_at.isoformat() if current_user.created_at else None,
            "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
            "mfa_enabled": current_user.otp_enabled or current_user.email_mfa_enabled,
            "email_verified": current_user.email_verified
        }
        
        return success_response(statistics)
        
    except Exception as e:
        current_app.logger.error(f"Error getting statistics for user {current_user.id}: {e}", exc_info=True)
        return error_response("Failed to get account statistics", 500) 