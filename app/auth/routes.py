from flask import request, jsonify, current_app, session, render_template
from . import auth_bp
from ..models import db, User
from ..utils.responses import success_response, error_response
from ..utils.email import send_email
from sqlalchemy.exc import IntegrityError
from flask_login import login_user, logout_user, login_required, current_user
import logging
import pyotp  # Add pyotp import
from email_validator import validate_email, EmailNotValidError
from .. import limiter
from ..models.config import get_config_value


@auth_bp.route("/register", methods=["POST"])
@limiter.limit("5 per hour")
def register():
    data = request.get_json()
    if not data:
        return error_response("Request must be JSON", 400)

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not all([username, email, password]):
        return error_response("Missing username, email, or password", 400)

    # Email validation
    try:
        email_info = validate_email(email, check_deliverability=False)
        email = email_info.normalized
    except EmailNotValidError as e:
        return error_response(f"Invalid email address: {str(e)}", 400)

    # Basic validation (more complex rules can be added)
    min_length = get_config_value("MIN_PASSWORD_LENGTH")
    if len(password) < min_length:
        return error_response(f"Password must be at least {min_length} characters long", 400)
    # Add email format validation if needed

    # Check if user already exists
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return error_response("Username or email already exists", 409)  # 409 Conflict

    try:
        new_user = User(username=username, email=email)
        new_user.set_password(password)  # Uses Argon2 now
        # Generate encryption salt during registration
        import os

        new_user.encryption_salt = os.urandom(16)

        db.session.add(new_user)
        db.session.commit()

        # Now that the user has an ID, initialize the two-tier encryption
        recovery_keys = new_user.initialize_encryption(password)
        db.session.commit()

        current_app.logger.info(f"User '{username}' registered successfully.")
        # Avoid returning sensitive info like password hash
        user_data = {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "recovery_keys": recovery_keys,
            "recovery_message": "IMPORTANT: Please save these recovery keys in a secure location. They will be needed to recover your account if you forget your password. They will NOT be shown again.",
        }
        return success_response(user_data, 201)  # 201 Created
    except IntegrityError as e:
        db.session.rollback()
        current_app.logger.error(f"Database integrity error during registration: {e}")
        return error_response("Registration failed due to a database conflict.", 409)
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error during registration for {username}: {e}", exc_info=True)
        return error_response("An unexpected error occurred during registration.", 500)


@auth_bp.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    if not data:
        return error_response("Request must be JSON", 400)

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return error_response("Missing username or password", 400)

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):  # Uses Argon2 check
        # Check if OTP is enabled
        if user.otp_enabled:
            # Store user ID in session to indicate first factor success
            session[get_config_value("SESSION_KEY_OTP_USER_ID")] = user.id
            session.modified = True
            current_app.logger.info(f"User '{username}' passed first factor, OTP required.")
            return success_response({"mfa_required": "otp"}, status_code=202)  # 202 Accepted
        else:
            # OTP not enabled, proceed with login
            login_user(user)
            # Set session version
            session["session_version"] = user.session_version
            session.modified = True

            # Update last login timestamp
            user.update_last_login()

            current_app.logger.info(f"User '{username}' logged in successfully (no OTP).")

            # Check if email MFA is enabled and send notification
            if user.email_mfa_enabled:
                try:
                    # Assuming you have a template named 'email/login_notification.html'
                    # You might need to create this template file.
                    template_path = get_config_value("EMAIL_LOGIN_NOTIFICATION_TEMPLATE")
                    email_html = render_template(template_path, user=user)
                    send_email(user.email, "Security Alert: New Login Detected", email_html)
                    current_app.logger.info(f"Sent login notification email to {user.email}")
                except Exception as e:
                    current_app.logger.error(f"Failed to send login notification email to {user.email}: {e}", exc_info=True)
                    # Log the error but don't fail the login

            # Return success, no tokens needed for session-based auth
            return success_response({"message": "Login successful"})
    else:
        current_app.logger.warning(f"Failed login attempt for username: '{username}'.")
        # Generic error to prevent user enumeration
        return error_response("Invalid username or password", 401)  # 401 Unauthorized


@auth_bp.route("/login/verify-otp", methods=["POST"])
@limiter.limit("10 per minute")
def login_verify_otp():
    """Verifies the OTP token after successful password authentication."""
    user_id = session.get(get_config_value("SESSION_KEY_OTP_USER_ID"))
    if not user_id:
        return error_response("Primary authentication step not completed or session expired.", 401)

    data = request.get_json()
    otp_token = data.get("otp_token")
    if not otp_token:
        return error_response("Missing OTP token.", 400)

    user = User.query.get(user_id)
    if not user or not user.otp_enabled or not user.otp_secret:
        # Should not happen if session is managed correctly, but good to check
        session.pop(get_config_value("SESSION_KEY_OTP_USER_ID"), None)
        session.modified = True
        return error_response("OTP is not configured for this user or user not found.", 400)

    # Verify the OTP token
    totp = pyotp.TOTP(user.otp_secret)
    if totp.verify(otp_token):
        # OTP verification successful, clear session marker and log in user
        session.pop(get_config_value("SESSION_KEY_OTP_USER_ID"), None)
        session.modified = True

        login_user(user)
        # Set session version
        session["session_version"] = user.session_version
        session.modified = True

        # Update last login timestamp
        user.update_last_login()

        current_app.logger.info(f"User ID '{user_id}' successfully authenticated with OTP.")

        # Check if email MFA is enabled and send notification (after successful OTP)
        if user.email_mfa_enabled:
            try:
                template_path = get_config_value("EMAIL_LOGIN_NOTIFICATION_TEMPLATE")
                email_html = render_template(template_path, user=user)
                send_email(user.email, "Security Alert: New Login Detected", email_html)
                current_app.logger.info(f"Sent login notification email to {user.email} after OTP verification.")
            except Exception as e:
                current_app.logger.error(f"Failed to send login notification email to {user.email} after OTP: {e}", exc_info=True)

        # Return success, no tokens needed for session-based auth
        return success_response({"message": "Login successful"})
    else:
        # Invalid OTP token
        current_app.logger.warning(f"Invalid OTP token provided for user ID '{user_id}'.")
        return error_response("Invalid OTP token.", 401)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    current_app.logger.info(f"User ID {current_user.id if current_user.is_authenticated else 'unknown'} logged out.")
    return success_response({"message": "Successfully logged out"})


@auth_bp.route("/me", methods=["GET"])
@login_required
def get_current_user():
    """Get the username of the currently authenticated user."""
    current_app.logger.info(f"User ID {current_user.id} requested their username.")
    return success_response({"username": current_user.username})


# Recovery key management endpoints
@auth_bp.route("/recovery-keys", methods=["GET"])
@login_required
@limiter.limit("10 per hour")
def get_recovery_key_status():
    """Check status of recovery keys (not the actual keys)"""
    recovery_key_count = len(current_user.recovery_keys)
    unused_keys = sum(1 for key in current_user.recovery_keys if not key.used_at)

    return success_response({"total_keys": recovery_key_count, "unused_keys": unused_keys, "has_keys": recovery_key_count > 0})


@auth_bp.route("/recovery-keys", methods=["POST"])
@login_required
@limiter.limit("5 per day")
def regenerate_recovery_keys():
    """Regenerate recovery keys"""
    data = request.get_json()
    if not data or "password" not in data:
        return error_response("Current password is required", 400)

    try:
        # Regenerate keys
        new_keys = current_user.regenerate_recovery_keys(data["password"])
        db.session.commit()

        return success_response(
            {"recovery_keys": new_keys, "recovery_message": "IMPORTANT: Please save these new recovery keys in a secure location. Your old keys are no longer valid."}
        )
    except ValueError as e:
        current_app.logger.warning(f"Failed to regenerate recovery keys for user {current_user.id}: {e}")
        return error_response(str(e), 400)
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error regenerating recovery keys: {e}", exc_info=True)
        return error_response("An unexpected error occurred", 500)
