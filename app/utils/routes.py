# from flask import request, jsonify
# from . import utils_bp
# from ..utils.responses import success_response, error_response

from flask import request, jsonify, url_for, render_template, current_app, Response, make_response, session
from flask_login import login_required, current_user, logout_user
import io
import csv
import zipfile
from . import utils_bp
from ..models import db
from ..models.user import User
from ..models.password_reset_token import PasswordResetToken
from .responses import success_response, error_response
from .email import send_email
from ..models.credential import Credential
from .encryption import derive_key, decrypt_data, encrypt_data
from .. import limiter
from ..models.config import get_config_value


@utils_bp.route("/forgot-password", methods=["POST"])
@limiter.limit("3 per hour")
def forgot_password():
    """
    Initiates the password reset process.
    Expects 'email' in JSON body.
    Generates a reset token, saves its hash, and emails a reset link to the user.
    """
    data = request.get_json()
    if not data or "email" not in data:
        return error_response("Email is required.", 400)

    user_email = data["email"]
    user = User.query.filter_by(email=user_email).first()

    if user:
        try:
            # Generate a secure token
            raw_token = PasswordResetToken.generate_token()

            # Create and save the token record (stores hash)
            reset_token = PasswordResetToken(user_id=user.id, token=raw_token)
            db.session.add(reset_token)
            db.session.commit()

            # Send the email
            # IMPORTANT: Ensure BASE_URL is configured in Flask app config
            reset_url = url_for("utils.reset_password_with_token", token=raw_token, _external=True)
            template_path = get_config_value("EMAIL_RESET_PASSWORD_TEMPLATE")
            email_html = render_template(template_path, reset_url=reset_url, user=user)

            send_email(to=user.email, subject="Password Reset Request", template=email_html)

            current_app.logger.info(f"Password reset initiated for user {user.id} ({user.email})")
            return success_response("If an account with that email exists, a password reset link has been sent.")

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error during forgot password for {user_email}: {e}", exc_info=True)
            # Use a generic error to avoid leaking information
            return error_response("An error occurred during the password reset process.", 500)
    else:
        # IMPORTANT: Return the same success message even if user doesn't exist
        # This prevents user enumeration attacks. Log the attempt.
        current_app.logger.info(f"Password reset attempt for non-existent email: {user_email}")
        return success_response("If an account with that email exists, a password reset link has been sent.")


@utils_bp.route("/reset-password/<token>", methods=["POST"])
@limiter.limit("3 per hour")
def reset_password_with_token(token):
    """
    Resets the user's password using a valid token.
    Expects 'new_password' in JSON body.
    """
    data = request.get_json()
    if not data or "new_password" not in data:
        return error_response("New password is required.", 400)

    new_password = data["new_password"]
    # Basic password complexity check (example)
    min_length = get_config_value("MIN_PASSWORD_LENGTH")
    if len(new_password) < min_length:
        return error_response(f"Password must be at least {min_length} characters long.", 400)

    # Find the token by hashing the provided token
    reset_token = PasswordResetToken.find_by_token(token)

    if not reset_token or not reset_token.is_valid():
        # Log the attempt with the first few chars of the token for debugging
        token_preview = token[:6] + "..." if token else "None"
        current_app.logger.warning(f"Invalid or expired password reset token attempt: {token_preview}")
        return error_response("Invalid or expired password reset token.", 400)

    user = reset_token.user
    if not user:
        # Should not happen if DB integrity is maintained, but check anyway
        current_app.logger.error(f"PasswordResetToken {reset_token.id} has no associated user.")
        return error_response("An unexpected error occurred.", 500)

    try:
        # Update user's password
        user.set_password(new_password)

        # Mark the token as used
        reset_token.mark_as_used()

        # Invalidate all sessions for this user
        # This is done by updating a session version field that's checked during authentication
        user.increment_session_version()

        db.session.add(user)
        db.session.add(reset_token)
        db.session.commit()

        current_app.logger.info(f"Password successfully reset for user {user.id} ({user.email})")
        return success_response("Password has been successfully reset.")

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error during password reset for user {user.id}: {e}", exc_info=True)
        return error_response("An error occurred while resetting the password.", 500)


@utils_bp.route("/export", methods=["POST"])
@login_required
@limiter.limit("3 per hour")
def export_credentials():
    """
    Exports the user's credentials as a password-protected ZIP file containing a CSV.
    """
    data = request.get_json()
    if not data:
        return error_response("Request data is required.", 400)

    if not data.get("master_password"):
        return error_response("Master password is required.", 400)

    if not data.get("export_password"):
        return error_response("Export password is required to protect the ZIP file.", 400)

    try:
        credentials = Credential.query.filter_by(user_id=current_user.id).all()
        if not credentials:
            return success_response("You have no credentials stored to export.")

        # Get encryption key from master password
        encryption_key = derive_key(data["master_password"], current_user.encryption_salt)

        # Create CSV in memory
        csv_buffer = io.StringIO()
        writer = csv.writer(csv_buffer)
        writer.writerow(["service_name", "service_url", "username", "password", "notes"])

        for cred in credentials:
            try:
                decrypted_password = decrypt_data(encryption_key, cred.encrypted_password)
                writer.writerow([cred.service_name, cred.service_url or "", cred.username, decrypted_password, cred.notes or ""])
            except Exception as e:
                current_app.logger.error(f"Error decrypting credential {cred.id}: {e}", exc_info=True)
                return error_response("Failed to decrypt one or more credentials.", 500)

        # Create ZIP file in memory with password protection
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED, strict_timestamps=False) as zip_file:
            zip_file.setpassword(data["export_password"].encode())
            zip_file.writestr("credentials_export.csv", csv_buffer.getvalue())

        zip_buffer.seek(0)
        response = make_response(zip_buffer.getvalue())
        response.headers.set("Content-Type", "application/zip")
        response.headers.set("Content-Disposition", "attachment", filename="credentials_export.zip")

        return response

    except Exception as e:
        current_app.logger.error(f"Error during credential export: {e}", exc_info=True)
        return error_response("Failed to export credentials.", 500)


@utils_bp.route("/import", methods=["POST"])
@login_required
@limiter.limit("3 per hour")
def import_credentials():
    """
    Imports credentials from a JSON or CSV file.
    Expects credentials array and master_password in JSON body.
    """
    data = request.get_json()
    if not data:
        return error_response("Request data is required.", 400)

    if not data.get("master_password"):
        return error_response("Master password is required.", 400)

    if not data.get("credentials"):
        return error_response("Credentials data is required.", 400)

    try:
        # Get encryption key from master password
        encryption_key = derive_key(data["master_password"], current_user.encryption_salt)

        # Process each credential
        for cred_data in data["credentials"]:
            # Create new credential
            credential = Credential(
                user_id=current_user.id,
                service_name=cred_data.get("service_name", ""),
                service_url=cred_data.get("service_url"),
                username=cred_data.get("username", ""),
                category=cred_data.get("category"),
                notes=cred_data.get("notes"),
            )

            # Encrypt and store the password

            if "password" in cred_data and cred_data.get("password") is not None:
                credential.encrypted_password = encrypt_data(encryption_key, cred_data["password"])
            else:
                credential.encrypted_password = encrypt_data(encryption_key, "")

            db.session.add(credential)

        db.session.commit()
        return success_response("Credentials imported successfully.")

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error during credential import: {e}", exc_info=True)
        return error_response("Failed to import credentials.", 500)
