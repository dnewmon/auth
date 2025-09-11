# from flask import request, jsonify
# from . import utils_bp
# from ..utils.responses import success_response, error_response

from flask import request, jsonify, url_for, render_template, current_app, Response, make_response, session
from flask_login import login_required, current_user, logout_user
import io
import csv
import os
import tempfile
import pyminizip
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

@utils_bp.route("/health", methods=["GET"])
def health():
    """
    Check if the API is running.
    """
    return success_response(message="API is running.")


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

            # Check if user has recovery keys
            has_recovery_keys = len(user.recovery_keys) > 0
            unused_keys = sum(1 for key in user.recovery_keys if not key.used_at)

            email_html = render_template(template_path, reset_url=reset_url, user=user, has_recovery_keys=has_recovery_keys, unused_keys=unused_keys)

            send_email(to=user.email, subject="Password Reset Request", template=email_html)

            current_app.logger.info(f"Password reset initiated for user {user.id} ({user.email})")
            return success_response(message="If an account with that email exists, a password reset link has been sent.")

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error during forgot password for {user_email}: {e}", exc_info=True)
            # Use a generic error to avoid leaking information
            return error_response("An error occurred during the password reset process.", 500)
    else:
        # IMPORTANT: Return the same success message even if user doesn't exist
        # This prevents user enumeration attacks. Log the attempt.
        current_app.logger.info(f"Password reset attempt for non-existent email: {user_email}")
        return success_response(message="If an account with that email exists, a password reset link has been sent.")


@utils_bp.route("/reset-password/<token>", methods=["POST"])
@limiter.limit("3 per hour")
def reset_password_with_token(token):
    """
    Resets the user's password using a valid token.
    Expects 'new_password' in JSON body.
    If 'recovery_key' is provided, will attempt to preserve encrypted credentials.
    """
    data = request.get_json()
    if not data or "new_password" not in data:
        return error_response("New password is required.", 400)

    new_password = data["new_password"]
    recovery_key = data.get("recovery_key")

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
        # Check if user has credentials that need to be preserved
        has_credentials = len(user.credentials) > 0
        credentials_migrated = False

        if has_credentials and recovery_key:
            try:
                # Try to recover with recovery key
                success = user.recover_with_recovery_key(recovery_key, new_password)
                credentials_migrated = True
                current_app.logger.info(f"Successfully migrated {len(user.credentials)} credentials for user {user.id}")
            except ValueError as e:
                current_app.logger.warning(f"Recovery with key failed for user {user.id}: {e}")
                # If recovery fails, continue with standard password reset
                user.set_password(new_password)
                credentials_migrated = False
        else:
            # Standard password reset, credentials will be lost if they exist
            user.set_password(new_password)

            # If user has credentials but didn't provide a recovery key, generate new encryption
            if has_credentials and not recovery_key:
                # Generate new encryption salt for future credentials
                user.encryption_salt = os.urandom(16)

                # Initialize new encryption (old credentials are now inaccessible)
                recovery_keys = user.initialize_encryption(new_password)
                current_app.logger.warning(f"User {user.id} reset password without migration. {len(user.credentials)} credentials will be inaccessible.")

                # Mark the token as used
                reset_token.mark_as_used()

                # Invalidate all sessions for this user
                user.increment_session_version()

                db.session.add(user)
                db.session.add(reset_token)
                db.session.commit()

                return success_response(
                    {
                        "message": "Password has been reset successfully, but you cannot access your previous credentials. New recovery keys have been generated.",
                        "recovery_keys": recovery_keys,
                        "recovery_message": "IMPORTANT: Please save these recovery keys in a secure location. They will be needed to recover your account if you forget your password again.",
                        "credentials_migrated": False,
                    }
                )

        # Mark the token as used
        reset_token.mark_as_used()

        # Invalidate all sessions for this user
        user.increment_session_version()

        db.session.add(user)
        db.session.add(reset_token)
        db.session.commit()

        # Return appropriate message based on whether credentials were migrated
        if credentials_migrated:
            return success_response({"message": "Password has been reset successfully and your credentials have been preserved.", "credentials_migrated": True})
        elif has_credentials:
            return success_response(
                {"message": "Password has been reset successfully, but you will not be able to access your previous credentials.", "credentials_migrated": False}
            )
        else:
            return success_response({"message": "Password has been reset successfully.", "credentials_migrated": True})  # No credentials to migrate, so technically true

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error during password reset for user {user.id}: {e}", exc_info=True)
        return error_response("An error occurred while resetting the password.", 500)


@utils_bp.route("/recover-with-key", methods=["POST"])
@limiter.limit("5 per hour")
def recover_with_recovery_key():
    """
    Recover account using a recovery key without a reset token.
    Expects email, recovery_key, and new_password in the request.
    """
    data = request.get_json()
    if not data:
        return error_response("Missing required data", 400)

    email = data.get("email")
    recovery_key = data.get("recovery_key")
    new_password = data.get("new_password")

    if not all([email, recovery_key, new_password]):
        return error_response("Email, recovery key, and new password are required", 400)

    # Basic password check
    min_length = get_config_value("MIN_PASSWORD_LENGTH")
    if len(new_password) < min_length:
        return error_response(f"Password must be at least {min_length} characters long", 400)

    # Find user
    user = User.query.filter_by(email=email).first()
    if not user:
        # Don't reveal if email exists
        return error_response("Invalid email or recovery key", 401)

    try:
        # Try to recover with recovery key
        success = user.recover_with_recovery_key(recovery_key, new_password)

        # Invalidate all sessions for this user
        user.increment_session_version()

        db.session.commit()

        return success_response({"message": "Account recovered successfully. You can now log in with your new password.", "credentials_preserved": True})
    except ValueError as e:
        current_app.logger.warning(f"Recovery attempt failed for {email}: {str(e)}")
        return error_response("Invalid email or recovery key", 401)
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error during account recovery: {e}", exc_info=True)
        return error_response("An unexpected error occurred", 500)


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

    if not data.get("session_token"):
        return error_response("Session token is required.", 400)

    if not data.get("export_password"):
        return error_response("Export password is required to protect the ZIP file.", 400)

    try:
        credentials = Credential.query.filter_by(user_id=current_user.id).all()
        if not credentials:
            return success_response(message="You have no credentials stored to export.")

        # Get master encryption key using session token
        try:
            from .master_verification import MasterVerificationManager
            master_key = MasterVerificationManager.get_master_key_from_session(data["session_token"])
        except ValueError as e:
            return error_response("Invalid session token. Please verify your password again.", 401)

        # Create CSV in memory
        csv_buffer = io.StringIO()
        writer = csv.writer(csv_buffer)
        writer.writerow(["service_name", "service_url", "username", "password", "notes"])

        for cred in credentials:
            try:
                decrypted_password = decrypt_data(master_key, cred.encrypted_password)
                writer.writerow([cred.service_name, cred.service_url or "", cred.username, decrypted_password, cred.notes or ""])
            except Exception as e:
                current_app.logger.error(f"Error decrypting credential {cred.id}: {e}", exc_info=True)
                return error_response("Failed to decrypt one or more credentials.", 500)

        # Create temporary files for CSV and ZIP
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as temp_csv:
            temp_csv.write(csv_buffer.getvalue().encode())
            temp_csv_path = temp_csv.name

        temp_zip_path = os.path.join(tempfile.gettempdir(), f"credentials_export_{current_user.id}.zip")

        # Create password-protected ZIP with pyminizip
        # Parameters: source_file, file_name_in_zip, dest_file, password, compress_level
        pyminizip.compress(temp_csv_path, "credentials_export.csv", temp_zip_path, data["export_password"], 5)

        # Read the zip file and create a response
        with open(temp_zip_path, "rb") as zip_file:
            response = make_response(zip_file.read())

        # Clean up temporary files
        os.unlink(temp_csv_path)
        os.unlink(temp_zip_path)

        response.headers.set("Content-Type", "application/zip")
        response.headers.set("Content-Disposition", "attachment", filename="credentials_export.zip")

        return response

    except Exception as e:
        # Clean up any temporary files in case of error
        if "temp_csv_path" in locals() and os.path.exists(temp_csv_path):
            os.unlink(temp_csv_path)
        if "temp_zip_path" in locals() and os.path.exists(temp_zip_path):
            os.unlink(temp_zip_path)

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

    if not data.get("session_token"):
        return error_response("Session token is required.", 400)

    if not data.get("credentials"):
        return error_response("Credentials data is required.", 400)

    try:
        # Get master encryption key using session token
        try:
            from .master_verification import MasterVerificationManager
            master_key = MasterVerificationManager.get_master_key_from_session(data["session_token"])
        except ValueError as e:
            return error_response("Invalid session token. Please verify your password again.", 401)

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
                credential.encrypted_password = encrypt_data(master_key, cred_data["password"])
            else:
                credential.encrypted_password = encrypt_data(master_key, "")

            db.session.add(credential)

        db.session.commit()
        return success_response(message="Credentials imported successfully.")

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error during credential import: {e}", exc_info=True)
        return error_response("Failed to import credentials.", 500)
