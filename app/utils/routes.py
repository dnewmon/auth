# from flask import request, jsonify
# from . import utils_bp
# from ..utils.responses import success_response, error_response

from flask import request, jsonify, url_for, render_template, current_app, Response, make_response, session
from flask_login import login_required, current_user, logout_user
from .. import csrf
import io
import csv
import json
import os
import tempfile
import time
import pyminizip
from datetime import datetime, timezone
from . import utils_bp
from ..models import db
from ..models.user import User
from ..models.password_reset_token import PasswordResetToken
from .responses import success_response, error_response
from .email import send_email
from ..models.credential import Credential
from .encryption import derive_key, decrypt_data, encrypt_data
from .. import limiter
from .password_generator import PasswordGenerator, analyze_password_strength
from ..models.audit_log import AuditLog
from ..models.config import get_config_value


@utils_bp.route("/forgot-password", methods=["POST"])
@csrf.exempt
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

            # Check if user has recovery keys (optimized with database queries)
            from ..models.user import RecoveryKey
            total_keys = RecoveryKey.query.filter_by(user_id=user.id).count()
            has_recovery_keys = total_keys > 0
            unused_keys = RecoveryKey.query.filter_by(user_id=user.id, used_at=None).count()

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
@csrf.exempt
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
@csrf.exempt
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
@csrf.exempt
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
            return success_response(message="You have no credentials stored to export.")

        # Get master encryption key using password
        try:
            master_key = current_user.get_master_key(data["master_password"])
        except ValueError as e:
            return error_response(str(e), 401)

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
@csrf.exempt
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
        # Get master encryption key using password
        try:
            master_key = current_user.get_master_key(data["master_password"])
        except ValueError as e:
            return error_response(str(e), 401)

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


@utils_bp.route("/import/preview", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("10 per hour")
def preview_import():
    """
    Preview credentials from password manager export files before importing.
    Supports Chrome, Firefox, LastPass, 1Password, Bitwarden, and KeePass formats.
    """
    data = request.get_json()
    if not data:
        return error_response("Request data is required.", 400)

    if not data.get("content"):
        return error_response("Import content is required.", 400)

    try:
        from .import_parsers import ImportManager
        
        import_manager = ImportManager()
        parser_name = data.get("format")  # Optional format hint
        
        # Parse the content
        credentials, detected_format = import_manager.parse_import(data["content"], parser_name)
        
        # Validate credentials
        validation_issues = import_manager.validate_credentials(credentials)
        
        # Return preview data
        return success_response({
            "detected_format": detected_format,
            "credential_count": len(credentials),
            "credentials": credentials,
            "validation_issues": validation_issues,
            "supported_formats": import_manager.get_supported_formats()
        })

    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        current_app.logger.error(f"Error during import preview: {e}", exc_info=True)
        return error_response("Failed to preview import.", 500)


@utils_bp.route("/import/password-manager", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("5 per hour")
def import_from_password_manager():
    """
    Import credentials from popular password manager export files.
    Supports Chrome, Firefox, LastPass, 1Password, Bitwarden, and KeePass formats.
    """
    data = request.get_json()
    if not data:
        return error_response("Request data is required.", 400)

    if not data.get("master_password"):
        return error_response("Master password is required.", 400)

    if not data.get("content"):
        return error_response("Import content is required.", 400)

    try:
        # Get master encryption key using password
        try:
            master_key = current_user.get_master_key(data["master_password"])
        except ValueError as e:
            return error_response(str(e), 401)

        from .import_parsers import ImportManager
        from ..utils.password_policy import validate_credential_password
        
        import_manager = ImportManager()
        parser_name = data.get("format")  # Optional format hint
        skip_duplicates = data.get("skip_duplicates", True)
        enforce_policy = data.get("enforce_policy", False)
        
        # Parse the content
        credentials, detected_format = import_manager.parse_import(data["content"], parser_name)
        
        if not credentials:
            return error_response("No valid credentials found in import data.", 400)

        # Track import results
        imported_count = 0
        skipped_count = 0
        error_count = 0
        policy_violations = []

        # Process each credential
        for cred_data in credentials:
            try:
                service_name = cred_data.get("service_name", "")
                username = cred_data.get("username", "")
                password = cred_data.get("password", "")
                
                # Check for duplicates if requested
                if skip_duplicates:
                    existing_cred = Credential.query.filter_by(
                        user_id=current_user.id,
                        service_name=service_name,
                        username=username
                    ).first()
                    
                    if existing_cred:
                        skipped_count += 1
                        continue

                # Validate password policy if requested
                if enforce_policy and password:
                    is_valid, errors, warnings = validate_credential_password(
                        password, 
                        {"username": current_user.username, "email": current_user.email}, 
                        "create"
                    )
                    
                    if not is_valid:
                        policy_violations.append({
                            "service_name": service_name,
                            "username": username,
                            "errors": errors
                        })
                        error_count += 1
                        continue

                # Create new credential
                credential = Credential(
                    user_id=current_user.id,
                    service_name=service_name,
                    service_url=cred_data.get("service_url"),
                    username=username,
                    category=cred_data.get("category", "imported"),
                    notes=cred_data.get("notes"),
                )

                # Encrypt and store the password
                if password:
                    credential.encrypted_password = encrypt_data(master_key, password)
                else:
                    credential.encrypted_password = encrypt_data(master_key, "")

                db.session.add(credential)
                imported_count += 1

            except Exception as e:
                current_app.logger.error(f"Error importing credential {service_name}: {e}", exc_info=True)
                error_count += 1

        db.session.commit()
        
        # Log the import operation for audit
        AuditLog.log_event(
            user_id=current_user.id,
            event_type="password_manager_import",
            message=f"Imported {imported_count} credentials from {detected_format}, skipped {skipped_count}, errors {error_count}",
            ip_address=request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
            additional_data={
                "detected_format": detected_format,
                "imported_count": imported_count,
                "skipped_count": skipped_count,
                "error_count": error_count
            }
        )

        return success_response({
            "message": "Password manager import completed",
            "detected_format": detected_format,
            "imported_count": imported_count,
            "skipped_count": skipped_count,
            "error_count": error_count,
            "policy_violations": policy_violations if enforce_policy else None
        })

    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error during password manager import: {e}", exc_info=True)
        return error_response("Failed to import from password manager.", 500)


@utils_bp.route("/import/formats", methods=["GET"])
@login_required
def get_import_formats():
    """Get list of supported password manager import formats."""
    try:
        from .import_parsers import ImportManager
        
        import_manager = ImportManager()
        formats = import_manager.get_supported_formats()
        
        return success_response({
            "supported_formats": formats,
            "format_descriptions": {
                "Chrome/Edge/Firefox CSV": "Browser saved passwords export",
                "LastPass CSV": "LastPass vault export",
                "1Password CSV": "1Password vault export", 
                "Bitwarden JSON": "Bitwarden vault export (JSON format)",
                "Bitwarden CSV": "Bitwarden vault export (CSV format)",
                "KeePass XML": "KeePass database export"
            }
        })
    except Exception as e:
        current_app.logger.error(f"Error getting import formats: {e}", exc_info=True)
        return error_response("Failed to get import formats.", 500)


@utils_bp.route("/backup", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("3 per hour")
def create_backup():
    """
    Create a comprehensive backup of user data including credentials, settings, and metadata.
    Returns a password-protected ZIP file containing all user data.
    """
    data = request.get_json()
    if not data:
        return error_response("Request data is required.", 400)

    if not data.get("master_password"):
        return error_response("Master password is required to create backup.", 400)

    if not data.get("backup_password"):
        return error_response("Backup password is required to protect the backup file.", 400)

    try:
        # Verify master password
        try:
            master_key = current_user.get_master_key(data["master_password"])
        except ValueError as e:
            return error_response(str(e), 401)

        # Create backup data structure
        backup_data = {
            "version": "1.0",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "user_info": {
                "username": current_user.username,
                "email": current_user.email,
                "created_at": current_user.created_at.isoformat(),
                "otp_enabled": current_user.otp_enabled,
                "email_mfa_enabled": current_user.email_mfa_enabled
            },
            "credentials": [],
            "shared_credentials_sent": [],
            "shared_credentials_received": []
        }

        # Export credentials
        credentials = Credential.query.filter_by(user_id=current_user.id).all()
        for cred in credentials:
            try:
                decrypted_password = decrypt_data(master_key, cred.encrypted_password)
                backup_data["credentials"].append({
                    "service_name": cred.service_name,
                    "service_url": cred.service_url,
                    "username": cred.username,
                    "password": decrypted_password,
                    "notes": cred.notes,
                    "category": cred.category,
                    "created_at": cred.created_at.isoformat(),
                    "updated_at": cred.updated_at.isoformat()
                })
            except Exception as e:
                current_app.logger.error(f"Error decrypting credential {cred.id}: {e}", exc_info=True)
                return error_response("Failed to decrypt one or more credentials.", 500)

        # Export shared credentials metadata (sent by user)
        from ..models.shared_credential import SharedCredential
        sent_shares = SharedCredential.query.filter_by(owner_id=current_user.id).all()
        for share in sent_shares:
            backup_data["shared_credentials_sent"].append({
                "credential_service_name": share.credential.service_name,
                "recipient_email": share.recipient.email,
                "status": share.status,
                "can_view": share.can_view,
                "can_edit": share.can_edit,
                "message": share.message,
                "created_at": share.created_at.isoformat(),
                "expires_at": share.expires_at.isoformat() if share.expires_at else None
            })

        # Export received shares metadata
        received_shares = SharedCredential.query.filter_by(recipient_id=current_user.id).all()
        for share in received_shares:
            backup_data["shared_credentials_received"].append({
                "credential_service_name": share.credential.service_name,
                "owner_email": share.owner.email,
                "status": share.status,
                "can_view": share.can_view,
                "can_edit": share.can_edit,
                "message": share.message,
                "created_at": share.created_at.isoformat(),
                "accepted_at": share.accepted_at.isoformat() if share.accepted_at else None
            })

        # Create temporary JSON file
        backup_json = json.dumps(backup_data, indent=2)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_json:
            temp_json.write(backup_json.encode())
            temp_json_path = temp_json.name

        # Create password-protected ZIP
        temp_zip_path = os.path.join(tempfile.gettempdir(), f"user_backup_{current_user.id}_{int(time.time())}.zip")
        pyminizip.compress(temp_json_path, f"backup_{current_user.username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 
                          temp_zip_path, data["backup_password"], 5)

        # Read the zip file and create response
        with open(temp_zip_path, "rb") as zip_file:
            response = make_response(zip_file.read())

        # Clean up temporary files
        os.unlink(temp_json_path)
        os.unlink(temp_zip_path)

        response.headers.set("Content-Type", "application/zip")
        response.headers.set("Content-Disposition", "attachment", 
                           filename=f"backup_{current_user.username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")

        return response

    except Exception as e:
        # Clean up any temporary files in case of error
        if "temp_json_path" in locals() and os.path.exists(temp_json_path):
            os.unlink(temp_json_path)
        if "temp_zip_path" in locals() and os.path.exists(temp_zip_path):
            os.unlink(temp_zip_path)

        current_app.logger.error(f"Error during backup creation: {e}", exc_info=True)
        return error_response("Failed to create backup.", 500)


@utils_bp.route("/restore", methods=["POST"])
@csrf.exempt
@login_required  
@limiter.limit("2 per hour")
def restore_backup():
    """
    Restore user data from a backup file.
    Expects backup_data (JSON) and master_password in request.
    """
    data = request.get_json()
    if not data:
        return error_response("Request data is required.", 400)

    if not data.get("master_password"):
        return error_response("Master password is required for restore.", 400)

    if not data.get("backup_data"):
        return error_response("Backup data is required.", 400)

    # Options for restore behavior
    merge_credentials = data.get("merge_credentials", True)  # True to merge, False to replace
    skip_existing = data.get("skip_existing", True)  # Skip credentials that already exist

    try:
        # Verify master password
        try:
            master_key = current_user.get_master_key(data["master_password"])
        except ValueError as e:
            return error_response(str(e), 401)

        backup_data = data["backup_data"]
        
        # Validate backup data format
        if not isinstance(backup_data, dict) or "credentials" not in backup_data:
            return error_response("Invalid backup data format.", 400)

        restored_count = 0
        skipped_count = 0
        error_count = 0

        # Restore credentials
        for cred_data in backup_data.get("credentials", []):
            try:
                # Check if credential already exists (by service_name and username)
                existing_cred = Credential.query.filter_by(
                    user_id=current_user.id,
                    service_name=cred_data.get("service_name", ""),
                    username=cred_data.get("username", "")
                ).first()

                if existing_cred and skip_existing:
                    skipped_count += 1
                    continue

                # Create new credential or update existing
                if existing_cred and not skip_existing:
                    credential = existing_cred
                else:
                    credential = Credential(user_id=current_user.id)

                # Set credential data
                credential.service_name = cred_data.get("service_name", "")
                credential.service_url = cred_data.get("service_url")
                credential.username = cred_data.get("username", "")
                credential.notes = cred_data.get("notes")
                credential.category = cred_data.get("category")

                # Encrypt and store the password
                if "password" in cred_data and cred_data.get("password") is not None:
                    credential.encrypted_password = encrypt_data(master_key, cred_data["password"])
                else:
                    credential.encrypted_password = encrypt_data(master_key, "")

                if not existing_cred:
                    db.session.add(credential)
                
                restored_count += 1

            except Exception as e:
                current_app.logger.error(f"Error restoring credential {cred_data.get('service_name', 'unknown')}: {e}", exc_info=True)
                error_count += 1

        db.session.commit()

        # Log the restore operation
        from ..models.audit_log import AuditLog
        audit_log = AuditLog(
            user_id=current_user.id,
            event_type="backup_restore",
            message=f"Restored {restored_count} credentials, skipped {skipped_count}, errors {error_count}",
            ip_address=request.headers.get('X-Forwarded-For', request.remote_addr)
        )
        db.session.add(audit_log)
        db.session.commit()

        return success_response({
            "message": "Backup restored successfully",
            "restored_count": restored_count,
            "skipped_count": skipped_count,
            "error_count": error_count,
            "backup_version": backup_data.get("version", "unknown"),
            "backup_created_at": backup_data.get("created_at")
        })

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error during backup restore: {e}", exc_info=True)
        return error_response("Failed to restore backup.", 500)


@utils_bp.route("/password-policy", methods=["GET"])
@login_required
def get_password_policy():
    """Get the current password policy configuration."""
    from .password_policy import get_password_policy
    
    policy = get_password_policy()
    return success_response(policy)


@utils_bp.route("/password-generator", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("50 per minute")
def generate_password():
    """Generate secure passwords with customizable options."""
    data = request.get_json() or {}
    
    try:
        generator = PasswordGenerator()
        
        # Configure generator based on request parameters
        length = data.get('length', 16)
        generator.set_length(length)
        
        # Character sets
        char_sets = data.get('character_sets', {})
        generator.set_character_sets(
            lowercase=char_sets.get('lowercase', True),
            uppercase=char_sets.get('uppercase', True),
            digits=char_sets.get('digits', True),
            symbols=char_sets.get('symbols', True)
        )
        
        # Safety options
        if data.get('safe_symbols_only', False):
            generator.set_safe_symbols_only(True)
        
        if data.get('exclude_ambiguous', True):
            generator.set_exclude_ambiguous(True)
        
        # Minimum requirements
        min_reqs = data.get('minimum_requirements', {})
        generator.set_minimum_requirements(
            lowercase=min_reqs.get('lowercase', 1),
            uppercase=min_reqs.get('uppercase', 1),
            digits=min_reqs.get('digits', 1),
            symbols=min_reqs.get('symbols', 1)
        )
        
        # Exclude/require specific characters
        if data.get('exclude_characters'):
            generator.exclude_characters(data['exclude_characters'])
        
        if data.get('require_characters'):
            generator.require_characters(data['require_characters'])
        
        # Generate password(s)
        count = min(data.get('count', 1), 10)  # Limit to 10 passwords max
        
        if count == 1:
            password = generator.generate()
            strength = generator.analyze_strength(password)
            
            return success_response({
                'password': password,
                'strength': strength,
                'length': len(password)
            })
        else:
            passwords = generator.generate_multiple(count)
            strengths = [generator.analyze_strength(pwd) for pwd in passwords]
            
            return success_response({
                'passwords': [
                    {
                        'password': pwd,
                        'strength': strength,
                        'length': len(pwd)
                    }
                    for pwd, strength in zip(passwords, strengths)
                ]
            })
    
    except ValueError as e:
        return error_response(f"Invalid password generation parameters: {str(e)}", 400)
    except Exception as e:
        current_app.logger.error(f"Password generation error: {str(e)}", exc_info=True)
        return error_response("Password generation failed", 500)


@utils_bp.route("/password-analyzer", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("100 per minute")
def analyze_password():
    """Analyze password strength and provide feedback."""
    data = request.get_json()
    if not data or 'password' not in data:
        return error_response("Password is required for analysis", 400)
    
    password = data['password']
    
    try:
        analysis = analyze_password_strength(password)
        return success_response(analysis)
    
    except Exception as e:
        current_app.logger.error(f"Password analysis error: {str(e)}", exc_info=True)
        return error_response("Password analysis failed", 500)


@utils_bp.route("/password-presets", methods=["GET"])
@login_required
def get_password_presets():
    """Get predefined password generation presets."""
    presets = {
        'strong': {
            'name': 'Strong Password',
            'description': 'Balanced security and usability',
            'length': 16,
            'character_sets': {
                'lowercase': True,
                'uppercase': True,
                'digits': True,
                'symbols': True
            },
            'safe_symbols_only': False,
            'exclude_ambiguous': True,
            'minimum_requirements': {
                'lowercase': 1,
                'uppercase': 1,
                'digits': 1,
                'symbols': 1
            }
        },
        'maximum_security': {
            'name': 'Maximum Security',
            'description': 'Highest security for critical accounts',
            'length': 24,
            'character_sets': {
                'lowercase': True,
                'uppercase': True,
                'digits': True,
                'symbols': True
            },
            'safe_symbols_only': False,
            'exclude_ambiguous': True,
            'minimum_requirements': {
                'lowercase': 2,
                'uppercase': 2,
                'digits': 2,
                'symbols': 2
            }
        },
        'compatible': {
            'name': 'System Compatible',
            'description': 'Works with most systems and services',
            'length': 16,
            'character_sets': {
                'lowercase': True,
                'uppercase': True,
                'digits': True,
                'symbols': True
            },
            'safe_symbols_only': True,
            'exclude_ambiguous': True,
            'minimum_requirements': {
                'lowercase': 1,
                'uppercase': 1,
                'digits': 1,
                'symbols': 1
            }
        },
        'memorable': {
            'name': 'Memorable',
            'description': 'Longer but easier to read and type',
            'length': 20,
            'character_sets': {
                'lowercase': True,
                'uppercase': True,
                'digits': True,
                'symbols': True
            },
            'safe_symbols_only': True,
            'exclude_ambiguous': True,
            'minimum_requirements': {
                'lowercase': 2,
                'uppercase': 2,
                'digits': 2,
                'symbols': 1
            }
        },
        'pin': {
            'name': 'Numeric PIN',
            'description': 'Numbers only for PIN codes',
            'length': 6,
            'character_sets': {
                'lowercase': False,
                'uppercase': False,
                'digits': True,
                'symbols': False
            },
            'safe_symbols_only': False,
            'exclude_ambiguous': False,
            'minimum_requirements': {
                'lowercase': 0,
                'uppercase': 0,
                'digits': 6,
                'symbols': 0
            }
        }
    }
    
    return success_response({'presets': presets})


@utils_bp.route("/audit-logs", methods=["GET"])
@login_required
@limiter.limit("30 per minute")
def get_audit_logs():
    """Get audit logs for the current user."""
    try:
        # Get query parameters
        limit = min(request.args.get('limit', 50, type=int), 100)
        page = request.args.get('page', 1, type=int)
        event_types = request.args.getlist('event_types')
        
        # Build query for user's audit logs
        query = AuditLog.query.filter_by(user_id=current_user.id)
        
        if event_types:
            query = query.filter(AuditLog.event_type.in_(event_types))
        
        # Apply pagination
        paginated = query.order_by(AuditLog.created_at.desc()).paginate(
            page=page,
            per_page=limit,
            error_out=False
        )
        
        # Convert to dictionaries
        logs = [log.to_dict() for log in paginated.items]
        
        return success_response({
            'logs': logs,
            'pagination': {
                'page': paginated.page,
                'per_page': paginated.per_page,
                'total': paginated.total,
                'pages': paginated.pages,
                'has_next': paginated.has_next,
                'has_prev': paginated.has_prev
            }
        })
    
    except Exception as e:
        current_app.logger.error(f"Error retrieving audit logs: {e}", exc_info=True)
        return error_response("Failed to retrieve audit logs", 500)


@utils_bp.route("/security-summary", methods=["GET"])
@login_required
@limiter.limit("10 per minute")
def get_security_summary():
    """Get security summary and recent alerts for the current user."""
    try:
        # Get recent activity for this user
        recent_logs = AuditLog.get_user_activity(current_user.id, limit=10)
        
        # Count different types of events in the last 30 days
        from datetime import datetime, timezone, timedelta
        since = datetime.now(timezone.utc) - timedelta(days=30)
        
        event_counts = {}
        login_attempts = AuditLog.query.filter(
            AuditLog.user_id == current_user.id,
            AuditLog.event_type.in_([AuditLog.EVENT_LOGIN, AuditLog.EVENT_FAILED_LOGIN]),
            AuditLog.created_at >= since
        ).all()
        
        successful_logins = sum(1 for log in login_attempts if log.event_type == AuditLog.EVENT_LOGIN)
        failed_logins = sum(1 for log in login_attempts if log.event_type == AuditLog.EVENT_FAILED_LOGIN)
        
        # Get credential access counts
        credential_actions = AuditLog.query.filter(
            AuditLog.user_id == current_user.id,
            AuditLog.event_type.in_([
                AuditLog.EVENT_CREDENTIAL_CREATED,
                AuditLog.EVENT_CREDENTIAL_VIEWED,
                AuditLog.EVENT_CREDENTIAL_UPDATED,
                AuditLog.EVENT_CREDENTIAL_DELETED
            ]),
            AuditLog.created_at >= since
        ).count()
        
        # Check for any security warnings
        security_warnings = AuditLog.query.filter(
            AuditLog.user_id == current_user.id,
            AuditLog.severity.in_([AuditLog.SEVERITY_WARNING, AuditLog.SEVERITY_ERROR, AuditLog.SEVERITY_CRITICAL]),
            AuditLog.created_at >= since
        ).count()
        
        return success_response({
            'recent_activity': [log.to_dict() for log in recent_logs],
            'statistics': {
                'successful_logins': successful_logins,
                'failed_logins': failed_logins,
                'credential_actions': credential_actions,
                'security_warnings': security_warnings
            },
            'summary': {
                'account_secure': security_warnings == 0,
                'recent_activity_count': len(recent_logs),
                'period_days': 30
            }
        })
    
    except Exception as e:
        current_app.logger.error(f"Error generating security summary: {e}", exc_info=True)
        return error_response("Failed to generate security summary", 500)


@utils_bp.route("/password-health-report", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("5 per minute")
def get_password_health_report():
    """Generate a comprehensive password health report for the user's credentials."""
    data = request.get_json()
    if not data or not data.get("master_password"):
        return error_response("Master password is required", 400)
    
    try:
        # Get master encryption key using password
        try:
            master_key = current_user.get_master_key(data["master_password"])
        except ValueError as e:
            return error_response(str(e), 401)
        
        # Get all credentials
        credentials = Credential.query.filter_by(user_id=current_user.id).all()
        if not credentials:
            return success_response({
                'total_credentials': 0,
                'health_score': 100,
                'summary': {
                    'weak_passwords': 0,
                    'reused_passwords': 0,
                    'old_passwords': 0,
                    'strong_passwords': 0
                },
                'recommendations': ['Start adding credentials to get a security analysis'],
                'credentials_analysis': []
            })
        
        # Analyze each credential
        password_analysis = []
        decrypted_passwords = []
        weak_count = 0
        strong_count = 0
        
        for cred in credentials:
            try:
                decrypted_password = decrypt_data(master_key, cred.encrypted_password)
                decrypted_passwords.append(decrypted_password)
                
                # Analyze password strength
                strength_analysis = analyze_password_strength(decrypted_password)
                
                credential_info = {
                    'id': cred.id,
                    'service_name': cred.service_name,
                    'username': cred.username,
                    'last_updated': cred.updated_at.isoformat() if cred.updated_at else cred.created_at.isoformat(),
                    'strength': strength_analysis
                }
                
                if strength_analysis['score'] < 60:
                    weak_count += 1
                    credential_info['issues'] = ['Weak password']
                elif strength_analysis['score'] >= 80:
                    strong_count += 1
                
                password_analysis.append(credential_info)
                
            except Exception as e:
                current_app.logger.error(f"Error analyzing credential {cred.id}: {e}")
                password_analysis.append({
                    'id': cred.id,
                    'service_name': cred.service_name,
                    'username': cred.username,
                    'error': 'Could not analyze password'
                })
        
        # Check for password reuse
        password_counts = {}
        for pwd in decrypted_passwords:
            password_counts[pwd] = password_counts.get(pwd, 0) + 1
        
        reused_passwords = sum(1 for count in password_counts.values() if count > 1)
        reused_count = len([pwd for pwd, count in password_counts.items() if count > 1])
        
        # Mark reused passwords in analysis
        for analysis in password_analysis:
            if 'error' not in analysis:
                # Find the actual password for this credential to check reuse
                for cred in credentials:
                    if cred.id == analysis['id']:
                        try:
                            pwd = decrypt_data(master_key, cred.encrypted_password)
                            if password_counts.get(pwd, 0) > 1:
                                if 'issues' not in analysis:
                                    analysis['issues'] = []
                                analysis['issues'].append('Password reused')
                        except:
                            pass
                        break
        
        # Check for old passwords (older than 90 days)
        from datetime import datetime, timedelta
        # Use timezone-naive datetime since database timestamps are timezone-naive
        old_threshold_naive = datetime.now() - timedelta(days=90)
        old_count = sum(1 for cred in credentials 
                       if (cred.updated_at or cred.created_at) < old_threshold_naive)
        
        # Mark old passwords
        for analysis in password_analysis:
            if 'error' not in analysis:
                for cred in credentials:
                    if cred.id == analysis['id']:
                        last_update = cred.updated_at or cred.created_at
                        if last_update < old_threshold_naive:
                            if 'issues' not in analysis:
                                analysis['issues'] = []
                            analysis['issues'].append('Password not updated in 90+ days')
                        break
        
        # Calculate overall health score
        total_issues = weak_count + reused_count + old_count
        max_possible_issues = len(credentials) * 3  # 3 types of issues per credential
        health_score = max(0, 100 - (total_issues * 100 // max(max_possible_issues, 1)))
        
        # Generate recommendations
        recommendations = []
        if weak_count > 0:
            recommendations.append(f"Update {weak_count} weak password(s) with stronger alternatives")
        if reused_count > 0:
            recommendations.append(f"Create unique passwords for {reused_passwords} credential(s) that share passwords")
        if old_count > 0:
            recommendations.append(f"Consider updating {old_count} password(s) that haven't been changed in 90+ days")
        if not recommendations:
            recommendations.append("Great job! Your password security looks good")
        
        return success_response({
            'total_credentials': len(credentials),
            'health_score': health_score,
            'summary': {
                'weak_passwords': weak_count,
                'reused_passwords': reused_passwords,
                'old_passwords': old_count,
                'strong_passwords': strong_count
            },
            'recommendations': recommendations,
            'credentials_analysis': password_analysis
        })
        
    except Exception as e:
        current_app.logger.error(f"Error generating password health report: {e}", exc_info=True)
        return error_response("Failed to generate password health report", 500)


@utils_bp.route("/breach-check", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("10 per minute")
def check_password_breach():
    """Check if a password has been found in known data breaches."""
    data = request.get_json()
    if not data or "password" not in data:
        return error_response("Password is required", 400)
    
    password = data["password"]
    if not password:
        return error_response("Password cannot be empty", 400)
    
    try:
        from .breach_monitor import BreachMonitor
        
        is_breached, breach_count = BreachMonitor.check_password_breach(password)
        
        risk_level = "SAFE"
        if is_breached:
            if breach_count > 1000:
                risk_level = "CRITICAL"
            elif breach_count > 100:
                risk_level = "HIGH"
            else:
                risk_level = "MEDIUM"
        
        response_data = {
            "is_breached": is_breached,
            "breach_count": breach_count,
            "risk_level": risk_level,
            "recommendation": "Change this password immediately" if is_breached else "Password appears secure"
        }
        
        return success_response(response_data)
        
    except Exception as e:
        current_app.logger.error(f"Error checking password breach: {e}", exc_info=True)
        return error_response("Failed to check password breach", 500)


@utils_bp.route("/security-audit", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("3 per hour")
def security_audit():
    """Perform comprehensive security audit of user's credentials."""
    data = request.get_json()
    master_password = data.get("master_password") if data else None
    
    if not master_password:
        return error_response("Master password is required for security audit", 400)
    
    try:
        # Verify master password
        try:
            master_key = current_user.get_master_key(master_password)
        except ValueError:
            return error_response("Invalid master password", 401)
        
        # Get all user credentials
        credentials = Credential.query.filter_by(user_id=current_user.id).all()
        
        # Decrypt credentials for analysis
        from .encryption import decrypt_data
        decrypted_credentials = []
        
        for credential in credentials:
            try:
                decrypted_password = decrypt_data(master_key, credential.encrypted_password)
                decrypted_credentials.append({
                    'id': credential.id,
                    'service_name': credential.service_name,
                    'username': credential.username,
                    'password': decrypted_password,
                    'created_at': credential.created_at.isoformat(),
                    'updated_at': credential.updated_at.isoformat()
                })
            except Exception as decrypt_error:
                current_app.logger.warning(f"Failed to decrypt credential {credential.id}: {decrypt_error}")
                continue
        
        # Perform security analysis
        from .breach_monitor import analyze_credential_security, generate_security_recommendations
        
        analysis_results = analyze_credential_security(decrypted_credentials)
        recommendations = generate_security_recommendations(analysis_results)
        
        # Remove actual password data from response for security
        sanitized_results = {
            'total_credentials': analysis_results['total_credentials'],
            'breached_passwords': analysis_results['breached_passwords'],
            'weak_passwords': analysis_results['weak_passwords'],
            'reused_passwords_count': len(analysis_results['reused_passwords']),
            'high_risk_count': len(analysis_results['high_risk_passwords']),
            'analysis_timestamp': analysis_results['analysis_timestamp'],
            'recommendations': recommendations
        }
        
        return success_response({
            'audit_results': sanitized_results,
            'next_recommended_audit': 'Schedule next audit in 30 days'
        })
        
    except Exception as e:
        current_app.logger.error(f"Error performing security audit: {e}", exc_info=True)
        return error_response("Failed to perform security audit", 500)
