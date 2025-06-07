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
from .password_generator import PasswordGenerator, analyze_password_strength
from ..models.audit_log import AuditLog
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


@utils_bp.route("/password-generator", methods=["POST"])
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
