import logging
from flask import request, jsonify, abort, session
from flask_login import login_required, current_user
from . import credentials_bp
from .. import db
from ..models.user import User
from ..models.credential import Credential
from ..utils.encryption import encrypt_data, decrypt_data
from ..utils.responses import success_response, error_response
from ..utils.master_verification import MasterVerificationManager
from .. import limiter
import time

logger = logging.getLogger(__name__)


@credentials_bp.route("/verify-master", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def verify_master_password():
    """Verify master password and store verification in session temporarily."""
    data = request.get_json()
    if not data or not data.get("master_password"):
        return error_response("Master password is required.", 400)

    try:
        MasterVerificationManager.verify_and_store(data["master_password"])
        return success_response(message="Master password verified.")
    except ValueError:
        return error_response("Invalid master password.", 401)


@credentials_bp.route("/verify-master/status", methods=["GET"])
@login_required
def check_master_verification_status():
    """Check the current status of master password verification."""
    status = MasterVerificationManager.get_status()
    return success_response(status)


def require_master_password():
    """Check if master password verification is still valid."""
    return MasterVerificationManager.require_verification()


@credentials_bp.route("/", methods=["POST"])
@login_required
def create_credential():
    """Create a new credential for the logged-in user."""
    if not require_master_password():
        return error_response("Master password verification required.", 401)

    data = request.get_json()
    if not data or not all(k in data for k in ("service_name", "username", "password")):
        return error_response("Missing required fields: service_name, username, password", 400)

    try:
        # Get master encryption key - the master password was already verified
        # by the session verification, so we can use the master key directly
        master_key = current_user.get_master_key(data["master_password"])
        encrypted_pw = encrypt_data(master_key, data["password"])
    except ValueError as e:
        logger.error(f"Error retrieving master key: {e}", exc_info=True)
        return error_response("Invalid master password. Please verify your password again.", 401)
    except Exception as e:
        logger.error(f"Error encrypting password for new credential: {e}", exc_info=True)
        return error_response("Failed to encrypt password securely. Please try again.", 500)

    new_credential = Credential(
        user_id=current_user.id,
        service_name=data["service_name"],
        service_url=data.get("service_url"),
        username=data["username"],
        encrypted_password=encrypted_pw,
        notes=data.get("notes"),
        category=data.get("category"),
    )

    try:
        db.session.add(new_credential)
        db.session.commit()
        return success_response(
            {
                "id": new_credential.id,
                "service_name": new_credential.service_name,
                "username": new_credential.username,
                "category": new_credential.category,
                "created_at": new_credential.created_at,
            },
            status_code=201,
        )
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error creating credential: {e}", exc_info=True)
        return error_response("Could not save credential to database.", 500)


@credentials_bp.route("/", methods=["GET"])
@login_required
def list_credentials():
    """List all credentials for the logged-in user (names/ids only)."""
    # Add optional category filter
    query = Credential.query.filter_by(user_id=current_user.id)

    user_creds = query.order_by(Credential.category).order_by(Credential.service_name).all()

    return success_response(
        [{"id": cred.id, "service_name": cred.service_name, "username": cred.username, "service_url": cred.service_url, "category": cred.category} for cred in user_creds]
    )


@credentials_bp.route("/<int:credential_id>", methods=["POST"])
@login_required
def get_credential(credential_id):
    """Get a specific credential's details including decrypted password."""
    data = request.get_json()
    if not data or "master_password" not in data:
        return error_response("Master password required.", 400)

    credential = Credential.query.get_or_404(credential_id)
    if credential.user_id != current_user.id:
        return error_response("You do not have permission to access this credential.", 403)

    try:
        # Get master encryption key using provided password
        master_key = current_user.get_master_key(data["master_password"])
        decrypted_password = decrypt_data(master_key, credential.encrypted_password)
    except ValueError as e:
        logger.error(f"Invalid master password: {e}")
        return error_response("Invalid master password.", 401)
    except Exception as e:
        logger.error(f"Error decrypting credential {credential.id}: {e}", exc_info=True)
        return error_response("Failed to decrypt credential.", 500)

    return success_response(
        {
            "id": credential.id,
            "service_name": credential.service_name,
            "service_url": credential.service_url,
            "username": credential.username,
            "password": decrypted_password,
            "notes": credential.notes,
            "category": credential.category,
            "created_at": credential.created_at,
            "updated_at": credential.updated_at,
        }
    )


@credentials_bp.route("/<int:credential_id>", methods=["PUT"])
@login_required
@limiter.limit("1 per minute")
def update_credential(credential_id):
    """Update an existing credential."""
    data = request.get_json()
    if not data:
        return error_response("No update data provided.", 400)

    if "master_password" not in data:
        return error_response("Master password required.", 400)

    credential = Credential.query.get_or_404(credential_id)
    if credential.user_id != current_user.id:
        return error_response("You do not have permission to access this credential.", 403)

    # Handle password updates
    if "password" in data:
        try:
            master_key = current_user.get_master_key(data["master_password"])
            credential.encrypted_password = encrypt_data(master_key, data["password"])
        except ValueError as e:
            logger.error(f"Invalid master password: {e}")
            return error_response("Invalid master password.", 401)
        except Exception as e:
            logger.error(f"Error encrypting new password for credential {credential.id}: {e}", exc_info=True)
            return error_response("Failed to encrypt new password securely. Please try again.", 500)

    # Update other fields
    updated = False
    if "service_name" in data:
        credential.service_name = data["service_name"]
        updated = True
    if "service_url" in data:
        credential.service_url = data["service_url"]
        updated = True
    if "username" in data:
        credential.username = data["username"]
        updated = True
    if "notes" in data:
        credential.notes = data["notes"]
        updated = True
    if "category" in data:
        credential.category = data["category"]
        updated = True
    if "password" in data:
        updated = True

    if not updated:
        return success_response({"message": "No changes detected"})

    try:
        db.session.commit()
        return success_response(
            {
                "id": credential.id,
                "service_name": credential.service_name,
                "username": credential.username,
                "category": credential.category,
                "updated_at": credential.updated_at,
            }
        )
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error updating credential: {e}", exc_info=True)
        return error_response("Could not save updated credential.", 500)


@credentials_bp.route("/<int:credential_id>/password", methods=["POST"])
@login_required
@limiter.limit("20 per minute")
def get_credential_password(credential_id):
    """Get only the decrypted password for a specific credential."""
    data = request.get_json()
    if not data or "master_password" not in data:
        return error_response("Master password required.", 400)

    credential = Credential.query.get_or_404(credential_id)
    if credential.user_id != current_user.id:
        return error_response("You do not have permission to access this credential.", 403)

    try:
        # Get master encryption key using provided password
        master_key = current_user.get_master_key(data["master_password"])
        decrypted_password = decrypt_data(master_key, credential.encrypted_password)
    except ValueError as e:
        logger.error(f"Invalid master password: {e}")
        return error_response("Invalid master password.", 401)
    except Exception as e:
        logger.error(f"Error decrypting credential {credential.id}: {e}", exc_info=True)
        return error_response("Failed to decrypt credential.", 500)

    return success_response({"password": decrypted_password})


@credentials_bp.route("/<int:credential_id>", methods=["DELETE"])
@login_required
@limiter.limit("1 per minute")
def delete_credential(credential_id):
    """Delete a credential."""
    # No master password needed for deletion, but might want to add it for extra security
    credential = Credential.query.get_or_404(credential_id)
    if credential.user_id != current_user.id:
        return error_response("You do not have permission to access this credential.", 403)

    try:
        db.session.delete(credential)
        db.session.commit()
        return success_response("Credential deleted successfully")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error deleting credential: {e}")
        return error_response("Could not delete credential.", 500)


@credentials_bp.route("/audit", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def audit_passwords():
    """Audit credential passwords by searching decrypted passwords for a search term."""
    data = request.get_json()
    if not data or not all(k in data for k in ("master_password", "search_term")):
        return error_response("Master password and search term are required.", 400)

    search_term = data["search_term"].lower().strip()
    if not search_term:
        return error_response("Search term cannot be empty.", 400)

    try:
        # Get master encryption key using provided password
        master_key = current_user.get_master_key(data["master_password"])
    except ValueError as e:
        logger.error(f"Invalid master password during audit: {e}")
        return error_response("Invalid master password.", 401)
    except Exception as e:
        logger.error(f"Error retrieving master key for audit: {e}", exc_info=True)
        return error_response("Failed to verify master password.", 500)

    # Get all user's credentials
    user_creds = Credential.query.filter_by(user_id=current_user.id).order_by(Credential.category).order_by(Credential.service_name).all()
    
    matching_credentials = []
    
    for cred in user_creds:
        try:
            # Decrypt the password and check if search term is contained
            decrypted_password = decrypt_data(master_key, cred.encrypted_password)
            if search_term in decrypted_password.lower():
                matching_credentials.append({
                    "id": cred.id,
                    "service_name": cred.service_name,
                    "username": cred.username,
                    "service_url": cred.service_url,
                    "category": cred.category
                })
        except Exception as e:
            logger.error(f"Error decrypting credential {cred.id} during audit: {e}", exc_info=True)
            # Continue with other credentials if one fails to decrypt
            continue

    return success_response(matching_credentials)
