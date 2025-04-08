import logging
from flask import request, jsonify, abort, session
from flask_login import login_required, current_user
from . import credentials_bp
from .. import db
from ..models.user import User
from ..models.credential import Credential
from ..utils.encryption import derive_key, encrypt_data, decrypt_data
from ..utils.responses import success_response, error_response
from .. import limiter
import time

logger = logging.getLogger(__name__)

# Session key for temporarily storing the master password hash
MASTER_PASSWORD_SESSION_KEY = "master_password_verified"
# Time in seconds that the master password verification remains valid
MASTER_PASSWORD_TIMEOUT = 300  # 5 minutes


@credentials_bp.route("/verify-master", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def verify_master_password():
    """Verify master password and store verification in session temporarily."""
    data = request.get_json()
    if not data or not data.get("master_password"):
        return error_response("Master password is required.", 400)

    if not current_user.check_password(data["master_password"]):
        return error_response("Invalid master password.", 401)

    # Store verification in session with timestamp
    session[MASTER_PASSWORD_SESSION_KEY] = {"verified": True, "timestamp": int(time.time())}
    session.modified = True

    return success_response("Master password verified.")


@credentials_bp.route("/verify-master/status", methods=["GET"])
@login_required
def check_master_verification_status():
    """Check the current status of master password verification."""
    verification = session.get(MASTER_PASSWORD_SESSION_KEY)
    current_time = int(time.time())

    if not verification or not verification.get("verified"):
        return jsonify({"verified": False, "expires_at": None, "time_remaining": 0})

    verification_time = verification["timestamp"]
    expires_at = verification_time + MASTER_PASSWORD_TIMEOUT
    time_remaining = max(0, expires_at - current_time)

    # If expired, clean up the session
    if time_remaining == 0:
        session.pop(MASTER_PASSWORD_SESSION_KEY, None)
        session.modified = True

    return jsonify({"verified": time_remaining > 0, "expires_at": expires_at, "time_remaining": time_remaining})


def require_master_password():
    """Check if master password verification is still valid."""
    verification = session.get(MASTER_PASSWORD_SESSION_KEY)
    if not verification or not verification.get("verified"):
        return False

    # Check if verification has expired
    if int(time.time()) - verification["timestamp"] > MASTER_PASSWORD_TIMEOUT:
        session.pop(MASTER_PASSWORD_SESSION_KEY, None)
        session.modified = True
        return False

    return True


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
        encryption_key = derive_key(data["master_password"], current_user.encryption_salt)
        encrypted_pw = encrypt_data(encryption_key, data["password"])
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
        return (
            jsonify(
                {
                    "id": new_credential.id,
                    "service_name": new_credential.service_name,
                    "username": new_credential.username,
                    "category": new_credential.category,
                    "created_at": new_credential.created_at,
                }
            ),
            201,
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
    category = request.args.get("category")
    query = Credential.query.filter_by(user_id=current_user.id)

    if category:
        query = query.filter_by(category=category)

    user_creds = query.order_by(Credential.category).order_by(Credential.service_name).all()

    return jsonify(
        [
            {"id": cred.id, "service_name": cred.service_name, "username": cred.username, "service_url": cred.service_url, "category": cred.category}
            for cred in user_creds
        ]
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
        encryption_key = derive_key(data["master_password"], current_user.encryption_salt)
        decrypted_password = decrypt_data(encryption_key, credential.encrypted_password)
    except Exception as e:
        logger.error(f"Error decrypting credential {credential.id}: {e}", exc_info=True)
        return error_response("Failed to decrypt credential.", 500)

    return jsonify(
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
            encryption_key = derive_key(data["master_password"], current_user.encryption_salt)
            credential.encrypted_password = encrypt_data(encryption_key, data["password"])
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
        return jsonify({"message": "No changes detected"}), 200

    try:
        db.session.commit()
        return jsonify(
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


@credentials_bp.route("/<int:credential_id>", methods=["DELETE"])
@login_required
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


# Routes for CRUD operations on credentials will go here in Phase 3
