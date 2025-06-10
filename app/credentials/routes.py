import logging
from flask import request, jsonify, abort, session, current_app
from flask_login import login_required, current_user
from .. import csrf
from sqlalchemy.orm import joinedload
from . import credentials_bp
from .. import db
from ..models.user import User
from ..models.credential import Credential
from ..utils.encryption import encrypt_data, decrypt_data
from ..utils.responses import success_response, error_response
from .. import limiter
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Session key for temporarily storing the master password hash
MASTER_PASSWORD_SESSION_KEY = "master_password_verified"
# Time in seconds that the master password verification remains valid
MASTER_PASSWORD_TIMEOUT = 300  # 5 minutes


@credentials_bp.route("/verify-master", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("10 per minute")
def verify_master_password():
    """Verify master password and store verification in session temporarily."""
    data = request.get_json()
    if not data or not data.get("master_password"):
        return error_response("Master password is required.", 400)

    try:
        # Try to get master key - this will validate the password
        master_key = current_user.get_master_key(data["master_password"])

        # Store verification in session with timestamp
        session[MASTER_PASSWORD_SESSION_KEY] = {"verified": True, "timestamp": int(time.time())}
        session.modified = True

        return success_response(message="Master password verified.")
    except ValueError as e:
        return error_response("Invalid master password.", 401)


@credentials_bp.route("/verify-master/status", methods=["GET"])
@login_required
def check_master_verification_status():
    """Check the current status of master password verification."""
    verification = session.get(MASTER_PASSWORD_SESSION_KEY)
    current_time = int(time.time())

    if not verification or not verification.get("verified"):
        return success_response({"verified": False, "expires_at": None, "time_remaining": 0})

    verification_time = verification["timestamp"]
    expires_at = verification_time + MASTER_PASSWORD_TIMEOUT
    time_remaining = max(0, expires_at - current_time)

    # If expired, clean up the session
    if time_remaining == 0:
        session.pop(MASTER_PASSWORD_SESSION_KEY, None)
        session.modified = True

    return success_response({"verified": time_remaining > 0, "expires_at": expires_at, "time_remaining": time_remaining})


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
@csrf.exempt
@login_required
def create_credential():
    """Create a new credential for the logged-in user."""
    data = request.get_json()
    if not data or not all(k in data for k in ("service_name", "username", "password", "master_password")):
        return error_response("Missing required fields: service_name, username, password, master_password", 400)

    # Validate password against policy
    from ..utils.password_policy import validate_credential_password
    user_info = {
        'username': current_user.username,
        'email': current_user.email
    }
    is_valid, policy_errors, policy_warnings = validate_credential_password(
        data["password"], user_info, "create"
    )
    
    if not is_valid and policy_errors:
        return error_response(f"Password policy violation: {'; '.join(policy_errors)}", 400)

    try:
        # Get master encryption key - always verify the master password for security
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
        
        # Add audit log entry
        from ..models.audit_log import AuditLog
        audit_log = AuditLog(
            user_id=current_user.id,
            event_type=AuditLog.EVENT_CREDENTIAL_CREATED,
            message=f"Created credential for {data['service_name']}",
            ip_address=request.headers.get('X-Forwarded-For', request.remote_addr),
            severity=AuditLog.SEVERITY_INFO
        )
        db.session.add(audit_log)
        db.session.commit()
        
        response_data = {
            "id": new_credential.id,
            "service_name": new_credential.service_name,
            "username": new_credential.username,
            "category": new_credential.category,
            "created_at": new_credential.created_at,
        }
        
        # Include policy warnings if any
        if policy_warnings:
            response_data["password_policy_warnings"] = policy_warnings
        
        return success_response(response_data, status_code=201)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error creating credential: {e}", exc_info=True)
        return error_response("Could not save credential to database.", 500)


@credentials_bp.route("/", methods=["GET"])
@login_required
def list_credentials():
    """List credentials for the logged-in user with pagination and filtering."""
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)  # Limit max per_page to 100
    
    # Get filter parameters
    category = request.args.get('category')
    search = request.args.get('search')
    
    # Build query with filters
    query = Credential.query.filter_by(user_id=current_user.id)
    
    if category:
        query = query.filter(Credential.category == category)
    
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            db.or_(
                Credential.service_name.ilike(search_pattern),
                Credential.username.ilike(search_pattern),
                Credential.service_url.ilike(search_pattern)
            )
        )
    
    # Apply ordering and pagination
    paginated = query.order_by(Credential.category.asc(), Credential.service_name.asc()).paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )
    
    # Format response with pagination metadata
    return success_response({
        "credentials": [
            {
                "id": cred.id,
                "service_name": cred.service_name,
                "username": cred.username,
                "service_url": cred.service_url,
                "category": cred.category,
                "created_at": cred.created_at,
                "updated_at": cred.updated_at
            } for cred in paginated.items
        ],
        "pagination": {
            "page": paginated.page,
            "per_page": paginated.per_page,
            "total": paginated.total,
            "pages": paginated.pages,
            "has_next": paginated.has_next,
            "has_prev": paginated.has_prev,
            "next_num": paginated.next_num,
            "prev_num": paginated.prev_num
        }
    })


@credentials_bp.route("/<int:credential_id>", methods=["POST"])
@csrf.exempt
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
@csrf.exempt
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
    policy_warnings = []
    if "password" in data:
        # Validate password against policy
        from ..utils.password_policy import validate_credential_password
        user_info = {
            'username': current_user.username,
            'email': current_user.email
        }
        is_valid, policy_errors, policy_warnings = validate_credential_password(
            data["password"], user_info, "update"
        )
        
        if not is_valid and policy_errors:
            return error_response(f"Password policy violation: {'; '.join(policy_errors)}", 400)
        
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
        
        response_data = {
            "id": credential.id,
            "service_name": credential.service_name,
            "username": credential.username,
            "category": credential.category,
            "updated_at": credential.updated_at,
        }
        
        # Include policy warnings if any
        if policy_warnings:
            response_data["password_policy_warnings"] = policy_warnings
        
        return success_response(response_data)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error updating credential: {e}", exc_info=True)
        return error_response("Could not save updated credential.", 500)


@credentials_bp.route("/<int:credential_id>", methods=["DELETE"])
@csrf.exempt
@login_required
def delete_credential(credential_id):
    """Delete a credential."""
    data = request.get_json()
    if not data or "master_password" not in data:
        return error_response("Master password required for credential deletion.", 400)
    
    credential = Credential.query.get_or_404(credential_id)
    if credential.user_id != current_user.id:
        return error_response("You do not have permission to access this credential.", 403)

    # Verify master password before deletion for security
    try:
        current_user.get_master_key(data["master_password"])
    except ValueError:
        return error_response("Invalid master password.", 401)

    try:
        db.session.delete(credential)
        db.session.commit()
        return success_response("Credential deleted successfully")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error deleting credential: {e}")
        return error_response("Could not delete credential.", 500)


# Credential sharing endpoints

@credentials_bp.route("/<int:credential_id>/share", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("10 per hour")
def share_credential(credential_id):
    """Share a credential with another user."""
    data = request.get_json()
    if not data:
        return error_response("Request data is required", 400)
    
    recipient_email = data.get("recipient_email")
    master_password = data.get("master_password")
    can_edit = data.get("can_edit", False)
    message = data.get("message", "")
    expires_days = data.get("expires_days")
    
    if not recipient_email or not master_password:
        return error_response("Recipient email and master password are required", 400)
    
    try:
        # Get the credential to share
        credential = Credential.query.filter_by(id=credential_id, user_id=current_user.id).first()
        if not credential:
            return error_response("Credential not found", 404)
        
        # Find the recipient user
        from ..models.user import User
        recipient = User.query.filter_by(email=recipient_email).first()
        if not recipient:
            return error_response("Recipient user not found", 404)
        
        if recipient.id == current_user.id:
            return error_response("Cannot share credential with yourself", 400)
        
        # Check if already shared with this user
        from ..models.shared_credential import SharedCredential
        existing_share = SharedCredential.query.filter_by(
            credential_id=credential_id,
            recipient_id=recipient.id
        ).first()
        
        if existing_share and existing_share.status in ['pending', 'accepted']:
            return error_response("Credential is already shared with this user", 409)
        
        # Get owner's master key to decrypt the credential
        try:
            owner_master_key = current_user.get_master_key(master_password)
        except ValueError as e:
            return error_response(str(e), 401)
        
        # Decrypt the credential password
        from ..utils.encryption import decrypt_data, encrypt_data
        decrypted_password = decrypt_data(owner_master_key, credential.encrypted_password)
        
        # Create credential data to share
        credential_data = {
            'service_name': credential.service_name,
            'service_url': credential.service_url,
            'username': credential.username,
            'password': decrypted_password,
            'notes': credential.notes,
            'category': credential.category
        }
        
        # Encrypt for recipient using their master key
        # Note: This requires the recipient to have initialized encryption
        if not recipient.encrypted_master_key:
            return error_response("Recipient has not set up encryption", 400)
        
        # Encrypt the credential data for the recipient
        # We'll store the plaintext credential data encrypted with the recipient's key
        # Since we can't get recipient's master key here, we'll use a different approach:
        # Store the plaintext data encrypted with a temporary key derived from both users' IDs
        import json
        credential_json = json.dumps(credential_data)
        
        # Generate a temporary sharing key from recipient's encryption salt
        # This allows the recipient to decrypt with their own credentials
        from ..utils.encryption import derive_key
        sharing_key = derive_key(f"share_{current_user.id}_{recipient.id}", recipient.encryption_salt)
        encrypted_for_recipient = encrypt_data(sharing_key, credential_json)
        
        # Calculate expiration date
        expires_at = None
        if expires_days:
            from datetime import timedelta
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)
        
        # Create the share record
        share = SharedCredential(
            credential_id=credential_id,
            owner_id=current_user.id,
            recipient_id=recipient.id,
            encrypted_data_for_recipient=encrypted_for_recipient,
            can_view=True,
            can_edit=can_edit,
            expires_at=expires_at,
            message=message,
            status='pending'
        )
        
        db.session.add(share)
        db.session.commit()
        
        # Send notification email to recipient
        try:
            from ..utils.email import send_email
            from flask import render_template
            
            share_url = f"{request.host_url}shared-credentials"  # Frontend route
            email_html = render_template('email/credential_shared.html', 
                                       recipient=recipient,
                                       owner=current_user,
                                       credential=credential,
                                       share=share,
                                       share_url=share_url)
            
            send_email(to=recipient.email, 
                     subject=f"Credential shared: {credential.service_name}", 
                     template=email_html)
        except Exception as e:
            current_app.logger.error(f"Failed to send share notification: {e}")
            # Don't fail the share if email fails
        
        return success_response({
            'message': 'Credential shared successfully',
            'share_id': share.id,
            'recipient_email': recipient.email,
            'expires_at': expires_at.isoformat() if expires_at else None
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error sharing credential: {e}", exc_info=True)
        return error_response("Failed to share credential", 500)


@credentials_bp.route("/shared", methods=["GET"])
@login_required 
@limiter.limit("30 per minute")
def get_shared_credentials():
    """Get credentials shared with the current user."""
    try:
        from ..models.shared_credential import SharedCredential
        
        # Get shares where current user is the recipient (with eager loading to avoid N+1 queries)
        shares = SharedCredential.query.filter_by(
            recipient_id=current_user.id
        ).filter(
            SharedCredential.status.in_(['pending', 'accepted'])
        ).options(
            joinedload(SharedCredential.credential),
            joinedload(SharedCredential.owner)
        ).all()
        
        # Filter out expired shares
        active_shares = [share for share in shares if not share.is_expired()]
        
        shared_credentials = []
        for share in active_shares:
            share_data = share.to_dict()
            share_data['credential'] = {
                'id': share.credential.id,
                'service_name': share.credential.service_name,
                'service_url': share.credential.service_url,
                'username': share.credential.username,
                'category': share.credential.category,
                'created_at': share.credential.created_at.isoformat()
            }
            share_data['owner'] = {
                'id': share.owner.id,
                'username': share.owner.username,
                'email': share.owner.email
            }
            shared_credentials.append(share_data)
        
        return success_response({
            'shared_credentials': shared_credentials,
            'total': len(shared_credentials)
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting shared credentials: {e}", exc_info=True)
        return error_response("Failed to get shared credentials", 500)


@credentials_bp.route("/shared/<int:share_id>/accept", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("10 per minute") 
def accept_shared_credential(share_id):
    """Accept a shared credential."""
    data = request.get_json()
    if not data:
        return error_response("Request data is required", 400)
    
    master_password = data.get("master_password")
    if not master_password:
        return error_response("Master password is required", 400)
    
    try:
        from ..models.shared_credential import SharedCredential
        
        # Get the share
        share = SharedCredential.query.filter_by(
            id=share_id,
            recipient_id=current_user.id
        ).first()
        
        if not share:
            return error_response("Shared credential not found", 404)
        
        if share.status != 'pending':
            return error_response("Shared credential is not pending", 400)
        
        if share.is_expired():
            return error_response("Shared credential has expired", 400)
        
        # Verify recipient's master password
        try:
            recipient_master_key = current_user.get_master_key(master_password)
        except ValueError as e:
            return error_response(str(e), 401)
        
        # Decrypt the shared credential data using the sharing key
        try:
            from ..utils.encryption import decrypt_data, encrypt_data, derive_key
            import json
            
            # Generate the same sharing key that was used when creating the share
            sharing_key = derive_key(f"share_{share.owner_id}_{current_user.id}", current_user.encryption_salt)
            
            # Decrypt the shared credential data
            decrypted_data = decrypt_data(sharing_key, share.encrypted_data_for_recipient)
            credential_data = json.loads(decrypted_data)
            
            # Create a new credential for the recipient with their encryption
            new_credential = Credential(
                user_id=current_user.id,
                service_name=credential_data['service_name'],
                service_url=credential_data.get('service_url'),
                username=credential_data['username'],
                encrypted_password=encrypt_data(recipient_master_key, credential_data['password']),
                notes=credential_data.get('notes'),
                category=credential_data.get('category')
            )
            
            db.session.add(new_credential)
            
        except Exception as decrypt_error:
            current_app.logger.error(f"Error decrypting shared credential data: {decrypt_error}", exc_info=True)
            return error_response("Failed to decrypt shared credential data", 400)
        
        # Accept the share
        share.accept()
        db.session.commit()
        
        return success_response({
            'message': 'Shared credential accepted successfully and added to your vault',
            'share_id': share.id,
            'new_credential_id': new_credential.id
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error accepting shared credential: {e}", exc_info=True)
        return error_response("Failed to accept shared credential", 500)


@credentials_bp.route("/shared/<int:share_id>/reject", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("10 per minute")
def reject_shared_credential(share_id):
    """Reject a shared credential."""
    try:
        from ..models.shared_credential import SharedCredential
        
        # Get the share
        share = SharedCredential.query.filter_by(
            id=share_id,
            recipient_id=current_user.id
        ).first()
        
        if not share:
            return error_response("Shared credential not found", 404)
        
        if share.status != 'pending':
            return error_response("Shared credential is not pending", 400)
        
        # Reject the share
        share.reject()
        db.session.commit()
        
        return success_response({
            'message': 'Shared credential rejected',
            'share_id': share.id
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error rejecting shared credential: {e}", exc_info=True)
        return error_response("Failed to reject shared credential", 500)


@credentials_bp.route("/<int:credential_id>/shares", methods=["GET"])
@login_required
@limiter.limit("30 per minute")
def get_credential_shares(credential_id):
    """Get all shares for a credential owned by the current user."""
    try:
        # Verify ownership
        credential = Credential.query.filter_by(id=credential_id, user_id=current_user.id).first()
        if not credential:
            return error_response("Credential not found", 404)
        
        from ..models.shared_credential import SharedCredential
        
        shares = SharedCredential.query.filter_by(
            credential_id=credential_id,
            owner_id=current_user.id
        ).options(
            joinedload(SharedCredential.recipient)
        ).all()
        
        shares_data = []
        for share in shares:
            share_data = share.to_dict()
            share_data['recipient'] = {
                'id': share.recipient.id,
                'username': share.recipient.username,
                'email': share.recipient.email
            }
            shares_data.append(share_data)
        
        return success_response({
            'shares': shares_data,
            'total': len(shares_data)
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting credential shares: {e}", exc_info=True)
        return error_response("Failed to get credential shares", 500)


@credentials_bp.route("/shared/<int:share_id>/revoke", methods=["POST"])
@csrf.exempt
@login_required
@limiter.limit("10 per minute")
def revoke_shared_credential(share_id):
    """Revoke a shared credential (owner only)."""
    try:
        from ..models.shared_credential import SharedCredential
        
        # Get the share
        share = SharedCredential.query.filter_by(
            id=share_id,
            owner_id=current_user.id
        ).first()
        
        if not share:
            return error_response("Shared credential not found", 404)
        
        if share.status not in ['pending', 'accepted']:
            return error_response("Cannot revoke this shared credential", 400)
        
        # Revoke the share
        share.revoke()
        db.session.commit()
        
        return success_response({
            'message': 'Shared credential revoked successfully',
            'share_id': share.id
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error revoking shared credential: {e}", exc_info=True)
        return error_response("Failed to revoke shared credential", 500)
