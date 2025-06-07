# from flask import request, jsonify
# from . import security_bp
# from ..models import db
# from ..utils.responses import success_response, error_response

import pyotp
import qrcode
import io
import base64
from flask import request, jsonify, current_app, Response, session, render_template
from flask_login import login_required, current_user
from . import security_bp
from ..models import db, User, MfaVerificationCode
from ..utils.responses import success_response, error_response
from ..utils.email import send_email
from .. import limiter
from ..models.config import get_config_value


@security_bp.route("/otp/setup", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def otp_setup():
    """Generates an OTP secret and provisioning URI for the current user."""
    user = current_user
    data = request.get_json()

    # Require password confirmation
    if not data or not data.get("password"):
        return error_response("Current password is required.", 400)

    if not user.check_password(data["password"]):
        return error_response("Invalid password.", 401)

    if user.otp_enabled:
        return error_response("OTP is already enabled for this account.", 400)

    # Generate a new base32 secret key
    otp_secret = pyotp.random_base32()

    # Store the temporary secret in the session until verified
    # Avoid saving directly to DB until user confirms with a token
    session[get_config_value("SESSION_KEY_OTP_SECRET_TEMP")] = otp_secret
    session.modified = True  # Ensure session is saved

    # Create provisioning URI (otpauth://)
    # Replace 'YourAppName' and user.email/username as appropriate
    provisioning_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(
        name=user.email,
        issuer_name=get_config_value(
            "OTP_ISSUER_NAME", "PasswordManagerApp"
        ),  # Or user.username
    )

    # Generate QR code
    qr_img = qrcode.make(provisioning_uri)
    img_io = io.BytesIO()
    qr_img.save(img_io, "PNG")
    img_io.seek(0)
    qr_code_b64 = base64.b64encode(img_io.getvalue()).decode("utf-8")

    current_app.logger.info(f"Generated OTP setup QR code for user {user.id}")
    return success_response(
        {
            "provisioning_uri": provisioning_uri,
            "qr_code_png_base64": qr_code_b64,
            "message": "Scan the QR code with your authenticator app and verify below.",
        }
    )


@security_bp.route("/otp/verify-enable", methods=["POST"])
@login_required
def otp_verify_enable():
    """Verifies the OTP token provided by the user and enables OTP."""
    user = current_user
    data = request.get_json()
    token = data.get("otp_token")

    if not token:
        return error_response("Missing OTP token.", 400)

    # Retrieve the temporary secret from the session
    otp_secret_temp = session.get(get_config_value("SESSION_KEY_OTP_SECRET_TEMP"))
    if not otp_secret_temp:
        return error_response(
            "OTP setup process not initiated or session expired. Please start setup again.",
            400,
        )

    # Verify the token against the temporary secret
    totp = pyotp.TOTP(otp_secret_temp)
    if totp.verify(token):
        # Verification successful, save the secret to the user model and enable OTP
        user.otp_secret = otp_secret_temp
        user.otp_enabled = True
        db.session.commit()

        # Clear the temporary secret from the session
        session.pop(get_config_value("SESSION_KEY_OTP_SECRET_TEMP"), None)
        session.modified = True

        # Send confirmation email that OTP has been enabled
        try:
            email_html = render_template('email/otp_enabled.html', user=user)
            send_email(user.email, "OTP Authentication Enabled", email_html)
            current_app.logger.info(f"Sent OTP enabled notification to {user.email}")
        except Exception as e:
            current_app.logger.error(f"Failed to send OTP enabled notification: {e}", exc_info=True)
            # Don't fail the operation if email fails

        current_app.logger.info(f"OTP enabled successfully for user {user.id}")
        return success_response({"message": "OTP has been successfully enabled."})
    else:
        current_app.logger.warning(f"OTP verification failed for user {user.id}")
        return error_response("Invalid OTP token.", 401)


@security_bp.route("/otp/disable", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def otp_disable():
    """Disables OTP for the current user."""
    user = current_user
    data = request.get_json()

    # Require password confirmation
    if not data or not data.get("password"):
        return error_response("Current password is required.", 400)

    if not user.check_password(data["password"]):
        return error_response("Invalid password.", 401)

    if not user.otp_enabled:
        return error_response("OTP is not currently enabled for this account.", 400)

    user.otp_secret = None
    user.otp_enabled = False
    db.session.commit()

    # Send confirmation email that OTP has been disabled
    try:
        email_html = render_template('email/otp_disabled.html', user=user)
        send_email(user.email, "OTP Authentication Disabled", email_html)
        current_app.logger.info(f"Sent OTP disabled notification to {user.email}")
    except Exception as e:
        current_app.logger.error(f"Failed to send OTP disabled notification: {e}", exc_info=True)
        # Don't fail the operation if email fails

    current_app.logger.info(f"OTP disabled for user {user.id}")
    return success_response({"message": "OTP has been successfully disabled."})


# Email MFA routes
@security_bp.route("/mfa/email/enable", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def enable_email_mfa():
    """Enables email MFA for the current user."""
    user = current_user
    data = request.get_json()

    # Require password confirmation
    if not data or not data.get("password"):
        return error_response("Current password is required.", 400)

    if not user.check_password(data["password"]):
        return error_response("Invalid password.", 401)

    if user.email_mfa_enabled:
        return error_response("Email MFA is already enabled.", 400)

    # Check if email is verified
    if not user.email_verified:
        return error_response("Email address must be verified before enabling email MFA. Please check your email for a verification link or request a new one.", 400)

    # Send confirmation email that MFA has been enabled
    try:
        email_html = render_template('email/mfa_enabled.html', user=user)
        send_email(user.email, "Email MFA Enabled", email_html)
        current_app.logger.info(f"Sent MFA enabled notification to {user.email}")
    except Exception as e:
        current_app.logger.error(f"Failed to send MFA enabled notification: {e}", exc_info=True)
        # Don't fail the operation if email fails

    user.email_mfa_enabled = True
    db.session.commit()
    current_app.logger.info(f"Email MFA enabled for user {user.id}")
    return success_response({"message": "Email MFA has been enabled successfully."})


@security_bp.route("/mfa/email/disable", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def disable_email_mfa():
    """Initiates the process to disable email MFA by sending a verification code."""
    user = current_user
    data = request.get_json()

    # Require password confirmation
    if not data or not data.get("password"):
        return error_response("Current password is required.", 400)

    if not user.check_password(data["password"]):
        return error_response("Invalid password.", 401)

    if not user.email_mfa_enabled:
        return error_response("Email MFA is not currently enabled.", 400)

    try:
        # Generate verification code
        verification_code = MfaVerificationCode.create_for_user(user.id, 'disable_mfa')
        
        # Send verification code email
        email_html = render_template('email/mfa_disable_code.html', 
                                     user=user, 
                                     verification_code=verification_code.code)
        send_email(user.email, "Verify MFA Disable Request", email_html)
        
        current_app.logger.info(f"Sent MFA disable verification code to {user.email}")
        return success_response({"message": "Verification code sent to your email. Please check your inbox and enter the code to disable MFA."})
        
    except Exception as e:
        current_app.logger.error(f"Failed to send MFA disable verification code: {e}", exc_info=True)
        return error_response("Failed to send verification code. Please try again later.", 500)


@security_bp.route("/mfa/email/disable/verify", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def verify_disable_email_mfa():
    """Verifies the code and disables email MFA."""
    user = current_user
    data = request.get_json()

    if not data or not data.get("verification_code"):
        return error_response("Verification code is required.", 400)

    verification_code = data.get("verification_code")
    
    # Find and validate the verification code
    code_entry = MfaVerificationCode.find_valid_code(user.id, verification_code, 'disable_mfa')
    if not code_entry:
        current_app.logger.warning(f"Invalid MFA disable verification code for user {user.id}")
        return error_response("Invalid or expired verification code.", 400)

    # Disable email MFA
    user.email_mfa_enabled = False
    code_entry.mark_as_used()
    db.session.commit()
    
    current_app.logger.info(f"Email MFA disabled for user {user.id}")
    return success_response({"message": "Email MFA has been disabled successfully."})


@security_bp.route("/mfa/status", methods=["GET"])
@login_required
def get_mfa_status():
    """Get the MFA configuration status for the current user."""
    user = current_user
    return success_response({
        "otp_enabled": user.otp_enabled, 
        "email_mfa_enabled": user.email_mfa_enabled,
        "email_verified": user.email_verified
    })
