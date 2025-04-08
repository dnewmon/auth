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
from ..models import db, User
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
        name=user.email, issuer_name=get_config_value("OTP_ISSUER_NAME", "PasswordManagerApp")  # Or user.username
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
        return error_response("OTP setup process not initiated or session expired. Please start setup again.", 400)

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

    current_app.logger.info(f"OTP disabled for user {user.id}")
    return success_response({"message": "OTP has been successfully disabled."})


# Placeholder for Email MFA routes
@security_bp.route("/mfa/email/enable", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def enable_email_mfa():
    """Enables email notifications for login for the current user."""
    user = current_user
    data = request.get_json()

    # Require password confirmation
    if not data or not data.get("password"):
        return error_response("Current password is required.", 400)

    if not user.check_password(data["password"]):
        return error_response("Invalid password.", 401)

    if user.email_mfa_enabled:
        return error_response("Email MFA notification is already enabled.", 400)

    # Send a test email to verify the email is working
    try:
        template_path = get_config_value("EMAIL_MFA_TEST_TEMPLATE")
        email_html = render_template(template_path, user=user)
        send_email(user.email, "Email MFA Test", email_html)
    except Exception as e:
        current_app.logger.error(f"Failed to send test email for MFA setup: {e}", exc_info=True)
        return error_response("Failed to send test email. Please verify your email settings.", 500)

    user.email_mfa_enabled = True
    db.session.commit()
    current_app.logger.info(f"Email MFA notification enabled for user {user.id}")
    return success_response({"message": "Email MFA notification has been enabled."})


@security_bp.route("/mfa/email/disable", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def disable_email_mfa():
    """Disables email notifications for login for the current user."""
    user = current_user
    data = request.get_json()

    # Require password confirmation
    if not data or not data.get("password"):
        return error_response("Current password is required.", 400)

    if not user.check_password(data["password"]):
        return error_response("Invalid password.", 401)

    if not user.email_mfa_enabled:
        return error_response("Email MFA notification is not currently enabled.", 400)

    user.email_mfa_enabled = False
    db.session.commit()
    current_app.logger.info(f"Email MFA notification disabled for user {user.id}")
    return success_response({"message": "Email MFA notification has been disabled."})


@security_bp.route("/mfa/status", methods=["GET"])
@login_required
def get_mfa_status():
    """Get the MFA configuration status for the current user."""
    user = current_user
    return success_response({"otp_enabled": user.otp_enabled, "email_mfa_enabled": user.email_mfa_enabled})
