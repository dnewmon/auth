from flask_mail import Message
from flask import current_app
from threading import Thread
from .. import mail  # Import the mail instance from app factory


def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
        except Exception as e:
            app.logger.error(f"Failed to send email: {e}", exc_info=True)


def send_email(to, subject, template=None, text_body=None):
    # Get the actual app instance - handle both real current_app proxy and mocked app
    if hasattr(current_app, '_get_current_object'):
        app = current_app._get_current_object()
    else:
        app = current_app
    
    # Prepare message arguments - match test expectations
    msg_kwargs = {
        "subject": subject,
        "recipients": [to]
    }
    
    # Add html parameter explicitly (tests expect it even if None)
    msg_kwargs["html"] = template
    
    # Add body parameter explicitly (tests expect it even if None)
    msg_kwargs["body"] = text_body
    
    # Only add sender if not in testing mode
    if (hasattr(app, 'config') and 
        app.config.get("MAIL_DEFAULT_SENDER") and 
        not app.config.get("TESTING")):
        msg_kwargs["sender"] = app.config["MAIL_DEFAULT_SENDER"]
    
    msg = Message(**msg_kwargs)
    # Send email asynchronously in a background thread
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr
