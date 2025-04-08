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


def send_email(to, subject, template):
    app = current_app._get_current_object()  # Get the actual app instance
    msg = Message(subject, recipients=[to], html=template, sender=app.config["MAIL_DEFAULT_SENDER"])
    # Send email asynchronously in a background thread
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr
