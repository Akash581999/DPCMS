import os
import smtplib
from email.message import EmailMessage
from jinja2 import Template
from datetime import datetime
from email.utils import formatdate
from models import MailMessage, Users, Notification, db

# ----------------------------------------------------------------
# Common Email Sending Helpers
# ----------------------------------------------------------------
def _send_email(recipient_email, subject, body):
    """Internal helper to send a basic email."""
    sender_email = os.getenv("SENDER_EMAIL")
    app_password = os.getenv("APP_PASSWORD")

    if not sender_email or not app_password:
        print("⚠️ Email credentials not set, skipping email sending.")
        return False

    msg = EmailMessage()
    msg["From"] = sender_email
    msg["To"] = recipient_email
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender_email, app_password)
            smtp.send_message(msg)
        print(f"✅ Email sent to {recipient_email}")
        return True
    except Exception as e:
        print(f"❌ Failed to send email to {recipient_email}: {e}")
        return False

# ----------------------------------------------------------------
# Template-Based Email Sending
# ----------------------------------------------------------------
def send_email_with_attachment(
    sender_email,
    app_password,
    recipient_email,
    template_type=None,
    attachment_file=None,
    attachment_filename=None,
    attachment_path=None,
    fullname=None,
    link_url=None,
    otp=None
):
    template = MailMessage.query.filter_by(template_type=template_type).first()
    if not template:
        raise ValueError(f"No email template found for type '{template_type}'")

    user = Users.query.filter_by(email=recipient_email).first()
    fullname = user.fullname if user else "User"
    link_url = template.link_url or "#"

    rendered_body = Template(template.body).render(fullname=fullname, link_url=link_url, otp=otp)

    msg = EmailMessage()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = template.subject
    msg.set_content(rendered_body)

    if attachment_file and attachment_filename:
        file_data = attachment_file.read()
        msg.add_attachment(file_data, maintype='application', subtype='octet-stream', filename=attachment_filename)
    elif attachment_path:
        with open(attachment_path, 'rb') as f:
            file_data = f.read()
            msg.add_attachment(file_data, maintype='application', subtype='octet-stream', filename=os.path.basename(attachment_path))

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(sender_email, app_password)
        smtp.send_message(msg)

    print(f"✅ Email sent to {recipient_email}")

# ----------------------------------------------------------------
# OTP and CSV Helpers
# ----------------------------------------------------------------
def send_email_with_otp(email, otp, fullname="User"):
    sender_email = os.getenv('SENDER_EMAIL')
    app_password = os.getenv('APP_PASSWORD')

    if not sender_email or not app_password:
        raise Exception("Email credentials not set in environment.")

    msg = EmailMessage()
    msg['Subject'] = "Your OTP for Registration"
    msg['From'] = sender_email
    msg['To'] = email

    msg.set_content(
        f"Hello {fullname},\n\n"
        f"Your OTP for registration is: {otp}\n\n"
        "This OTP will expire shortly.\n\nThank you!"
    )

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(sender_email, app_password)
        smtp.send_message(msg)

def send_email_with_contacts_csv(recipient_email, fullname="User", csv_filepath="exported_contacts.csv"):
    sender_email = os.getenv('SENDER_EMAIL')
    app_password = os.getenv('APP_PASSWORD')

    if not sender_email or not app_password:
        raise Exception("Email credentials not set in environment variables.")

    if not os.path.exists(csv_filepath):
        raise FileNotFoundError(f"CSV file not found: {csv_filepath}")

    msg = EmailMessage()
    msg['Subject'] = "Exported Contacts CSV"
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Date'] = formatdate(localtime=True)
    msg.set_content(
        f"Hello {fullname},\n\nAttached is the exported contacts CSV you requested.\n\nBest,\nYour App Team"
    )

    with open(csv_filepath, 'rb') as file:
        msg.add_attachment(file.read(), maintype='application', subtype='octet-stream', filename=os.path.basename(csv_filepath))

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(sender_email, app_password)
        smtp.send_message(msg)

# ----------------------------------------------------------------
# Notification System (In-App + Email)
# ----------------------------------------------------------------
def send_notification(user_id, message, type="consent_update", subject=None):
    """Send both in-app and email notifications (avoiding ENUM conflict)."""
    user = Users.query.get(user_id)
    if not user:
        print(f"⚠️ No user found with ID {user_id}")
        return

    # ✅ 1. Create IN-APP notification entry
    notif = Notification(
        user_id=user_id,
        fiduciary_id=None,
        type=type,
        message=message,
        channel="in_app",   # ✅ valid enum
        status="sent",
        created_at=datetime.utcnow()
    )
    db.session.add(notif)
    db.session.commit()

    # ✅ 2. Send EMAIL notification separately (not stored as 'email+in_app')
    email_sent = _send_email(
        user.email,
        subject or "Notification from Data Fiduciary Portal",
        f"Hello {user.fullname},\n\n{message}\n\nBest regards,\nData Fiduciary Team"
    )

    if email_sent:
        print(f"✅ In-app + Email notification sent to {user.email}")
    else:
        print(f"⚠️ Only in-app notification saved (email failed for {user.email})")