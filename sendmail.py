import os
import smtplib
from email.message import EmailMessage
from jinja2 import Template
from models import MailMessage, Users
from email.utils import formatdate

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
    # 🧠 Get mail template from DB
    template = MailMessage.query.filter_by(template_type=template_type).first()
    if not template:
        raise ValueError(f"No email template found for type '{template_type}'")

    # 🧠 Get user from DB by recipient email
    user = Users.query.filter_by(email=recipient_email).first()
    fullname = user.fullname if user else "User"
    link_url = template.link_url or "#"  # use template's link

    # 🧠 Render body with dynamic values using Jinja2
    rendered_body = Template(template.body).render(fullname=fullname, link_url=link_url, otp=otp)

    # 📩 Compose email
    msg = EmailMessage()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = template.subject
    msg.set_content(rendered_body)

    # 📎 Add attachment
    if attachment_file and attachment_filename:
        file_data = attachment_file.read()
        msg.add_attachment(file_data, maintype='application', subtype='octet-stream', filename=attachment_filename)
    elif attachment_path:
        with open(attachment_path, 'rb') as f:
            file_data = f.read()
            msg.add_attachment(file_data, maintype='application', subtype='octet-stream', filename=attachment_path)

    # 🚀 Send email via Gmail
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(sender_email, app_password)
        smtp.send_message(msg)

    print(f"✅ Email sent to {recipient_email}")
    

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
        "This OTP will expire shortly. Please use it to complete your registration.\n\n"
        "Thank you!"
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
        f"Hello {fullname},\n\n"
        f"Attached is the exported contacts CSV you requested.\n\n"
        f"Best regards,\nYour App Team"
    )

    # Read and attach the CSV file
    with open(csv_filepath, 'rb') as file:
        file_data = file.read()
        file_name = os.path.basename(csv_filepath)
        msg.add_attachment(file_data, maintype='application', subtype='octet-stream', filename=file_name)

    # Send the email
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(sender_email, app_password)
        smtp.send_message(msg)

# ----------------------------------------------------------------
# Consent and grievance notifications
# ----------------------------------------------------------------
from datetime import datetime
from models import Notification, Users, db

def send_notification(user_id, message, type="consent_update", subject=None):
    """Send an in-app + email notification to a user."""
    user = Users.query.get(user_id)
    if not user:
        print(f"⚠️ No user found with ID {user_id}")
        return

    # Save in DB
    notif = Notification(
        user_id=user_id,
        fiduciary_id=None,
        type=type,
        message=message,
        channel="email+in_app",
        status="sent",
        created_at=datetime.utcnow()
    )
    db.session.add(notif)
    db.session.commit()

    # Send email
    sender_email = os.getenv("SENDER_EMAIL")
    app_password = os.getenv("APP_PASSWORD")
    if not sender_email or not app_password:
        print("⚠️ Email credentials not set, skipping email notification.")
        return

    msg = EmailMessage()
    msg["From"] = sender_email
    msg["To"] = user.email
    msg["Subject"] = subject or "Notification from Data Fiduciary Portal"
    msg.set_content(f"Hello {user.fullname},\n\n{message}\n\nBest regards,\nData Fiduciary Team")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender_email, app_password)
            smtp.send_message(msg)
        print(f"✅ Notification sent to {user.email}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")