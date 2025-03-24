import smtplib
import random
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Temporary in-memory store for OTPs (for local testing)
otp_store = {}

def generate_otp():
    """Generate a 6-digit OTP."""
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp):
    """Send OTP to user's email."""
    sender_email = os.getenv("EMAIL_ADDRESS")
    sender_password = os.getenv("EMAIL_PASSWORD")

    message = MIMEMultipart("alternative")
    message["Subject"] = "Your OTP Verification Code"
    message["From"] = sender_email
    message["To"] = email

    # Email content
    text = f"Your OTP verification code is: {otp}"
    message.attach(MIMEText(text, "plain"))

    # Sending the email
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, message.as_string())
        return True
    except Exception as e:
        print(f"Failed to send OTP: {e}")
        return False
