from django.core.mail import send_mail
from django.conf import settings


def send_verification_email(email, verification_url):
    subject = "Verify your Authx account"
    message = f"Click the link below to verify your email:\n\n{verification_url}\n\nIf you did not create this account, ignore this email."
    
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False
    )