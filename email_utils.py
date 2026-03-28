import smtplib
from email.mime.text import MIMEText

def send_email(from_email, password, to_email, subject, content):
    msg = MIMEText(content)
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(from_email, password)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print("Email error:", e)
        