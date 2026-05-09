import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(from_email: str, password: str, to_email: str,
               subject: str, content: str, html: str = None):
    """
    Gửi email qua Gmail SMTP.
    - content: nội dung text thuần
    - html: nội dung HTML (tùy chọn, nếu có sẽ gửi kèm)
    """
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = from_email
        msg["To"]      = to_email

        msg.attach(MIMEText(content, "plain", "utf-8"))
        if html:
            msg.attach(MIMEText(html, "html", "utf-8"))

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(from_email, password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"[email] Error sending to {to_email}: {e}")
        return False
