import time
from database import SessionLocal
from models import Invoice, User
from security import decrypt
from email_utils import send_email

def run_worker():
    while True:
        db = SessionLocal()

        invoices = db.query(Invoice).filter(Invoice.status == "pending").all()

        for inv in invoices:
            user = db.query(User).filter(User.id == inv.user_id).first()

            if not user or not user.smtp_email or not user.smtp_password:
                continue  # bỏ qua invoice lỗi

            smtp_pass = decrypt(user.smtp_password)

            send_email(
                user.smtp_email,
                smtp_pass,
                inv.customer_email,
                "Invoice",
                f"You owe {inv.total}"
            )

            inv.status = "sent"

        db.commit()
        db.close()

        time.sleep(10)