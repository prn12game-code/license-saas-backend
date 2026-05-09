"""
worker.py — LicenseHub Reminder Scheduler
Chạy song song với server. Mỗi giờ kiểm tra hóa đơn quá hạn và gửi nhắc.

Luồng nhắc:
  1. Hóa đơn quá due_date → gửi nhắc lần 1
  2. Mỗi remind_every_days ngày tiếp theo → gửi nhắc tiếp
  3. Dừng khi reminder_count >= max_reminders HOẶC status == "paid"
"""

import time
from datetime import datetime, timezone
from database import SessionLocal
from models import Invoice, User
from security import decrypt
from email_utils import send_email


def build_reminder_email(invoice: Invoice, user: User, reminder_num: int) -> tuple[str, str]:
    """Tạo subject và nội dung email nhắc."""
    template = user.email_template or (
        "Xin chào {CUSTOMER},\n\n"
        "Đây là lần nhắc thứ {NUM}: Hóa đơn #{INVOICE_ID} trị giá "
        "{AMOUNT} {CURRENCY} đã quá hạn thanh toán.\n\n"
        "Vui lòng thanh toán sớm để tránh phát sinh thêm vấn đề.\n\n"
        "Trân trọng."
    )

    content = template.replace("{CUSTOMER}", invoice.customer_name or "")
    content = content.replace("{EMAIL}", invoice.customer_email or "")
    content = content.replace("{AMOUNT}", str(invoice.total))
    content = content.replace("{CURRENCY}", invoice.currency or "USD")
    content = content.replace("{INVOICE_ID}", str(invoice.id))
    content = content.replace("{DUE_DATE}", invoice.due_date or "")
    content = content.replace("{NUM}", str(reminder_num))

    subject = f"[Nhắc lần {reminder_num}] Hóa đơn #{invoice.id} — {invoice.total} {invoice.currency}"
    return subject, content


def run_worker():
    print("[worker] Reminder scheduler started")
    while True:
        try:
            db = SessionLocal()
            now = datetime.now(timezone.utc).replace(tzinfo=None)

            # Lấy tất cả hóa đơn pending có due_date và remind_every_days > 0
            invoices = (
                db.query(Invoice)
                .filter(
                    Invoice.status == "pending",
                    Invoice.due_date != None,
                    Invoice.remind_every_days > 0,
                )
                .all()
            )

            for inv in invoices:
                try:
                    # Lấy max_reminders từ user settings
                    user = db.query(User).filter(User.id == inv.user_id).first()
                    if not user:
                        continue

                    max_r = user.max_reminders or 5

                    # Đã nhắc đủ số lần → bỏ qua
                    if inv.reminder_count >= max_r:
                        continue

                    # Kiểm tra due_date
                    due = datetime.fromisoformat(inv.due_date)
                    if now < due:
                        continue  # Chưa đến hạn

                    # Xác định có nên nhắc không
                    should_remind = False
                    if inv.last_reminded_at is None:
                        should_remind = True  # Lần nhắc đầu tiên
                    else:
                        days_since = (now - inv.last_reminded_at).days
                        if days_since >= inv.remind_every_days:
                            should_remind = True

                    if not should_remind:
                        continue

                    # Gửi email nhắc
                    if not user.smtp_email or not user.smtp_password:
                        continue

                    smtp_pass = decrypt(user.smtp_password)
                    reminder_num = inv.reminder_count + 1
                    subject, content = build_reminder_email(inv, user, reminder_num)

                    send_email(
                        user.smtp_email, smtp_pass,
                        inv.customer_email, subject, content
                    )

                    inv.last_reminded_at = now
                    inv.reminder_count = reminder_num
                    print(f"[worker] Nhắc #{inv.id} → {inv.customer_email} (lần {reminder_num}/{max_r})")

                except Exception as e:
                    print(f"[worker] Lỗi hóa đơn #{inv.id}: {e}")

            db.commit()
            db.close()

        except Exception as e:
            print(f"[worker] Lỗi vòng lặp: {e}")

        time.sleep(3600)  # Kiểm tra mỗi 1 giờ


if __name__ == "__main__":
    run_worker()
