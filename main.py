import os, secrets as _secrets
from datetime import datetime, timedelta
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Header, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Optional

load_dotenv()
ADMIN_EMAIL    = os.getenv("ADMIN_EMAIL")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

from database import SessionLocal, engine
from models import Base, User, Invoice, License, TokenPackage, TokenTransaction
from security import (hash_password, verify_password, encrypt, decrypt,
                      verify_admin_secret, check_rate_limit, check_password_strength)
from auth import create_token, verify_token, generate_token
from email_utils import send_email
from license_utils import generate_code
import webhook_utils
import token_utils

Base.metadata.create_all(bind=engine)

app = FastAPI(title="LicenseHub API", version="2.1", docs_url="/api/docs", redoc_url=None)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# ── Dependencies ──────────────────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(authorization: str = Header(default=None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    try:
        payload = verify_token(authorization.split(" ")[1])
        user = db.query(User).filter(User.email == payload.get("email")).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def require_admin(admin_secret: str):
    if not verify_admin_secret(admin_secret):
        raise HTTPException(status_code=403, detail="Unauthorized")


# ── Pages ─────────────────────────────────────────────────

@app.get("/",               response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "index.html")

@app.get("/login",          response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html")

@app.get("/register",       response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html")

@app.get("/dashboard",      response_class=HTMLResponse)
def dashboard_page(request: Request):
    return templates.TemplateResponse(request, "dashboard.html")

@app.get("/forgot-password",response_class=HTMLResponse)
def forgot_page(request: Request):
    return templates.TemplateResponse(request, "forgot_password.html")

@app.get("/reset-password", response_class=HTMLResponse)
def reset_page(request: Request, token: str = ""):
    return templates.TemplateResponse(request, "reset_password.html", {"token": token})


# ── Auth ──────────────────────────────────────────────────

@app.post("/api/register")
def register(request: Request, email: str = Form(...), password: str = Form(...),
             db: Session = Depends(get_db)):
    ip = request.client.host
    if not check_rate_limit(ip):
        raise HTTPException(429, "Too many attempts — please wait a minute")
    strong, msg = check_password_strength(password)
    if not strong:
        raise HTTPException(400, msg)
    if db.query(User).filter(User.email == email.lower().strip()).first():
        raise HTTPException(409, "Email already registered")
    token = generate_token()
    user = User(email=email.lower().strip(), password=hash_password(password),
                verify_token=token, is_verified="no", token_balance=0,
                default_currency="USD", language="en", max_reminders=5)
    db.add(user); db.commit()
    link = f"http://127.0.0.1:8000/api/verify?token={token}"
    send_email(ADMIN_EMAIL, EMAIL_PASSWORD, email, "Verify your LicenseHub account",
               f"Welcome!\n\nClick to verify:\n{link}")
    return {"msg": "Check your email to verify your account"}


@app.get("/api/verify")
def verify_email(token: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.verify_token == token).first()
    if not user:
        raise HTTPException(400, "Invalid or expired token")
    user.is_verified = "yes"; user.verify_token = None
    db.commit()
    return RedirectResponse(url="/login?verified=1")


@app.post("/api/login")
def login(request: Request, email: str = Form(...), password: str = Form(...),
          db: Session = Depends(get_db)):
    if not check_rate_limit(f"login:{request.client.host}"):
        raise HTTPException(429, "Too many login attempts")
    user = db.query(User).filter(User.email == email.lower().strip()).first()
    if not user or not verify_password(password, user.password):
        raise HTTPException(401, "Invalid email or password")
    if user.is_verified != "yes":
        raise HTTPException(403, "Please verify your email first")
    return {"token": create_token({"email": user.email}), "email": user.email}


@app.post("/api/forgot-password")
def forgot_password(email: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email.lower().strip()).first()
    if user:
        token = generate_token(); user.reset_token = token; db.commit()
        link = f"http://127.0.0.1:8000/reset-password?token={token}"
        send_email(ADMIN_EMAIL, EMAIL_PASSWORD, email, "Reset your password",
                   f"Click to reset:\n{link}")
    return {"msg": "If that email exists, a reset link has been sent"}


@app.post("/api/reset-password")
def reset_password(token: str = Form(...), new_password: str = Form(...),
                   db: Session = Depends(get_db)):
    strong, msg = check_password_strength(new_password)
    if not strong:
        raise HTTPException(400, msg)
    user = db.query(User).filter(User.reset_token == token).first()
    if not user:
        raise HTTPException(400, "Invalid or expired reset token")
    user.password = hash_password(new_password); user.reset_token = None
    db.commit()
    return {"msg": "Password reset successfully"}


@app.post("/api/change-password")
def change_password(old_password: str = Form(...), new_password: str = Form(...),
                    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not verify_password(old_password, current_user.password):
        raise HTTPException(400, "Current password is incorrect")
    strong, msg = check_password_strength(new_password)
    if not strong:
        raise HTTPException(400, msg)
    current_user.password = hash_password(new_password); db.commit()
    return {"msg": "Password changed successfully"}


# ── User settings ─────────────────────────────────────────

@app.get("/api/settings")
def get_settings(current_user: User = Depends(get_current_user)):
    return {
        "default_currency": current_user.default_currency or "USD",
        "language": current_user.language or "en",
        "max_reminders": current_user.max_reminders or 5,
        "email_template": current_user.email_template or "",
    }


@app.post("/api/settings")
def save_settings(
    default_currency: Optional[str] = Form(None),
    language: Optional[str] = Form(None),
    max_reminders: Optional[int] = Form(None),
    email_template: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if default_currency: current_user.default_currency = default_currency
    if language:         current_user.language = language
    if max_reminders is not None: current_user.max_reminders = max_reminders
    if email_template is not None: current_user.email_template = email_template
    db.add(current_user); db.commit()
    return {"msg": "Settings saved"}


# ── SMTP ──────────────────────────────────────────────────

@app.post("/api/smtp")
def save_smtp(email: str, password: str, db: Session = Depends(get_db),
              current_user: User = Depends(get_current_user)):
    current_user.smtp_email = email
    current_user.smtp_password = encrypt(password)
    db.add(current_user); db.commit()
    return {"msg": "SMTP settings saved"}


# ── Invoices ──────────────────────────────────────────────

@app.post("/api/invoice")
def create_invoice(
    customer_name:     str           = Form(...),
    customer_email:    str           = Form(...),
    total:             float         = Form(...),
    currency:          str           = Form(default="USD"),
    notes:             Optional[str] = Form(None),
    due_date:          Optional[str] = Form(None),
    remind_every_days: Optional[int] = Form(0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if total <= 0:
        raise HTTPException(400, "Total must be greater than 0")
    if not current_user.smtp_email or not current_user.smtp_password:
        raise HTTPException(400, "Please configure SMTP settings first")

    # ── Kiểm tra giới hạn hóa đơn theo ngày ──
    plan      = current_user.plan or "free"
    limits    = PLANS.get(plan, PLANS["free"])
    max_daily = limits["max_invoices_per_day"]

    if max_daily != -1:
        from sqlalchemy import func as sqlfunc
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        count_today = db.query(Invoice).filter(
            Invoice.user_id   == current_user.id,
            Invoice.created_at >= today_start,
        ).count()

        if count_today >= max_daily:
            raise HTTPException(
                status_code=429,
                detail=(
                    f"Bạn đã dùng hết {max_daily} hóa đơn hôm nay (gói {limits['label']}). "
                    f"Nâng cấp gói để tạo thêm, hoặc quay lại vào ngày mai."
                )
            )

    invoice = Invoice(
        customer_name=customer_name.strip(),
        customer_email=customer_email.lower().strip(),
        total=total, currency=currency,
        notes=notes, due_date=due_date,
        remind_every_days=remind_every_days or 0,
        user_id=current_user.id
    )
    db.add(invoice); db.commit(); db.refresh(invoice)

    smtp_pass = decrypt(current_user.smtp_password)
    template  = current_user.email_template or (
        "Xin chào {CUSTOMER},\n\n"
        "Bạn có hóa đơn #{INVOICE_ID} trị giá {AMOUNT} {CURRENCY}.\n"
        "{DUE_LINE}"
        "{NOTES_LINE}"
        "\nVui lòng thanh toán đúng hạn.\n\nTrân trọng."
    )
    due_line   = f"Hạn thanh toán: {due_date}\n" if due_date else ""
    notes_line = f"Ghi chú: {notes}\n" if notes else ""

    content = template.replace("{CUSTOMER}", customer_name)
    content = content.replace("{EMAIL}", customer_email)
    content = content.replace("{AMOUNT}", str(total))
    content = content.replace("{CURRENCY}", currency)
    content = content.replace("{INVOICE_ID}", str(invoice.id))
    content = content.replace("{DUE_DATE}", due_date or "")
    content = content.replace("{DUE_LINE}", due_line)
    content = content.replace("{NOTES_LINE}", notes_line)

    send_email(current_user.smtp_email, smtp_pass, customer_email,
               f"Hóa đơn #{invoice.id} — {total} {currency}", content)

    # Trả về cả số hóa đơn còn lại hôm nay
    used_today = count_today + 1 if max_daily != -1 else 0
    remaining  = (max_daily - used_today) if max_daily != -1 else -1

    return {
        "msg": "Invoice created",
        "invoice_id": invoice.id,
        "daily_remaining": remaining,
        "daily_limit": max_daily,
    }


@app.get("/api/invoices")
def list_invoices(status: Optional[str] = None, db: Session = Depends(get_db),
                  current_user: User = Depends(get_current_user)):
    q = db.query(Invoice).filter(Invoice.user_id == current_user.id)
    if status in ("pending", "paid"):
        q = q.filter(Invoice.status == status)
    invoices = q.order_by(Invoice.created_at.desc()).all()
    return [_inv_dict(i) for i in invoices]


@app.get("/api/invoice/{invoice_id}")
def get_invoice(invoice_id: int, db: Session = Depends(get_db),
                current_user: User = Depends(get_current_user)):
    inv = db.query(Invoice).filter(
        Invoice.id == invoice_id, Invoice.user_id == current_user.id
    ).first()
    if not inv:
        raise HTTPException(404, "Invoice not found")
    return _inv_dict(inv)


def _inv_dict(i: Invoice) -> dict:
    return {
        "id": i.id,
        "customer_name": i.customer_name,
        "customer_email": i.customer_email,
        "total": i.total,
        "currency": i.currency,
        "status": i.status,
        "notes": i.notes,
        "due_date": i.due_date,
        "remind_every_days": i.remind_every_days,
        "reminder_count": i.reminder_count,
        "last_reminded_at": str(i.last_reminded_at) if i.last_reminded_at else None,
        "created_at": str(i.created_at) if i.created_at else None,
    }


@app.post("/api/invoice/{invoice_id}/paid")
def mark_paid(invoice_id: int, db: Session = Depends(get_db),
              current_user: User = Depends(get_current_user)):
    inv = db.query(Invoice).filter(
        Invoice.id == invoice_id, Invoice.user_id == current_user.id
    ).first()
    if not inv:
        raise HTTPException(404, "Invoice not found")
    if inv.status == "paid":
        raise HTTPException(400, "Already paid")
    inv.status = "paid"; db.commit()
    if current_user.smtp_email and current_user.smtp_password:
        smtp_pass = decrypt(current_user.smtp_password)
        send_email(current_user.smtp_email, smtp_pass, inv.customer_email,
                   "Xác nhận thanh toán",
                   f"Xin chào {inv.customer_name},\n\nChúng tôi đã nhận thanh toán {inv.total} {inv.currency}. Cảm ơn bạn!")
    if current_user.webhook_url:
        webhook_utils.fire("invoice.paid", inv, current_user.webhook_url, current_user.webhook_secret)
    return {"msg": "Invoice marked as paid"}


# ── Licenses ──────────────────────────────────────────────

@app.get("/api/check-license")
def check_license(code: str, device_id: str, db: Session = Depends(get_db)):
    lic = db.query(License).filter(License.code == code).first()
    if not lic or lic.is_used == "revoked": return {"valid": False}
    if lic.is_used == "no": return {"valid": False, "reason": "Not activated"}
    if lic.device_id and lic.device_id != device_id: return {"valid": False, "reason": "Device mismatch"}
    return {"valid": True}


@app.post("/api/activate")
def activate(code: str = Form(...), device_id: str = Form(...),
             db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    lic = db.query(License).filter(License.code == code).first()
    if not lic: raise HTTPException(404, "License not found")
    if lic.is_used == "revoked": raise HTTPException(400, "License revoked")
    if lic.is_used == "yes" and lic.device_id != device_id:
        raise HTTPException(400, "License already used on another device")
    lic.device_id = device_id; lic.is_used = "yes"
    current_user.license_expiry = ("permanent" if lic.duration_days == -1
                                   else str(datetime.utcnow() + timedelta(days=lic.duration_days)))
    db.commit()
    return {"msg": "License activated", "expiry": current_user.license_expiry}


@app.get("/api/my-license")
def my_license(current_user: User = Depends(get_current_user)):
    return {"license_expiry": current_user.license_expiry}


# ── Webhooks ──────────────────────────────────────────────

@app.post("/api/webhook")
def save_webhook(url: str, db: Session = Depends(get_db),
                 current_user: User = Depends(get_current_user)):
    if not url.startswith(("http://", "https://")):
        raise HTTPException(400, "URL must start with http:// or https://")
    current_user.webhook_url = url.strip()
    if not current_user.webhook_secret:
        current_user.webhook_secret = _secrets.token_hex(32)
    db.add(current_user); db.commit()
    return {"msg": "Webhook saved", "url": current_user.webhook_url,
            "secret": current_user.webhook_secret}


@app.get("/api/webhook")
def get_webhook(current_user: User = Depends(get_current_user)):
    return {"url": current_user.webhook_url, "secret": current_user.webhook_secret,
            "configured": bool(current_user.webhook_url)}


@app.delete("/api/webhook")
def delete_webhook(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    current_user.webhook_url = None; current_user.webhook_secret = None
    db.add(current_user); db.commit()
    return {"msg": "Webhook removed"}


@app.post("/api/webhook/test")
def test_webhook(current_user: User = Depends(get_current_user)):
    if not current_user.webhook_url:
        raise HTTPException(400, "No webhook configured")
    class _F:
        id=0; customer_name="Test"; customer_email="test@example.com"
        total=0.0; currency="USD"; status="paid"
    webhook_utils.fire("webhook.test", _F(), current_user.webhook_url, current_user.webhook_secret)
    return {"msg": "Test webhook fired"}


# ── Tokens ────────────────────────────────────────────────

@app.get("/api/tokens/balance")
def token_balance(current_user: User = Depends(get_current_user)):
    return {"balance": token_utils.get_balance(current_user)}

@app.get("/api/tokens/packages")
def list_packages(db: Session = Depends(get_db)):
    pkgs = token_utils.get_active_packages(db)
    return [{"id": p.id, "name": p.name, "description": p.description,
             "tokens": p.tokens, "price": p.price, "currency": p.currency} for p in pkgs]

@app.get("/api/tokens/history")
def token_history(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    txs = token_utils.get_history(db, current_user.id)
    return [{"delta": t.delta, "reason": t.reason, "balance_after": t.balance_after,
             "created_at": str(t.created_at)} for t in txs]


# ── Admin ─────────────────────────────────────────────────

@app.post("/api/admin/generate-license")
def gen_license(days: int, admin_secret: str, db: Session = Depends(get_db)):
    require_admin(admin_secret)
    code = generate_code(16)
    db.add(License(code=code, duration_days=days, is_used="no")); db.commit()
    return {"code": code, "duration_days": days}

@app.post("/api/admin/revoke")
def revoke(code: str, admin_secret: str, db: Session = Depends(get_db)):
    require_admin(admin_secret)
    lic = db.query(License).filter(License.code == code).first()
    if not lic: raise HTTPException(404, "Not found")
    lic.is_used = "revoked"; db.commit()
    return {"msg": "Revoked"}

@app.get("/api/admin/licenses")
def all_licenses(admin_secret: str, db: Session = Depends(get_db)):
    require_admin(admin_secret)
    return [{"id": l.id, "code": l.code, "duration_days": l.duration_days,
             "is_used": l.is_used, "device_id": l.device_id}
            for l in db.query(License).all()]

@app.get("/api/admin/users")
def get_users(admin_secret: str, db: Session = Depends(get_db)):
    require_admin(admin_secret)
    return [{"id": u.id, "email": u.email, "is_verified": u.is_verified,
             "license_expiry": u.license_expiry, "token_balance": u.token_balance}
            for u in db.query(User).all()]

@app.get("/api/admin/invoices")
def get_all_invoices(admin_secret: str, db: Session = Depends(get_db)):
    require_admin(admin_secret)
    return [_inv_dict(i) for i in db.query(Invoice).order_by(Invoice.created_at.desc()).all()]

@app.post("/api/admin/grant-tokens")
def grant_tokens(user_email: str, amount: int, reason: str, admin_secret: str,
                 db: Session = Depends(get_db)):
    require_admin(admin_secret)
    user = db.query(User).filter(User.email == user_email.lower().strip()).first()
    if not user: raise HTTPException(404, "User not found")
    new_bal = token_utils.grant_tokens(db, user, amount, reason)
    return {"msg": f"Granted {amount} tokens", "new_balance": new_bal}

@app.post("/api/admin/token-packages")
def create_package(name: str, description: str, tokens: int, price: float,
                   currency: str = "USD", admin_secret: str = "",
                   db: Session = Depends(get_db)):
    require_admin(admin_secret)
    pkg = TokenPackage(name=name, description=description, tokens=tokens,
                       price=price, currency=currency, is_active=True)
    db.add(pkg); db.commit(); db.refresh(pkg)
    return {"msg": "Package created", "id": pkg.id}


# ── Plan / Subscription ───────────────────────────────────
from models import PLANS
from datetime import date

@app.get("/api/my-plan")
def my_plan(current_user: User = Depends(get_current_user)):
    plan = current_user.plan or "free"
    limits = PLANS.get(plan, PLANS["free"])
    expired = False
    if current_user.plan_expires_at and current_user.plan_expires_at != "lifetime":
        expired = date.today().isoformat() > current_user.plan_expires_at
    return {
        "plan": plan,
        "label": limits["label"],
        "expires_at": current_user.plan_expires_at,
        "expired": expired,
        "limits": limits,
        "note": current_user.plan_note,
    }


@app.post("/api/admin/upgrade-user")
def upgrade_user(
    user_email:   str,
    plan:         str,
    admin_secret: str,
    days:         int  = -1,   # -1 = lifetime, N = số ngày
    note:         str  = "",
    db: Session = Depends(get_db)
):
    """
    Nâng cấp tài khoản user lên plan mới.
    Ví dụ:
      POST /api/admin/upgrade-user?user_email=abc@gmail.com&plan=pro&days=365&admin_secret=xxx
    """
    require_admin(admin_secret)
    if plan not in PLANS:
        raise HTTPException(400, f"Plan không hợp lệ. Chọn: {list(PLANS.keys())}")

    user = db.query(User).filter(User.email == user_email.lower().strip()).first()
    if not user:
        raise HTTPException(404, "User not found")

    old_plan = user.plan
    user.plan = plan
    user.plan_note = note or f"Upgraded by admin on {date.today()}"

    if days == -1:
        user.plan_expires_at = "lifetime"
    else:
        from datetime import timedelta
        exp = date.today() + timedelta(days=days)
        user.plan_expires_at = exp.isoformat()

    # Tặng token bonus nếu có
    bonus = PLANS[plan].get("token_bonus", 0)
    if bonus > 0:
        user.token_balance = (user.token_balance or 0) + bonus

    db.commit()
    return {
        "msg": f"Upgraded {user_email} từ {old_plan} → {plan}",
        "expires_at": user.plan_expires_at,
        "token_bonus": bonus,
    }


@app.post("/api/admin/downgrade-user")
def downgrade_user(
    user_email:   str,
    admin_secret: str,
    db: Session = Depends(get_db)
):
    """Hạ cấp user về Free."""
    require_admin(admin_secret)
    user = db.query(User).filter(User.email == user_email.lower().strip()).first()
    if not user:
        raise HTTPException(404, "User not found")
    old = user.plan
    user.plan = "free"; user.plan_expires_at = None; user.plan_note = "Downgraded by admin"
    db.commit()
    return {"msg": f"Downgraded {user_email} từ {old} → free"}


@app.get("/api/admin/plans")
def list_plans(admin_secret: str):
    """Xem tất cả gói và giới hạn."""
    require_admin(admin_secret)
    return PLANS


# ── Subscription management ───────────────────────────────
from models import PLANS, REFERRAL_BONUS_DAYS
from datetime import date, timedelta as tdelta
import random, string

def _gen_referral_code(email: str) -> str:
    """Tạo mã giới thiệu duy nhất từ email + random."""
    prefix = email.split("@")[0][:4].upper()
    suffix = ''.join(random.choices(string.digits + string.ascii_uppercase, k=4))
    return f"{prefix}-{suffix}"

@app.get("/api/my-plan")
def my_plan(current_user: User = Depends(get_current_user)):
    plan  = current_user.plan or "free"
    info  = PLANS.get(plan, PLANS["free"])
    today = date.today().isoformat()
    expired = False
    if current_user.plan_expires_at and current_user.plan_expires_at != "lifetime":
        expired = today > current_user.plan_expires_at
    return {
        "plan":         plan,
        "label":        info["label"],
        "plan_type":    current_user.plan_type,
        "expires_at":   current_user.plan_expires_at,
        "auto_renew":   current_user.auto_renew,
        "expired":      expired,
        "trial_used":   current_user.trial_used,
        "limits":       info,
        "referral_code":current_user.referral_code,
        "referral_count":current_user.referral_count or 0,
    }


@app.post("/api/cancel-subscription")
def cancel_subscription(db: Session = Depends(get_db),
                         current_user: User = Depends(get_current_user)):
    """
    Hủy gia hạn — KHÔNG xóa plan, vẫn dùng được đến hết kỳ.
    Sau khi hết hạn, tự động về Free.
    """
    if current_user.plan == "free":
        raise HTTPException(400, "Bạn đang dùng gói Free, không có gì để hủy.")
    current_user.auto_renew = False
    db.commit()
    return {
        "msg": f"Đã hủy gia hạn. Bạn vẫn dùng gói {current_user.plan.upper()} đến {current_user.plan_expires_at}.",
        "expires_at": current_user.plan_expires_at,
    }


@app.post("/api/reactivate-subscription")
def reactivate_subscription(db: Session = Depends(get_db),
                              current_user: User = Depends(get_current_user)):
    """Bật lại gia hạn tự động."""
    current_user.auto_renew = True
    db.commit()
    return {"msg": "Đã bật lại gia hạn tự động."}


@app.post("/api/start-trial")
def start_trial(db: Session = Depends(get_db),
                current_user: User = Depends(get_current_user)):
    """Dùng thử Pro 7 ngày — mỗi account chỉ 1 lần."""
    if current_user.trial_used:
        raise HTTPException(400, "Bạn đã dùng free trial rồi.")
    if current_user.plan != "free":
        raise HTTPException(400, "Trial chỉ dành cho tài khoản Free.")
    exp = (date.today() + tdelta(days=7)).isoformat()
    current_user.plan = "pro"
    current_user.plan_type = "trial"
    current_user.plan_expires_at = exp
    current_user.plan_start_at = date.today().isoformat()
    current_user.auto_renew = False
    current_user.trial_used = True
    db.commit()
    return {"msg": f"Đã kích hoạt Pro Trial 7 ngày! Hết hạn: {exp}"}


# ── Admin — nâng / hạ plan ────────────────────────────────

@app.post("/api/admin/upgrade-user")
def upgrade_user(
    user_email:   str,
    plan:         str,
    plan_type:    str  = "monthly",   # monthly | annual | lifetime
    admin_secret: str  = "",
    note:         str  = "",
    db: Session = Depends(get_db)
):
    """
    Nâng cấp sau khi nhận tiền (chuyển khoản / ZaloPay / Wise).

    Ví dụ gọi sau khi user chuyển khoản gói Pro Annual:
      POST /api/admin/upgrade-user?user_email=abc@gmail.com&plan=pro&plan_type=annual&admin_secret=xxx
    """
    require_admin(admin_secret)
    if plan not in PLANS:
        raise HTTPException(400, f"Plan không hợp lệ. Chọn: {list(PLANS.keys())}")

    user = db.query(User).filter(User.email == user_email.lower().strip()).first()
    if not user: raise HTTPException(404, "User not found")

    old_plan = user.plan
    user.plan = plan
    user.plan_type = plan_type
    user.auto_renew = True
    user.plan_start_at = date.today().isoformat()
    user.plan_note = note or f"Upgraded {plan_type} by admin on {date.today()}"

    if plan_type == "lifetime":
        user.plan_expires_at = "lifetime"
    elif plan_type == "annual":
        user.plan_expires_at = (date.today() + tdelta(days=365)).isoformat()
    elif plan_type == "monthly":
        user.plan_expires_at = (date.today() + tdelta(days=30)).isoformat()

    # Tặng token bonus
    bonus = PLANS[plan].get("token_bonus", 0)
    if bonus > 0:
        user.token_balance = (user.token_balance or 0) + bonus

    # Tạo referral code nếu chưa có
    if not user.referral_code:
        user.referral_code = _gen_referral_code(user.email)

    db.commit()
    return {
        "msg": f"✅ Upgraded {user_email}: {old_plan} → {plan} ({plan_type})",
        "expires_at": user.plan_expires_at,
        "token_bonus": bonus,
    }


@app.post("/api/admin/downgrade-user")
def downgrade_user(user_email: str, admin_secret: str, db: Session = Depends(get_db)):
    require_admin(admin_secret)
    user = db.query(User).filter(User.email == user_email.lower().strip()).first()
    if not user: raise HTTPException(404, "User not found")
    old = user.plan
    user.plan = "free"; user.plan_type = None
    user.plan_expires_at = None; user.auto_renew = True
    db.commit()
    return {"msg": f"Downgraded {user_email}: {old} → free"}


@app.get("/api/admin/plans")
def list_plans(admin_secret: str):
    require_admin(admin_secret)
    return PLANS


# ── Referral system ───────────────────────────────────────

@app.get("/api/referral/my-code")
def get_my_referral(db: Session = Depends(get_db),
                    current_user: User = Depends(get_current_user)):
    """Lấy mã giới thiệu của user. Tạo nếu chưa có."""
    if not current_user.referral_code:
        current_user.referral_code = _gen_referral_code(current_user.email)
        db.commit()
    return {
        "code":           current_user.referral_code,
        "referral_count": current_user.referral_count or 0,
        "reward_per_ref": "14 ngày Pro Trial cho cả 2",
    }


@app.post("/api/referral/validate")
def validate_referral(code: str, db: Session = Depends(get_db)):
    """Kiểm tra mã giới thiệu có hợp lệ không."""
    referrer = db.query(User).filter(User.referral_code == code.upper().strip()).first()
    if not referrer:
        raise HTTPException(404, "Mã giới thiệu không hợp lệ.")
    return {"valid": True, "referrer_email": referrer.email[:3] + "***"}


# API register bổ sung referral_code
@app.post("/api/register-with-referral")
def register_with_referral(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    referral_code: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """Đăng ký có thể kèm mã giới thiệu (không bắt buộc)."""
    ip = request.client.host
    if not check_rate_limit(ip):
        raise HTTPException(429, "Too many attempts")
    strong, msg = check_password_strength(password)
    if not strong: raise HTTPException(400, msg)
    if db.query(User).filter(User.email == email.lower().strip()).first():
        raise HTTPException(409, "Email already registered")

    # Kiểm tra mã giới thiệu
    referrer = None
    if referral_code:
        referrer = db.query(User).filter(
            User.referral_code == referral_code.upper().strip()
        ).first()
        if not referrer:
            raise HTTPException(400, "Mã giới thiệu không tồn tại.")

    verify_token_str = generate_token()
    new_code = _gen_referral_code(email)
    user = User(
        email=email.lower().strip(),
        password=hash_password(password),
        verify_token=verify_token_str,
        is_verified="no",
        token_balance=0,
        default_currency="USD",
        language="en",
        max_reminders=5,
        referral_code=new_code,
        referred_by=referral_code.upper().strip() if referral_code else None,
    )

    # Nếu có mã giới thiệu hợp lệ → cả 2 được thưởng
    if referrer:
        today = date.today()
        bonus_exp = (today + tdelta(days=REFERRAL_BONUS_DAYS)).isoformat()

        # Người được giới thiệu → Pro Trial 14 ngày
        user.plan = "pro"
        user.plan_type = "referral_trial"
        user.plan_expires_at = bonus_exp
        user.plan_start_at = today.isoformat()
        user.trial_used = True

        # Người giới thiệu → thêm 14 ngày Pro (nếu đang Pro/VIP thì cộng thêm)
        if referrer.plan in ("pro", "vip") and referrer.plan_expires_at and referrer.plan_expires_at != "lifetime":
            current_exp = date.fromisoformat(referrer.plan_expires_at)
            referrer.plan_expires_at = (current_exp + tdelta(days=REFERRAL_BONUS_DAYS)).isoformat()
        elif referrer.plan == "free":
            referrer.plan = "pro"
            referrer.plan_type = "referral_bonus"
            referrer.plan_expires_at = bonus_exp
            referrer.plan_start_at = today.isoformat()

        referrer.referral_count = (referrer.referral_count or 0) + 1

    db.add(user)
    db.commit()

    link = f"http://127.0.0.1:8000/api/verify?token={verify_token_str}"
    send_email(ADMIN_EMAIL, EMAIL_PASSWORD, email, "Verify your LicenseHub account",
               f"Welcome!\n\nClick to verify:\n{link}"
               + (f"\n\n🎁 Bạn nhận được 14 ngày Pro Trial vì dùng mã giới thiệu!" if referrer else ""))

    return {
        "msg": "Đăng ký thành công! Kiểm tra email để xác minh.",
        "referral_bonus": referrer is not None,
        "your_code": new_code,
    }
