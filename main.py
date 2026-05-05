import os, secrets as _secrets
from datetime import datetime, timedelta
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Header, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

load_dotenv()

ADMIN_EMAIL    = os.getenv("ADMIN_EMAIL")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

from database import SessionLocal, engine
from models import Base, User, Invoice, License, TokenPackage, TokenTransaction
from security import (
    hash_password, verify_password, encrypt, decrypt,
    verify_admin_secret, check_rate_limit, check_password_strength
)
from auth import create_token, verify_token, generate_token
from email_utils import send_email
from license_utils import generate_code
import webhook_utils
import token_utils

Base.metadata.create_all(bind=engine)

app = FastAPI(title="LicenseHub API", version="2.0", docs_url="/api/docs", redoc_url=None)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# ── DB & auth dependencies ────────────────────────────────

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
        email   = payload.get("email")
        user    = db.query(User).filter(User.email == email).first()
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

@app.get("/",                  response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "index.html")

@app.get("/login",             response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html")

@app.get("/register",          response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html")

@app.get("/dashboard",         response_class=HTMLResponse)
def dashboard_page(request: Request):
    return templates.TemplateResponse(request, "dashboard.html")

@app.get("/forgot-password",   response_class=HTMLResponse)
def forgot_page(request: Request):
    return templates.TemplateResponse(request, "forgot_password.html")

@app.get("/reset-password",    response_class=HTMLResponse)
def reset_page(request: Request, token: str = ""):
    return templates.TemplateResponse(request, "reset_password.html", {"token": token})


# ── Auth ──────────────────────────────────────────────────

@app.post("/api/register")
def register(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    ip = request.client.host
    if not check_rate_limit(ip):
        raise HTTPException(status_code=429, detail="Too many attempts — please wait a minute")

    strong, msg = check_password_strength(password)
    if not strong:
        raise HTTPException(status_code=400, detail=msg)

    if db.query(User).filter(User.email == email.lower().strip()).first():
        raise HTTPException(status_code=409, detail="Email already registered")

    token = generate_token()
    user  = User(
        email=email.lower().strip(),
        password=hash_password(password),
        verify_token=token,
        is_verified="no",
        token_balance=0,
    )
    db.add(user); db.commit()

    link = f"http://127.0.0.1:8000/api/verify?token={token}"
    send_email(ADMIN_EMAIL, EMAIL_PASSWORD, email,
               "Verify your LicenseHub account",
               f"Welcome!\n\nClick to verify:\n{link}\n\nLink expires in 24 hours.")
    return {"msg": "Check your email to verify your account"}


@app.get("/api/verify")
def verify_email(token: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.verify_token == token).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    user.is_verified = "yes"; user.verify_token = None
    db.commit()
    return RedirectResponse(url="/login?verified=1")


@app.post("/api/login")
def login(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    ip = request.client.host
    if not check_rate_limit(f"login:{ip}"):
        raise HTTPException(status_code=429, detail="Too many login attempts — please wait a minute")

    user = db.query(User).filter(User.email == email.lower().strip()).first()
    if not user or not verify_password(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if user.is_verified != "yes":
        raise HTTPException(status_code=403, detail="Please verify your email first")

    token = create_token({"email": user.email})
    return {"token": token, "email": user.email}


@app.post("/api/forgot-password")
def forgot_password(email: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email.lower().strip()).first()
    if user:
        token = generate_token()
        user.reset_token = token; db.commit()
        link = f"http://127.0.0.1:8000/reset-password?token={token}"
        send_email(ADMIN_EMAIL, EMAIL_PASSWORD, email,
                   "Reset your LicenseHub password",
                   f"Click to reset your password:\n{link}\n\nIgnore this if you didn't request it.")
    # Always return same response — prevents email enumeration
    return {"msg": "If that email exists, a reset link has been sent"}


@app.post("/api/reset-password")
def reset_password(token: str = Form(...), new_password: str = Form(...), db: Session = Depends(get_db)):
    strong, msg = check_password_strength(new_password)
    if not strong:
        raise HTTPException(status_code=400, detail=msg)
    user = db.query(User).filter(User.reset_token == token).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    user.password = hash_password(new_password); user.reset_token = None
    db.commit()
    return {"msg": "Password reset successfully"}


@app.post("/api/change-password")
def change_password(
    old_password: str = Form(...), new_password: str = Form(...),
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    if not verify_password(old_password, current_user.password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    strong, msg = check_password_strength(new_password)
    if not strong:
        raise HTTPException(status_code=400, detail=msg)
    current_user.password = hash_password(new_password)
    db.commit()
    return {"msg": "Password changed successfully"}


# ── SMTP ──────────────────────────────────────────────────

@app.post("/api/smtp")
def save_smtp(email: str, password: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    current_user.smtp_email    = email
    current_user.smtp_password = encrypt(password)
    db.add(current_user); db.commit()
    return {"msg": "SMTP settings saved"}


# ── Invoices ──────────────────────────────────────────────

@app.post("/api/invoice")
def create_invoice(
    customer_name: str = Form(...), customer_email: str = Form(...),
    total: float = Form(...), currency: str = Form(default="USD"),
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    if total <= 0:
        raise HTTPException(status_code=400, detail="Total must be greater than 0")
    if not current_user.smtp_email or not current_user.smtp_password:
        raise HTTPException(status_code=400, detail="Please configure your SMTP settings first")

    invoice = Invoice(
        customer_name=customer_name.strip(),
        customer_email=customer_email.lower().strip(),
        total=total, currency=currency, user_id=current_user.id
    )
    db.add(invoice); db.commit(); db.refresh(invoice)

    smtp_pass = decrypt(current_user.smtp_password)
    template  = current_user.email_template or "Hello {customer_name},\n\nYou have an invoice for {amount} {currency}.\n\nThank you!"
    content   = template.format(customer_name=customer_name, amount=total, currency=currency)
    send_email(current_user.smtp_email, smtp_pass, customer_email, f"Invoice #{invoice.id}", content)

    return {"msg": "Invoice created", "invoice_id": invoice.id}


@app.get("/api/invoices")
def list_invoices(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    invoices = db.query(Invoice).filter(Invoice.user_id == current_user.id).all()
    return [{"id": i.id, "customer_name": i.customer_name, "customer_email": i.customer_email,
             "total": i.total, "currency": i.currency, "status": i.status} for i in invoices]


@app.post("/api/invoice/{invoice_id}/paid")
def mark_paid(invoice_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    invoice = db.query(Invoice).filter(Invoice.id == invoice_id, Invoice.user_id == current_user.id).first()
    if not invoice:
        raise HTTPException(status_code=404, detail="Invoice not found")
    if invoice.status == "paid":
        raise HTTPException(status_code=400, detail="Invoice already marked as paid")

    invoice.status = "paid"; db.commit()

    if current_user.smtp_email and current_user.smtp_password:
        smtp_pass = decrypt(current_user.smtp_password)
        send_email(current_user.smtp_email, smtp_pass, invoice.customer_email,
                   "Payment confirmed",
                   f"Hi {invoice.customer_name}, your payment of {invoice.total} {invoice.currency} has been received. Thank you!")

    if current_user.webhook_url:
        webhook_utils.fire("invoice.paid", invoice, current_user.webhook_url, current_user.webhook_secret)

    return {"msg": "Invoice marked as paid"}


# ── Licenses ──────────────────────────────────────────────

@app.get("/api/check-license")
def check_license(code: str, device_id: str, db: Session = Depends(get_db)):
    lic = db.query(License).filter(License.code == code).first()
    if not lic or lic.is_used == "revoked":
        return {"valid": False, "reason": "Not found or revoked"}
    if lic.is_used == "no":
        return {"valid": False, "reason": "Not yet activated"}
    if lic.device_id and lic.device_id != device_id:
        return {"valid": False, "reason": "Device mismatch"}
    return {"valid": True}


@app.post("/api/activate")
def activate(code: str = Form(...), device_id: str = Form(...),
             db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    lic = db.query(License).filter(License.code == code).first()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")
    if lic.is_used == "revoked":
        raise HTTPException(status_code=400, detail="License has been revoked")
    if lic.is_used == "yes" and lic.device_id != device_id:
        raise HTTPException(status_code=400, detail="License already used on another device")

    lic.device_id = device_id; lic.is_used = "yes"
    if lic.duration_days == -1:
        current_user.license_expiry = "permanent"
    else:
        current_user.license_expiry = str(datetime.utcnow() + timedelta(days=lic.duration_days))
    db.commit()
    return {"msg": "License activated", "expiry": current_user.license_expiry}


@app.get("/api/my-license")
def my_license(current_user: User = Depends(get_current_user)):
    return {"license_expiry": current_user.license_expiry}


# ── Webhooks ──────────────────────────────────────────────

@app.post("/api/webhook")
def save_webhook(url: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
    current_user.webhook_url = url.strip()
    if not current_user.webhook_secret:
        current_user.webhook_secret = _secrets.token_hex(32)
    db.add(current_user); db.commit()
    return {"msg": "Webhook saved", "url": current_user.webhook_url, "secret": current_user.webhook_secret}


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
        raise HTTPException(status_code=400, detail="No webhook URL configured")

    class _Fake:
        id=0; customer_name="Test Customer"; customer_email="test@example.com"
        total=0.0; currency="USD"; status="paid"

    webhook_utils.fire("webhook.test", _Fake(), current_user.webhook_url, current_user.webhook_secret)
    return {"msg": "Test webhook fired"}


# ── Token system ──────────────────────────────────────────

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
    if days < -1 or days == 0:
        raise HTTPException(status_code=400, detail="days must be -1 (permanent) or a positive integer")
    code = generate_code(16)
    db.add(License(code=code, duration_days=days, is_used="no")); db.commit()
    return {"code": code, "duration_days": days}


@app.post("/api/admin/revoke")
def revoke(code: str, admin_secret: str, db: Session = Depends(get_db)):
    require_admin(admin_secret)
    lic = db.query(License).filter(License.code == code).first()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")
    lic.is_used = "revoked"; db.commit()
    return {"msg": "License revoked"}


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
    return [{"id": i.id, "customer_name": i.customer_name, "total": i.total,
             "currency": i.currency, "status": i.status, "user_id": i.user_id}
            for i in db.query(Invoice).all()]


@app.post("/api/admin/grant-tokens")
def grant_tokens(user_email: str, amount: int, reason: str, admin_secret: str,
                 db: Session = Depends(get_db)):
    require_admin(admin_secret)
    user = db.query(User).filter(User.email == user_email.lower().strip()).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    new_balance = token_utils.grant_tokens(db, user, amount, reason)
    return {"msg": f"Granted {amount} tokens to {user_email}", "new_balance": new_balance}


@app.post("/api/admin/token-packages")
def create_package(
    name: str, description: str, tokens: int, price: float,
    currency: str = "USD", admin_secret: str = "",
    db: Session = Depends(get_db)
):
    require_admin(admin_secret)
    pkg = TokenPackage(name=name, description=description, tokens=tokens,
                       price=price, currency=currency, is_active=True)
    db.add(pkg); db.commit(); db.refresh(pkg)
    return {"msg": "Package created", "id": pkg.id}


@app.delete("/api/admin/token-packages/{pkg_id}")
def delete_package(pkg_id: int, admin_secret: str, db: Session = Depends(get_db)):
    require_admin(admin_secret)
    pkg = db.query(TokenPackage).filter(TokenPackage.id == pkg_id).first()
    if not pkg:
        raise HTTPException(status_code=404, detail="Package not found")
    pkg.is_active = False; db.commit()
    return {"msg": "Package deactivated"}
