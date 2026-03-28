import os
from dotenv import load_dotenv
from fastapi import Header
from auth import verify_token
load_dotenv()

ADMIN_SECRET = os.getenv("ADMIN_SECRET")
JWT_SECRET = os.getenv("JWT_SECRET")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")

from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from models import Base, User, Invoice, License
from security import hash_password, verify_password, encrypt, decrypt
from auth import create_token
from email_utils import send_email
from license_utils import generate_code


app = FastAPI()

Base.metadata.create_all(bind=engine)


# DB dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
def get_current_user(authorization: str = Header(...), db: Session = Depends(get_db)):
    try:
        token = authorization.split(" ")[1]
        payload = verify_token(token)
        email = payload["email"]

        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        return user
    except:
        raise HTTPException(status_code=401, detail="Invalid token")


from fastapi import HTTPException

@app.post("/x9k2-admin-gen")
def generate_license(days: int, admin_secret: str, db: Session = Depends(get_db)):

    if admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Unauthorized")

    code = generate_code(16)

    lic = License(
        code=code,
        duration_days=days,
        is_used="no"
    )

    db.add(lic)
    db.commit()

    return {"code": code}


from datetime import datetime, timedelta

@app.post("/activate")
def activate(code: str, user_email: str, device_id: str, db: Session = Depends(get_db)):

    lic = db.query(License).filter(License.code == code).first()
    if lic.device_id and lic.device_id != device_id:
        return {"error": "license already used on another device"}
    if not lic or lic.is_used == "yes":
        return {"error": "invalid code"}

    user = db.query(User).filter(User.email == user_email).first()

    if not user:
        return {"error": "user not found"}

    if lic.duration_days == -1:
        user.license_expiry = "permanent"
    else:
        expiry = datetime.utcnow() + timedelta(days=lic.duration_days)
        user.license_expiry = str(expiry)

    lic.is_used = "yes"
    lic.device_id = device_id
    db.commit()

    return {"msg": "activated"}

# Register
@app.post("/register")
def register(email: str, password: str, db: Session = Depends(get_db)):
    user = User(email=email, password=hash_password(password))
    db.add(user)
    db.commit()
    return {"msg": "created"}

# Login
@app.post("/login")
def login(email: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password):
        return {"error": "invalid"}

    token = create_token({"email": email})
    return {"token": token}

# Save SMTP
@app.post("/smtp")
def save_smtp(
    email: str,
    password: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user = current_user
    user.smtp_email = email
    user.smtp_password = encrypt(password)
    db.commit()
    return {"msg": "saved"}

# Create invoice
@app.post("/invoice")
def create_invoice(
    customer_name: str,
    customer_email: str,
    total: float,
    currency: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user = current_user

    if not user:
        return {"error": "user not found"}

    invoice = Invoice(
        customer_name=customer_name,
        customer_email=customer_email,
        total=total
    )

    db.add(invoice)
    db.commit()

    # ===== EMAIL =====
    smtp_pass = decrypt(user.smtp_password)

    # template cho phép user chỉnh
    template = user.email_template or "Hello {customer_name}, you owe {amount} {currency}"

    content = template.format(
        customer_name=customer_name,
        amount=total,
        currency=currency   #  KHÔNG HARD CODE NỮA
    )

    send_email(
        user.smtp_email,
        smtp_pass,
        customer_email,
        "Invoice",
        content
    )

    return {"msg": "invoice created"}

# Mark as paid
@app.post("/paid")
def mark_paid(
    invoice_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    invoice = db.query(Invoice).filter(Invoice.id == invoice_id).first()
    invoice.status = "paid"
    db.commit()

    user = current_user
    smtp_pass = decrypt(user.smtp_password)

    send_email(
        user.smtp_email,
        smtp_pass,
        invoice.customer_email,
        "Payment received",
        "Thank you for your payment!"
    )

    return {"msg": "updated"}




@app.get("/check-license")
def check_license(code: str, device_id: str, db: Session = Depends(get_db)):

    lic = db.query(License).filter(License.code == code).first()

    if not lic:
        return {"valid": False}

    if lic.is_used == "revoked":
        return {"valid": False}

    # check device
    if lic.device_id and lic.device_id != device_id:
        return {"valid": False}

    return {"valid": True}

@app.post("/revoke")
def revoke(code: str, admin_secret: str, db: Session = Depends(get_db)):
    if admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Unauthorized")

    lic = db.query(License).filter(License.code == code).first()

    if not lic:
        raise HTTPException(status_code=404, detail="License not found")

    lic.is_used = "revoked"
    db.commit()

    return {"msg": "revoked"}

@app.get("/licenses")
def list_licenses(admin_secret: str, db: Session = Depends(get_db)):
    if admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403)

    return db.query(License).all()