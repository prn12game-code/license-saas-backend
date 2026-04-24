import os
from auth import generate_token
from dotenv import load_dotenv
from fastapi import Header
from auth import verify_token
from pydantic import BaseModel
from fastapi.responses import HTMLResponse
from fastapi import Form
load_dotenv()

ADMIN_SECRET = os.getenv("ADMIN_SECRET")
JWT_SECRET = os.getenv("JWT_SECRET")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from models import Base, User, Invoice, License
from security import hash_password, verify_password, encrypt, decrypt
from auth import create_token
from email_utils import send_email
from license_utils import generate_code
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request

templates = Jinja2Templates(directory="templates")

app = FastAPI(docs_url=None, redoc_url=None)

Base.metadata.create_all(bind=engine)

class RegisterRequest(BaseModel):
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str


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

    # lần đầu
    if not lic.device_id:
        lic.device_id = device_id

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

    ip = request.client.host

    if lic.device_id and lic.device_id != device_id:
        return {"error": "device mismatch"}

    if hasattr(lic, "ip") and lic.ip and lic.ip != ip:
        return {"error": "ip mismatch"}

    lic.device_id = device_id
    lic.ip = ip

# Register
@app.post("/register")
def register(
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        return {"error": "email already exists"}

    token = generate_token()

    user = User(
        email=email,
        password=hash_password(password),
        verify_token=token,
        is_verified="no"
    )

    db.add(user)
    db.commit()

    # gửi email xác nhận
    verify_link = f"http://127.0.0.1:8000/verify?token={token}"

    send_email(
        ADMIN_EMAIL,
        EMAIL_PASSWORD,
        email,
        "Verify your account",
        f"Click to verify: {verify_link}"
    )

    return {"msg": "check your email to verify account"}

@app.get("/register", response_class=HTMLResponse)
def register_page():
    return """
    <html>
        <body>
            <h2>Register</h2>
            <form action="/register" method="post">
                <input name="email" placeholder="Email"><br>
                <input name="password" type="password" placeholder="Password"><br>
                <button type="submit">Register</button>
            </form>
        </body>
    </html>
    """

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return """
    <html>
        <body>
            <h2>Login</h2>
            <form action="/login" method="post">
                <input name="email" placeholder="Email"><br>
                <input name="password" type="password" placeholder="Password"><br>
                <button type="submit">Login</button>
            </form>
        </body>
    </html>
    """
# Login
@app.post("/login")
def login(
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == email).first()

    if not user or not verify_password(password, user.password):
        return {"error": "invalid"}

    
    if user.is_verified != "yes":
        return {"error": "please verify your email first"}

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

    # ✅ FIX ĐẶT Ở ĐÂY
    if not user.smtp_email or not user.smtp_password:
        return {"error": "smtp not set"}

    invoice = Invoice(
        customer_name=customer_name,
        customer_email=customer_email,
        total=total,
        user_id=user.id   # ⚠️ nhớ thêm dòng này
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

class RegisterRequest(BaseModel):
    email: str
    password: str

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return """
    <html>
        <body>
            <h2>Login</h2>
            <form action="/login" method="post">
                <input name="email" placeholder="Email"><br>
                <input name="password" type="password" placeholder="Password"><br>
                <button type="submit">Login</button>
            </form>
        </body>
    </html>
    """

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html>
        <body>
            <h1>Invoice SaaS</h1>
            <a href="/login">Login</a><br>
            <a href="/register">Register</a>
        </body>
    </html>
    """

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/verify")
def verify(token: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.verify_token == token).first()

    if not user:
        return {"error": "invalid token"}

    user.is_verified = "yes"
    user.verify_token = None
    db.commit()

    return {"msg": "account verified"}

@app.post("/forgot-password")
def forgot_password(email: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()

    if not user:
        return {"error": "email not found"}

    token = generate_token()
    user.reset_token = token
    db.commit()

    link = f"http://127.0.0.1:8000/reset-password?token={token}"

    send_email(
        ADMIN_EMAIL,
        EMAIL_PASSWORD,
        email,
        "Reset password",
        f"Click here: {link}"
    )

    return {"msg": "check your email"}

@app.post("/change-password")
def change_password(
    old_password: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not verify_password(old_password, current_user.password):
        return {"error": "wrong password"}

    current_user.password = hash_password(new_password)
    db.commit()

    return {"msg": "changed"}

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    invoices = db.query(Invoice).filter(Invoice.user_id == current_user.id).all()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "invoices": invoices
    })

@app.get("/admin/users")
def get_users(admin_secret: str, db: Session = Depends(get_db)):
    if admin_secret != ADMIN_SECRET:
        return {"error": "unauthorized"}

    return db.query(User).all()

@app.get("/admin/invoices")
def get_all_invoices(admin_secret: str, db: Session = Depends(get_db)):
    if admin_secret != ADMIN_SECRET:
        return {"error": "unauthorized"}

    return db.query(Invoice).all()

@app.get("/my-license")
def my_license(current_user: User = Depends(get_current_user)):
    return {
        "license": current_user.license_expiry
    }

@app.get("/admin/licenses")
def all_licenses(admin_secret: str, db: Session = Depends(get_db)):
    if admin_secret != ADMIN_SECRET:
        return {"error": "unauthorized"}

    return db.query(License).all()