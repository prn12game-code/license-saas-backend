"""
security.py — LicenseHub v2
Handles: password hashing, Fernet encryption, token validation, rate limiting
"""

import os, time, hmac, hashlib
from collections import defaultdict
from cryptography.fernet import Fernet, InvalidToken
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()

# ── Password hashing ──────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

def hash_password(password: str) -> str:
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    if not password or not hashed:
        return False
    try:
        return pwd_context.verify(password, hashed)
    except Exception:
        return False

# ── Fernet encryption (SMTP passwords at rest) ────────────
_raw_key = os.getenv("FERNET_KEY", "").strip()
if not _raw_key:
    raise EnvironmentError(
        "FERNET_KEY missing from .env\n"
        "Generate: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
    )
try:
    _cipher = Fernet(_raw_key.encode())
except Exception as exc:
    raise ValueError(f"FERNET_KEY is invalid: {exc}")

def encrypt(plaintext: str) -> str:
    if not plaintext:
        raise ValueError("Cannot encrypt empty string")
    return _cipher.encrypt(plaintext.encode()).decode()

def decrypt(token: str) -> str:
    if not token:
        raise ValueError("Cannot decrypt empty token")
    try:
        return _cipher.decrypt(token.encode()).decode()
    except InvalidToken:
        raise ValueError("Decryption failed — token corrupted or key changed")

# ── Constant-time comparison (prevents timing attacks) ────
def safe_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

def verify_admin_secret(provided: str) -> bool:
    expected = os.getenv("ADMIN_SECRET", "")
    if not expected or not provided:
        return False
    return safe_compare(provided, expected)

# ── In-memory rate limiter ────────────────────────────────
_attempts: dict = defaultdict(list)
_WINDOW = 60       # seconds
_MAX = 10          # attempts per window

def check_rate_limit(identifier: str) -> bool:
    now = time.time()
    _attempts[identifier] = [t for t in _attempts[identifier] if t > now - _WINDOW]
    if len(_attempts[identifier]) >= _MAX:
        return False
    _attempts[identifier].append(now)
    return True

# ── Password strength ─────────────────────────────────────
def check_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    if not any(c.isalpha() for c in password):
        return False, "Password must contain at least one letter"
    return True, "OK"
