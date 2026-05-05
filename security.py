"""
security.py — LicenseHub v2
Dùng bcrypt trực tiếp thay vì passlib để tránh lỗi tương thích.
"""

import os
import hmac
import hashlib
import time
import bcrypt
from collections import defaultdict
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

load_dotenv()

# ── Mã hóa mật khẩu (bcrypt trực tiếp) ──────────────────

def hash_password(password: str) -> str:
    """Hash mật khẩu bằng bcrypt. Không bao giờ lưu mật khẩu thô."""
    if not password or len(password) < 8:
        raise ValueError("Mật khẩu phải có ít nhất 8 ký tự")
    # Giới hạn 72 bytes để tránh lỗi bcrypt
    password_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password_bytes, salt).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    """Kiểm tra mật khẩu với hash. Trả về False nếu sai, không raise lỗi."""
    if not password or not hashed:
        return False
    try:
        password_bytes = password.encode("utf-8")[:72]
        return bcrypt.checkpw(password_bytes, hashed.encode("utf-8"))
    except Exception:
        return False

# ── Mã hóa Fernet (cho mật khẩu SMTP lưu trong DB) ──────

_raw_key = os.getenv("FERNET_KEY", "").strip()
if not _raw_key:
    raise EnvironmentError(
        "Thiếu FERNET_KEY trong file .env\n"
        "Tạo key mới bằng lệnh:\n"
        "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
    )

try:
    _cipher = Fernet(_raw_key.encode())
except Exception as exc:
    raise ValueError(f"FERNET_KEY không hợp lệ: {exc}")

def encrypt(plaintext: str) -> str:
    """Mã hóa chuỗi để lưu an toàn vào DB."""
    if not plaintext:
        raise ValueError("Không thể mã hóa chuỗi rỗng")
    return _cipher.encrypt(plaintext.encode()).decode()

def decrypt(token: str) -> str:
    """Giải mã token. Lỗi nếu bị giả mạo hoặc key thay đổi."""
    if not token:
        raise ValueError("Không thể giải mã chuỗi rỗng")
    try:
        return _cipher.decrypt(token.encode()).decode()
    except InvalidToken:
        raise ValueError("Giải mã thất bại — dữ liệu bị hỏng hoặc key đã thay đổi")

# ── So sánh chuỗi constant-time (chống timing attack) ────

def safe_compare(a: str, b: str) -> bool:
    """So sánh 2 chuỗi trong thời gian cố định để chống timing attack."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

def verify_admin_secret(provided: str) -> bool:
    """Kiểm tra admin secret."""
    expected = os.getenv("ADMIN_SECRET", "")
    if not expected or not provided:
        return False
    return safe_compare(provided, expected)

# ── Rate limiter đơn giản (chống brute force) ─────────────

_attempts: dict = defaultdict(list)
_WINDOW = 60    # giây
_MAX = 10       # số lần tối đa trong _WINDOW giây

def check_rate_limit(identifier: str) -> bool:
    """
    Trả về True nếu còn trong giới hạn.
    Trả về False nếu đã vượt giới hạn (caller nên raise HTTP 429).
    """
    now = time.time()
    _attempts[identifier] = [t for t in _attempts[identifier] if t > now - _WINDOW]
    if len(_attempts[identifier]) >= _MAX:
        return False
    _attempts[identifier].append(now)
    return True

# ── Kiểm tra độ mạnh mật khẩu ────────────────────────────

def check_password_strength(password: str) -> tuple[bool, str]:
    """Trả về (đủ mạnh, thông báo)."""
    if len(password) < 8:
        return False, "Mật khẩu phải có ít nhất 8 ký tự"
    if not any(c.isdigit() for c in password):
        return False, "Mật khẩu phải có ít nhất 1 số"
    if not any(c.isalpha() for c in password):
        return False, "Mật khẩu phải có ít nhất 1 chữ cái"
    return True, "OK"
