from jose import jwt
from datetime import datetime, timedelta
import os, secrets
from dotenv import load_dotenv

load_dotenv()
SECRET = os.getenv("JWT_SECRET", "change_me")
ALGO   = "HS256"

def generate_token() -> str:
    return secrets.token_urlsafe(32)

def create_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(hours=24)
    return jwt.encode(payload, SECRET, algorithm=ALGO)

def verify_token(token: str) -> dict:
    return jwt.decode(token, SECRET, algorithms=[ALGO])
