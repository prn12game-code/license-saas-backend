from jose import jwt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import secrets

load_dotenv()

SECRET = os.getenv("JWT_SECRET")
ALGO = "HS256"


def generate_token():
    return secrets.token_urlsafe(32)


def create_token(data):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(hours=24)
    return jwt.encode(payload, SECRET, algorithm=ALGO)

def verify_token(token):
    return jwt.decode(token, SECRET, algorithms=[ALGO])