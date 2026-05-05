from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime
from sqlalchemy.sql import func
from database import Base


class User(Base):
    __tablename__ = "users"
    id             = Column(Integer, primary_key=True)
    email          = Column(String, unique=True)
    password       = Column(String)
    is_verified    = Column(String, default="no")
    verify_token   = Column(String)
    reset_token    = Column(String)
    smtp_email     = Column(String)
    smtp_password  = Column(String)
    license_expiry = Column(String)
    email_template = Column(String)
    webhook_url    = Column(String, nullable=True)
    webhook_secret = Column(String, nullable=True)
    token_balance  = Column(Integer, default=0)


class Invoice(Base):
    __tablename__ = "invoices"
    id             = Column(Integer, primary_key=True)
    user_id        = Column(Integer)
    customer_name  = Column(String)
    customer_email = Column(String)
    total          = Column(Float)
    currency       = Column(String, default="USD")
    status         = Column(String, default="pending")
    ip             = Column(String)


class License(Base):
    __tablename__ = "licenses"
    id            = Column(Integer, primary_key=True)
    code          = Column(String, unique=True)
    duration_days = Column(Integer)
    is_used       = Column(String, default="no")
    device_id     = Column(String, nullable=True)


class TokenPackage(Base):
    __tablename__ = "token_packages"
    id          = Column(Integer, primary_key=True)
    name        = Column(String)
    description = Column(String)
    tokens      = Column(Integer)
    price       = Column(Float)
    currency    = Column(String, default="USD")
    is_active   = Column(Boolean, default=True)
    created_at  = Column(DateTime, server_default=func.now())


class TokenTransaction(Base):
    __tablename__ = "token_transactions"
    id            = Column(Integer, primary_key=True)
    user_id       = Column(Integer)
    delta         = Column(Integer)
    reason        = Column(String)
    balance_after = Column(Integer)
    created_at    = Column(DateTime, server_default=func.now())
