from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime
from sqlalchemy.sql import func
from database import Base

# ── Plan definitions ──────────────────────────────────────
PLANS = {
    "free": {
        "label":                "Free",
        "max_invoices_per_day": 5,
        "max_reminders":        1,
        "webhooks":             False,
        "email_template":       False,
        "analytics":            False,
        "pdf_export":           False,
        "customer_book":        False,
        "token_bonus":          0,
        "price_monthly":        0,
        "price_annual":         0,
    },
    "starter": {
        "label":                "Starter",
        "max_invoices_per_day": 30,
        "max_reminders":        3,
        "webhooks":             True,
        "email_template":       True,
        "analytics":            False,
        "pdf_export":           True,
        "customer_book":        False,
        "token_bonus":          100,
        "price_monthly":        6,    # $6/month  (số may mắn 6)
        "price_annual":         46,   # $46/year  (số may mắn 4+6)
    },
    "pro": {
        "label":                "Pro",
        "max_invoices_per_day": 200,
        "max_reminders":        10,
        "webhooks":             True,
        "email_template":       True,
        "analytics":            True,
        "pdf_export":           True,
        "customer_book":        True,
        "token_bonus":          500,
        "price_monthly":        14,   # $14/month (số may mắn 1+4)
        "price_annual":         116,  # $116/year (số may mắn 1+1+6)
    },
    "vip": {
        "label":                "VIP",
        "max_invoices_per_day": -1,
        "max_reminders":        -1,
        "webhooks":             True,
        "email_template":       True,
        "analytics":            True,
        "pdf_export":           True,
        "customer_book":        True,
        "token_bonus":          2000,
        "price_monthly":        46,   # $46/month (số may mắn 4+6)
        "price_annual":         416,  # $416/year (số may mắn 4+1+6 ✨)
    },
}

REFERRAL_BONUS_DAYS = 14  # Số ngày bonus khi dùng mã giới thiệu


class User(Base):
    __tablename__ = "users"
    id               = Column(Integer, primary_key=True)
    email            = Column(String, unique=True)
    password         = Column(String)
    is_verified      = Column(String, default="no")
    verify_token     = Column(String)
    reset_token      = Column(String)
    smtp_email       = Column(String)
    smtp_password    = Column(String)
    license_expiry   = Column(String)
    email_template   = Column(String)
    webhook_url      = Column(String, nullable=True)
    webhook_secret   = Column(String, nullable=True)
    token_balance    = Column(Integer, default=0)
    # Settings
    default_currency = Column(String, default="USD")
    language         = Column(String, default="en")
    max_reminders    = Column(Integer, default=5)
    # Plan / subscription
    plan             = Column(String, default="free")
    plan_type        = Column(String, nullable=True)   # "monthly" | "annual" | "lifetime"
    plan_expires_at  = Column(String, nullable=True)   # ISO date or "lifetime"
    plan_start_at    = Column(String, nullable=True)   # ISO date when plan started
    auto_renew       = Column(Boolean, default=True)   # False = cancelled, expires at end of period
    plan_note        = Column(String, nullable=True)
    # Referral
    referral_code    = Column(String, unique=True, nullable=True)  # Mã giới thiệu của user này
    referred_by      = Column(String, nullable=True)               # Mã ai đã giới thiệu họ
    referral_count   = Column(Integer, default=0)                  # Đã giới thiệu bao nhiêu người
    # Trial
    trial_used       = Column(Boolean, default=False)   # Đã dùng free trial chưa


class Invoice(Base):
    __tablename__ = "invoices"
    id                = Column(Integer, primary_key=True)
    user_id           = Column(Integer)
    customer_name     = Column(String)
    customer_email    = Column(String)
    total             = Column(Float)
    currency          = Column(String, default="USD")
    status            = Column(String, default="pending")
    notes             = Column(String, nullable=True)
    due_date          = Column(String, nullable=True)
    remind_every_days = Column(Integer, default=0)
    reminder_count    = Column(Integer, default=0)
    last_reminded_at  = Column(DateTime, nullable=True)
    created_at        = Column(DateTime, server_default=func.now())
    ip                = Column(String, nullable=True)


class License(Base):
    __tablename__ = "licenses"
    id            = Column(Integer, primary_key=True)
    code          = Column(String, unique=True)
    duration_days = Column(Integer)
    is_used       = Column(String, default="no")
    device_id     = Column(String, nullable=True)
    grants_plan   = Column(String, nullable=True)


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
