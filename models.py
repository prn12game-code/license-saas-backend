from sqlalchemy import Column, Integer, String, Float
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    email = Column(String, unique=True)
    password = Column(String)

    is_verified = Column(String, default="no")
    verify_token = Column(String)
    reset_token = Column(String)                 

    smtp_email = Column(String)
    smtp_password = Column(String)
    license_expiry = Column(String)
    smtp_mode = Column(String, default="always")
    
    email_template = Column(String)

class Invoice(Base):
    ip = Column(String)
    __tablename__ = "invoices"
    user_id = Column(Integer)
    id = Column(Integer, primary_key=True)
    customer_name = Column(String)
    customer_email = Column(String)
    total = Column(Float)
    status = Column(String, default="pending")

class License(Base):
    __tablename__ = "licenses"
    id = Column(Integer, primary_key=True)
    code = Column(String, unique=True)
    duration_days = Column(Integer)
    is_used = Column(String, default="no")
    device_id = Column(String, nullable=True)