from sqlalchemy import Column, Integer, String, DateTime, func, Boolean
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    referral_code = Column(String(50))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    verification_code = Column(String(6), nullable=True)
    verification_expires_at = Column(DateTime(timezone=True), nullable=True)
    is_verified = Column(Boolean, nullable=False, server_default="0")
    reset_code = Column(String(6), nullable=True)
    reset_expires_at = Column(DateTime(timezone=True), nullable=True)
    is_admin = Column(Boolean, nullable=False, server_default="0")
