"""
Database Module — SQLite via SQLAlchemy
Handles connection, session management, and table creation.
"""

from sqlalchemy import (
    create_engine, Column, Integer, String, Float,
    Boolean, Text, DateTime, JSON
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///./quantum_cbom.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── ORM Models ────────────────────────────────────────────────────────────────

class ScanResult(Base):
    __tablename__ = "scan_results"

    id               = Column(Integer, primary_key=True, index=True)
    target           = Column(String, index=True)
    port             = Column(Integer, default=443)
    scanned_at       = Column(DateTime, default=datetime.utcnow)

    # TLS Details
    tls_version      = Column(String)
    cipher_suite     = Column(String)
    key_exchange     = Column(String)
    signature_alg    = Column(String)
    cert_type        = Column(String)
    key_size         = Column(Integer)
    cert_expiry      = Column(String)
    cert_subject     = Column(String)
    cert_issuer      = Column(String)
    cert_valid       = Column(Boolean)

    # Classification
    quantum_status   = Column(String)   # NOT_PQC_READY | TRANSITIONAL | FULLY_QUANTUM_SAFE
    risk_level       = Column(String)   # HIGH | MEDIUM | LOW
    risk_score       = Column(Float)
    is_compliant     = Column(Boolean, default=False)

    # Structured output
    cbom_json        = Column(JSON)
    remediation      = Column(JSON)
    badge_issued     = Column(Boolean, default=False)

    scan_error       = Column(Text, nullable=True)


class Certificate(Base):
    __tablename__ = "pqc_certificates"

    id               = Column(Integer, primary_key=True, index=True)
    scan_id          = Column(Integer, index=True)
    target           = Column(String)
    issued_at        = Column(DateTime, default=datetime.utcnow)
    expires_at       = Column(DateTime)
    certificate_json = Column(JSON)
    badge_svg        = Column(Text)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
