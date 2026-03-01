"""
Scan Router
-----------
POST /api/scan/       — Trigger a new TLS scan
GET  /api/scan/{id}   — Retrieve scan result
GET  /api/scan/       — List all scans (paginated)
DELETE /api/scan/{id} — Delete a scan record
"""

from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from pydantic import BaseModel, validator
from sqlalchemy.orm import Session
from typing import List, Optional
import re

from db import get_db, ScanResult
from tls_scanner import scan_tls
from quantum_validator import validate_quantum_safety
from cbom_generator import generate_cbom
from certificate_engine import generate_pqc_certificate, generate_badge_svg

router = APIRouter()


# ── Request / Response Models ─────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    port: int = 443

    @validator("target")
    def validate_target(cls, v):
        v = v.strip().lower()
        if not v:
            raise ValueError("Target cannot be empty")
        # Allow hostnames and IPs (basic validation)
        if len(v) > 253:
            raise ValueError("Target too long")
        return v

    @validator("port")
    def validate_port(cls, v):
        if not (1 <= v <= 65535):
            raise ValueError("Port must be 1–65535")
        return v


class ScanSummary(BaseModel):
    id: int
    target: str
    port: int
    tls_version: Optional[str]
    quantum_status: Optional[str]
    risk_level: Optional[str]
    risk_score: Optional[float]
    is_compliant: Optional[bool]
    scanned_at: Optional[str]
    scan_error: Optional[str]

    class Config:
        from_attributes = True


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/", summary="Scan a TLS endpoint")
async def create_scan(req: ScanRequest, db: Session = Depends(get_db)):
    """
    Full pipeline:
    1. TLS scan
    2. Quantum safety validation
    3. CBOM generation
    4. Certificate issuance
    5. Persist to database
    """

    # Step 1: TLS Scan
    scan_data = scan_tls(req.target, req.port)

    # Step 2: Quantum Validation
    validation = validate_quantum_safety(
        tls_version    = scan_data.tls_version,
        cipher_suite   = scan_data.cipher_suite,
        key_exchange   = scan_data.key_exchange,
        signature_alg  = scan_data.signature_alg,
        cert_type      = scan_data.cert_type,
        key_size       = scan_data.key_size,
        days_until_expiry = getattr(scan_data, "days_until_expiry", 365),
    )

    # Step 3: CBOM Generation
    cbom = generate_cbom(
        target        = req.target,
        port          = req.port,
        tls_version   = scan_data.tls_version,
        cipher_suite  = scan_data.cipher_suite,
        key_exchange  = scan_data.key_exchange,
        signature_alg = scan_data.signature_alg,
        cert_type     = scan_data.cert_type,
        key_size      = scan_data.key_size,
        cert_expiry   = scan_data.cert_expiry,
        cert_subject  = scan_data.cert_subject,
        cert_issuer   = scan_data.cert_issuer,
        quantum_status= validation.quantum_status,
        risk_level    = validation.risk_level,
        risk_score    = validation.risk_score,
        findings      = validation.findings,
        remediation   = validation.remediation,
        is_compliant  = validation.is_compliant,
    )

    # Step 4: Persist scan
    db_scan = ScanResult(
        target         = req.target,
        port           = req.port,
        tls_version    = scan_data.tls_version,
        cipher_suite   = scan_data.cipher_suite,
        key_exchange   = scan_data.key_exchange,
        signature_alg  = scan_data.signature_alg,
        cert_type      = scan_data.cert_type,
        key_size       = scan_data.key_size,
        cert_expiry    = scan_data.cert_expiry,
        cert_subject   = scan_data.cert_subject,
        cert_issuer    = scan_data.cert_issuer,
        cert_valid     = scan_data.cert_valid,
        quantum_status = validation.quantum_status,
        risk_level     = validation.risk_level,
        risk_score     = validation.risk_score,
        is_compliant   = validation.is_compliant,
        cbom_json      = cbom,
        remediation    = {"actions": validation.remediation},
        badge_issued   = validation.is_compliant,
        scan_error     = scan_data.error,
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    # Step 5: Generate certificate
    cert_json = generate_pqc_certificate(
        target         = req.target,
        scan_id        = db_scan.id,
        quantum_status = validation.quantum_status,
        risk_level     = validation.risk_level,
        risk_score     = validation.risk_score,
        cbom           = cbom,
    )
    badge_svg = generate_badge_svg(validation.quantum_status, req.target, validation.risk_score)

    return {
        "scan_id"         : db_scan.id,
        "target"          : req.target,
        "port"            : req.port,
        "scanned_at"      : db_scan.scanned_at.isoformat(),
        "scan_error"      : scan_data.error,

        # TLS Details
        "tls_version"     : scan_data.tls_version,
        "cipher_suite"    : scan_data.cipher_suite,
        "key_exchange"    : scan_data.key_exchange,
        "signature_alg"   : scan_data.signature_alg,
        "cert_type"       : scan_data.cert_type,
        "key_size"        : scan_data.key_size,
        "cert_expiry"     : scan_data.cert_expiry,
        "cert_subject"    : scan_data.cert_subject,
        "cert_issuer"     : scan_data.cert_issuer,
        "cert_valid"      : scan_data.cert_valid,
        "days_until_expiry": getattr(scan_data, "days_until_expiry", None),

        # Validation
        "quantum_status"  : validation.quantum_status,
        "risk_level"      : validation.risk_level,
        "risk_score"      : validation.risk_score,
        "is_compliant"    : validation.is_compliant,
        "findings"        : validation.findings,
        "remediation"     : validation.remediation,

        # Artifacts
        "cbom"            : cbom,
        "certificate"     : cert_json,
        "badge_svg"       : badge_svg,
    }


@router.get("/", summary="List all scan results")
def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    scans = db.query(ScanResult).order_by(ScanResult.scanned_at.desc()).offset(skip).limit(limit).all()
    total = db.query(ScanResult).count()
    return {
        "total" : total,
        "skip"  : skip,
        "limit" : limit,
        "items" : [_scan_to_dict(s) for s in scans],
    }


@router.get("/{scan_id}", summary="Get a specific scan result")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_to_dict(scan, full=True)


@router.delete("/{scan_id}", summary="Delete a scan record")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"deleted": scan_id}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _scan_to_dict(scan: ScanResult, full: bool = False) -> dict:
    base = {
        "id"             : scan.id,
        "target"         : scan.target,
        "port"           : scan.port,
        "scanned_at"     : scan.scanned_at.isoformat() if scan.scanned_at else None,
        "tls_version"    : scan.tls_version,
        "cipher_suite"   : scan.cipher_suite,
        "key_exchange"   : scan.key_exchange,
        "signature_alg"  : scan.signature_alg,
        "cert_type"      : scan.cert_type,
        "key_size"       : scan.key_size,
        "cert_expiry"    : scan.cert_expiry,
        "cert_subject"   : scan.cert_subject,
        "quantum_status" : scan.quantum_status,
        "risk_level"     : scan.risk_level,
        "risk_score"     : scan.risk_score,
        "is_compliant"   : scan.is_compliant,
        "badge_issued"   : scan.badge_issued,
        "scan_error"     : scan.scan_error,
    }
    if full:
        base["cbom"]       = scan.cbom_json
        base["remediation"] = scan.remediation
    return base
