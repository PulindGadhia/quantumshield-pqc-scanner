"""
Dashboard Router
----------------
GET /api/dashboard/stats   — Aggregated statistics for the dashboard
GET /api/dashboard/summary — Quick status summary
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List

from db import get_db, ScanResult

router = APIRouter()


@router.get("/stats", summary="Dashboard statistics")
def get_stats(db: Session = Depends(get_db)):
    total = db.query(ScanResult).count()

    if total == 0:
        return _empty_stats()

    compliant      = db.query(ScanResult).filter(ScanResult.is_compliant == True).count()
    high_risk      = db.query(ScanResult).filter(ScanResult.risk_level == "HIGH").count()
    medium_risk    = db.query(ScanResult).filter(ScanResult.risk_level == "MEDIUM").count()
    low_risk       = db.query(ScanResult).filter(ScanResult.risk_level == "LOW").count()

    fully_qs       = db.query(ScanResult).filter(ScanResult.quantum_status == "FULLY_QUANTUM_SAFE").count()
    transitional   = db.query(ScanResult).filter(ScanResult.quantum_status == "TRANSITIONAL").count()
    not_ready      = db.query(ScanResult).filter(ScanResult.quantum_status == "NOT_PQC_READY").count()

    avg_risk       = db.query(func.avg(ScanResult.risk_score)).scalar() or 0.0

    # TLS version distribution
    tls_dist = db.query(ScanResult.tls_version, func.count(ScanResult.id)).group_by(ScanResult.tls_version).all()

    # Cert type distribution
    cert_dist = db.query(ScanResult.cert_type, func.count(ScanResult.id)).group_by(ScanResult.cert_type).all()

    # Recent high-risk scans
    recent_high = db.query(ScanResult).filter(
        ScanResult.risk_level == "HIGH"
    ).order_by(ScanResult.scanned_at.desc()).limit(5).all()

    return {
        "total_scans"        : total,
        "compliant_count"    : compliant,
        "compliance_pct"     : round((compliant / total) * 100, 1) if total else 0,
        "avg_risk_score"     : round(float(avg_risk), 1),

        "risk_distribution"  : {
            "HIGH"  : high_risk,
            "MEDIUM": medium_risk,
            "LOW"   : low_risk,
        },
        "quantum_distribution": {
            "FULLY_QUANTUM_SAFE": fully_qs,
            "TRANSITIONAL"      : transitional,
            "NOT_PQC_READY"     : not_ready,
        },
        "tls_distribution"   : dict(tls_dist),
        "cert_type_distribution": dict(cert_dist),

        "recent_high_risk"   : [
            {
                "id"            : s.id,
                "target"        : s.target,
                "risk_level"    : s.risk_level,
                "risk_score"    : s.risk_score,
                "quantum_status": s.quantum_status,
                "scanned_at"    : s.scanned_at.isoformat() if s.scanned_at else None,
            }
            for s in recent_high
        ],

        "pqc_readiness_pct"  : round((fully_qs / total) * 100, 1) if total else 0,
    }


@router.get("/summary", summary="Quick health summary")
def get_summary(db: Session = Depends(get_db)):
    total    = db.query(ScanResult).count()
    high     = db.query(ScanResult).filter(ScanResult.risk_level == "HIGH").count()
    compliant = db.query(ScanResult).filter(ScanResult.is_compliant == True).count()

    if total == 0:
        return {"status": "NO_DATA", "message": "No scans performed yet."}

    if compliant == total:
        return {"status": "ALL_COMPLIANT", "total": total, "high_risk": high}
    elif high > 0:
        return {"status": "ACTION_REQUIRED", "total": total, "high_risk": high, "compliant": compliant}
    else:
        return {"status": "TRANSITIONAL", "total": total, "high_risk": high, "compliant": compliant}


def _empty_stats():
    return {
        "total_scans"        : 0,
        "compliant_count"    : 0,
        "compliance_pct"     : 0,
        "avg_risk_score"     : 0,
        "risk_distribution"  : {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "quantum_distribution": {"FULLY_QUANTUM_SAFE": 0, "TRANSITIONAL": 0, "NOT_PQC_READY": 0},
        "tls_distribution"   : {},
        "cert_type_distribution": {},
        "recent_high_risk"   : [],
        "pqc_readiness_pct"  : 0,
    }
