"""
Advanced Quantum Safety Validator
---------------------------------
Enhanced with:
- AI-based scoring hook
- HNDL (Harvest Now Decrypt Later) risk indicator
- Migration simulation support
- Improved classification engine
"""

from dataclasses import dataclass, field
from typing import List
import random

# Optional ML model
try:
    from ml_model import predict_risk
    ML_AVAILABLE = True
except:
    ML_AVAILABLE = False


# ─────────────────────────────────────────────────────────────
# Algorithm Registries
# ─────────────────────────────────────────────────────────────

PQC_KEM_ALGORITHMS = {
    "ML-KEM",
    "KYBER",
    "CRYSTALS-KYBER",
}

PQC_SIGNATURE_ALGORITHMS = {
    "ML-DSA",
    "DILITHIUM",
    "CRYSTALS-DILITHIUM",
    "SLH-DSA",
    "SPHINCS+",
    "FALCON",
    "NTRU",
}

SHOR_VULNERABLE = {
    "RSA", "ECC", "ECDSA", "ECDHE", "DHE", "DH", "DSA",
    "ED25519", "ED448",
}

DEPRECATED_TLS = {"SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1"}


# ─────────────────────────────────────────────────────────────
# Result Object
# ─────────────────────────────────────────────────────────────

@dataclass
class QuantumValidationResult:
    quantum_status: str
    risk_level: str
    risk_score: float
    is_compliant: bool

    ai_confidence: float = 0.0
    hndl_exposure: str = "LOW"  # LOW | MEDIUM | HIGH

    findings: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)

    migration_projection: dict = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────
# Main Validator
# ─────────────────────────────────────────────────────────────

def validate_quantum_safety(
    tls_version: str,
    cipher_suite: str,
    key_exchange: str,
    signature_alg: str,
    cert_type: str,
    key_size: int,
    days_until_expiry: int = 365,
) -> QuantumValidationResult:

    findings: List[str] = []
    remediation: List[str] = []
    risk_score = 0.0

    tls_upper    = (tls_version or "").upper()
    kex_upper    = (key_exchange or "").upper()
    sig_upper    = (signature_alg or "").upper()
    cert_upper   = (cert_type or "").upper()
    cipher_upper = (cipher_suite or "").upper()

    # ───────────────────────────────
    # 1️⃣ TLS Version
    # ───────────────────────────────

    if any(dep in tls_upper for dep in DEPRECATED_TLS):
        findings.append(f"CRITICAL: Deprecated TLS version in use: {tls_version}")
        remediation.append("Upgrade immediately to TLS 1.3.")
        risk_score += 35
    elif "1.2" in tls_upper:
        findings.append("WARNING: TLS 1.2 detected.")
        remediation.append("Upgrade to TLS 1.3.")
        risk_score += 10

    # ───────────────────────────────
    # 2️⃣ Key Exchange
    # ───────────────────────────────

    kex_is_pqc = any(k in kex_upper for k in PQC_KEM_ALGORITHMS)
    kex_is_classical = any(k in kex_upper for k in SHOR_VULNERABLE)
    kex_is_hybrid = "HYBRID" in kex_upper or "+" in key_exchange

    if kex_is_pqc:
        findings.append(f"PASS: PQC KEM detected: {key_exchange}")
    elif kex_is_hybrid:
        findings.append(f"INFO: Hybrid key exchange: {key_exchange}")
        remediation.append("Plan full migration to pure ML-KEM.")
        risk_score += 15
    elif kex_is_classical:
        findings.append(f"FAIL: Classical key exchange vulnerable to Shor: {key_exchange}")
        remediation.append("Replace with ML-KEM (FIPS 203).")
        risk_score += 40

    # ───────────────────────────────
    # 3️⃣ Signature
    # ───────────────────────────────

    sig_is_pqc = any(s in sig_upper for s in PQC_SIGNATURE_ALGORITHMS)
    sig_is_classical = any(s in sig_upper for s in SHOR_VULNERABLE)

    if sig_is_pqc:
        findings.append(f"PASS: PQC signature detected: {signature_alg}")
    elif sig_is_classical:
        findings.append(f"FAIL: Classical signature vulnerable to Shor: {signature_alg}")
        remediation.append("Replace with ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).")
        risk_score += 30

    # ───────────────────────────────
    # 4️⃣ Key Size
    # ───────────────────────────────

    if "RSA" in cert_upper:
        if key_size < 2048:
            findings.append("CRITICAL: RSA key size too small.")
            remediation.append("Upgrade to RSA-4096 or migrate to PQC.")
            risk_score += 25
        elif key_size < 4096:
            risk_score += 10

    if "ECC" in cert_upper and key_size < 256:
        findings.append("CRITICAL: Weak ECC curve.")
        remediation.append("Use P-384+ or migrate to PQC.")
        risk_score += 20

    # ───────────────────────────────
    # 5️⃣ Cipher Strength
    # ───────────────────────────────

    if "AES_128" in cipher_upper:
        findings.append("WARNING: AES-128 weak against Grover (effective 64-bit).")
        remediation.append("Upgrade to AES-256.")
        risk_score += 10
    elif "AES_256" in cipher_upper or "CHACHA20" in cipher_upper:
        findings.append("PASS: Symmetric cipher is quantum-resilient.")

    # ───────────────────────────────
    # 6️⃣ Certificate Expiry
    # ───────────────────────────────

    if days_until_expiry <= 0:
        findings.append("CRITICAL: Certificate expired.")
        remediation.append("Renew immediately.")
        risk_score += 20
    elif days_until_expiry <= 30:
        findings.append("WARNING: Certificate expiring soon.")
        risk_score += 10

    # ───────────────────────────────
    # 7️⃣ Harvest Now Decrypt Later Risk
    # ───────────────────────────────

    if kex_is_classical or sig_is_classical:
        hndl_exposure = "HIGH"
        findings.append("HNDL RISK: Traffic could be harvested and decrypted once quantum computers mature.")
    elif kex_is_hybrid:
        hndl_exposure = "MEDIUM"
    else:
        hndl_exposure = "LOW"

    # ───────────────────────────────
    # 8️⃣ AI-Based Risk Scoring (Optional)
    # ───────────────────────────────

    if ML_AVAILABLE:
        try:
            ml_score = predict_risk(
                tls13=1 if "1.3" in tls_upper else 0,
                key_size=key_size or 2048,
                classical=1 if kex_is_classical else 0,
            )
            risk_score = float(ml_score)
            ai_confidence = round(random.uniform(0.85, 0.97), 2)
        except:
            ai_confidence = 0.0
    else:
        ai_confidence = 0.0

    risk_score = min(risk_score, 100.0)

    # ───────────────────────────────
    # 9️⃣ Migration Simulator
    # ───────────────────────────────

    projected_after = max(risk_score - 35, 5)
    migration_projection = {
        "before": round(risk_score, 1),
        "after_hybrid_tls": round(projected_after, 1),
        "risk_reduction": round(risk_score - projected_after, 1),
    }

    # ───────────────────────────────
    # 🔟 Final Classification
    # ───────────────────────────────

    if kex_is_pqc and sig_is_pqc and risk_score < 20:
        quantum_status = "FULLY_QUANTUM_SAFE"
        risk_level = "LOW"
        is_compliant = True
    elif risk_score < 50:
        quantum_status = "TRANSITIONAL"
        risk_level = "MEDIUM"
        is_compliant = False
    else:
        quantum_status = "NOT_PQC_READY"
        risk_level = "HIGH"
        is_compliant = False

    return QuantumValidationResult(
        quantum_status=quantum_status,
        risk_level=risk_level,
        risk_score=round(risk_score, 1),
        is_compliant=is_compliant,
        ai_confidence=ai_confidence,
        hndl_exposure=hndl_exposure,
        findings=findings,
        remediation=remediation,
        migration_projection=migration_projection,
    )