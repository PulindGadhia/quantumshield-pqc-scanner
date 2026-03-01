"""
Cryptographic Bill of Materials (CBOM) Generator
--------------------------------------------------
Produces a structured, machine-readable JSON document following the
CycloneDX CBOM specification (https://cyclonedx.org/capabilities/cbom/)
adapted for quantum-safety classification.

A CBOM answers: "What cryptographic algorithms does this system use,
and are they quantum-safe?"
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def generate_cbom(
    target: str,
    port: int,
    tls_version: str,
    cipher_suite: str,
    key_exchange: str,
    signature_alg: str,
    cert_type: str,
    key_size: int,
    cert_expiry: str,
    cert_subject: str,
    cert_issuer: str,
    quantum_status: str,
    risk_level: str,
    risk_score: float,
    findings: List[str],
    remediation: List[str],
    is_compliant: bool,
) -> Dict[str, Any]:
    """
    Build and return a CycloneDX-inspired CBOM JSON document for a single
    scanned endpoint.
    """

    scan_id = str(uuid.uuid4())
    now     = datetime.now(timezone.utc).isoformat()

    # ── Component: TLS Protocol ───────────────────────────────────────────
    tls_component = {
        "bom-ref"      : f"tls-{scan_id[:8]}",
        "type"         : "protocol",
        "name"         : "TLS",
        "version"      : tls_version,
        "quantum_safe" : _is_tls_qs(tls_version),
        "nist_status"  : "CURRENT" if "1.3" in tls_version else ("DEPRECATED" if tls_version in ["TLSv1", "TLSv1.1"] else "ACCEPTABLE"),
        "details"      : {
            "cipher_suite": cipher_suite,
        }
    }

    # ── Component: Key Exchange ───────────────────────────────────────────
    kex_component = {
        "bom-ref"      : f"kex-{scan_id[:8]}",
        "type"         : "key-exchange",
        "name"         : key_exchange,
        "quantum_safe" : _is_kex_qs(key_exchange),
        "nist_status"  : _kex_nist_status(key_exchange),
        "nist_standard": _kex_nist_standard(key_exchange),
    }

    # ── Component: Signature Algorithm ───────────────────────────────────
    sig_component = {
        "bom-ref"      : f"sig-{scan_id[:8]}",
        "type"         : "signature-algorithm",
        "name"         : signature_alg,
        "quantum_safe" : _is_sig_qs(signature_alg),
        "nist_status"  : _sig_nist_status(signature_alg),
        "nist_standard": _sig_nist_standard(signature_alg),
    }

    # ── Component: Certificate ────────────────────────────────────────────
    cert_component = {
        "bom-ref"      : f"cert-{scan_id[:8]}",
        "type"         : "certificate",
        "name"         : cert_subject,
        "cert_type"    : cert_type,
        "key_size"     : key_size,
        "expiry"       : cert_expiry,
        "issuer"       : cert_issuer,
        "quantum_safe" : _is_cert_qs(cert_type, key_size),
        "key_size_assessment": _assess_key_size(cert_type, key_size),
    }

    # ── Risk Assessment ───────────────────────────────────────────────────
    risk_assessment = {
        "overall_risk"    : risk_level,
        "risk_score"      : risk_score,
        "quantum_status"  : quantum_status,
        "is_compliant"    : is_compliant,
        "findings"        : findings,
        "finding_count"   : len(findings),
        "critical_count"  : sum(1 for f in findings if "CRITICAL" in f),
        "warning_count"   : sum(1 for f in findings if "WARNING" in f),
        "pass_count"      : sum(1 for f in findings if "PASS" in f),
    }

    # ── Remediation Plan ──────────────────────────────────────────────────
    remediation_plan = {
        "required"         : not is_compliant,
        "actions"          : remediation,
        "priority"         : _remediation_priority(risk_level),
        "estimated_effort" : _estimate_effort(quantum_status),
        "reference_standards": [
            "NIST FIPS 203 - ML-KEM (Kyber)",
            "NIST FIPS 204 - ML-DSA (Dilithium)",
            "NIST FIPS 205 - SLH-DSA (SPHINCS+)",
            "NIST SP 800-208 - Recommendation for Stateful HBS Signature Schemes",
            "CISA Post-Quantum Cryptography Initiative",
        ],
    }

    # ── Assemble Full CBOM ────────────────────────────────────────────────
    cbom = {
        "bomFormat"    : "CycloneDX-CBOM",
        "specVersion"  : "1.6",
        "serialNumber" : f"urn:uuid:{scan_id}",
        "version"      : 1,
        "metadata"     : {
            "timestamp": now,
            "tool"     : {
                "name"   : "Quantum-Ready Cybersecurity Scanner",
                "version": "1.0.0",
                "vendor" : "QuantumShield",
            },
            "target": {
                "host"  : target,
                "port"  : port,
                "url"   : f"https://{target}:{port}",
            }
        },
        "components": [
            tls_component,
            kex_component,
            sig_component,
            cert_component,
        ],
        "risk_assessment"  : risk_assessment,
        "remediation_plan" : remediation_plan,
        "quantum_label"    : {
            "status"      : quantum_status,
            "badge_issued": is_compliant,
            "label_text"  : _quantum_label_text(quantum_status),
            "color_code"  : _status_color(quantum_status),
        },
    }

    return cbom


# ── Helper Functions ──────────────────────────────────────────────────────────

def _is_tls_qs(version: str) -> bool:
    return "1.3" in version

def _is_kex_qs(kex: str) -> bool:
    kex_up = kex.upper()
    return any(k in kex_up for k in ["KYBER", "ML-KEM", "NTRU", "BIKE", "HQC"])

def _is_sig_qs(sig: str) -> bool:
    sig_up = sig.upper()
    return any(s in sig_up for s in ["DILITHIUM", "ML-DSA", "FALCON", "SPHINCS", "SLH-DSA", "NTRUPRIME"])

def _is_cert_qs(cert_type: str, key_size: int) -> bool:
    return False  # RSA/ECC certs are never quantum-safe regardless of key size

def _kex_nist_status(kex: str) -> str:
    kex_up = kex.upper()
    if any(k in kex_up for k in ["KYBER", "ML-KEM"]):
        return "STANDARDIZED"
    if "HYBRID" in kex_up:
        return "TRANSITIONAL"
    return "DEPRECATED_PQC_ERA"

def _kex_nist_standard(kex: str) -> Optional[str]:
    kex_up = kex.upper()
    if any(k in kex_up for k in ["KYBER", "ML-KEM"]):
        return "FIPS 203"
    return None

def _sig_nist_status(sig: str) -> str:
    sig_up = sig.upper()
    if any(s in sig_up for s in ["DILITHIUM", "ML-DSA"]):
        return "STANDARDIZED"
    if any(s in sig_up for s in ["SPHINCS", "SLH-DSA"]):
        return "STANDARDIZED"
    if "FALCON" in sig_up:
        return "DRAFT (FIPS 206)"
    return "DEPRECATED_PQC_ERA"

def _sig_nist_standard(sig: str) -> Optional[str]:
    sig_up = sig.upper()
    if any(s in sig_up for s in ["DILITHIUM", "ML-DSA"]):
        return "FIPS 204"
    if any(s in sig_up for s in ["SPHINCS", "SLH-DSA"]):
        return "FIPS 205"
    if "FALCON" in sig_up:
        return "Draft FIPS 206"
    return None

def _assess_key_size(cert_type: str, key_size: int) -> str:
    cert_up = cert_type.upper()
    if "RSA" in cert_up:
        if key_size < 1024: return "CRITICALLY_WEAK"
        if key_size < 2048: return "WEAK"
        if key_size < 4096: return "ACCEPTABLE_SHORT_TERM"
        return "STRONG_SHORT_TERM"
    if "ECC" in cert_up:
        if key_size < 224: return "WEAK"
        if key_size < 384: return "ACCEPTABLE"
        return "STRONG"
    return "UNKNOWN"

def _remediation_priority(risk_level: str) -> str:
    return {"HIGH": "IMMEDIATE (< 30 days)", "MEDIUM": "SHORT-TERM (< 6 months)", "LOW": "PLANNED (< 2 years)"}.get(risk_level, "UNKNOWN")

def _estimate_effort(quantum_status: str) -> str:
    return {
        "NOT_PQC_READY"    : "HIGH — Full cryptographic inventory + algorithm migration required",
        "TRANSITIONAL"     : "MEDIUM — Complete migration from hybrid to pure PQC",
        "FULLY_QUANTUM_SAFE": "LOW — Monitoring and certificate renewal only",
    }.get(quantum_status, "UNKNOWN")

def _quantum_label_text(status: str) -> str:
    return {
        "FULLY_QUANTUM_SAFE": "✓ PQC Ready — NIST FIPS 203/204/205 Compliant",
        "TRANSITIONAL"      : "⚠ PQC Transitional — Partial Quantum Protection",
        "NOT_PQC_READY"     : "✗ Not PQC Ready — Vulnerable to Quantum Attacks",
    }.get(status, "UNKNOWN")

def _status_color(status: str) -> str:
    return {
        "FULLY_QUANTUM_SAFE": "#00C851",
        "TRANSITIONAL"      : "#FF8800",
        "NOT_PQC_READY"     : "#FF4444",
    }.get(status, "#888888")
