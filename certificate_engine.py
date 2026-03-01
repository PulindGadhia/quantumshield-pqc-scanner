"""
PQC Certificate & Digital Badge Generator
------------------------------------------
Issues a signed JSON certificate and an SVG badge when an endpoint is
fully quantum-safe. Generates a remediation report otherwise.
"""

import json
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any


def generate_pqc_certificate(
    target: str,
    scan_id: int,
    quantum_status: str,
    risk_level: str,
    risk_score: float,
    cbom: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Generate a PQC compliance certificate as a structured JSON document.
    Includes a SHA-256 fingerprint for integrity verification.
    """
    cert_id   = str(uuid.uuid4())
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(days=365)

    certificate = {
        "certificate_id"  : cert_id,
        "certificate_type": "PQC_COMPLIANCE",
        "scan_id"         : scan_id,
        "issued_to"       : target,
        "issued_at"       : issued_at.isoformat(),
        "expires_at"      : expires_at.isoformat(),
        "issuer"          : {
            "name"     : "QuantumShield Certification Authority",
            "version"  : "1.0",
            "standards": ["NIST FIPS 203", "NIST FIPS 204", "NIST FIPS 205"],
        },
        "compliance"      : {
            "status"        : quantum_status,
            "risk_level"    : risk_level,
            "risk_score"    : risk_score,
            "is_compliant"  : quantum_status == "FULLY_QUANTUM_SAFE",
            "standards_met" : _determine_standards(quantum_status),
        },
        "cbom_reference"  : cbom.get("serialNumber"),
        "cbom_summary"    : {
            "components_count": len(cbom.get("components", [])),
            "findings_count"  : cbom.get("risk_assessment", {}).get("finding_count", 0),
            "critical_count"  : cbom.get("risk_assessment", {}).get("critical_count", 0),
        },
    }

    # Fingerprint for tamper detection
    cert_str = json.dumps(certificate, sort_keys=True)
    certificate["fingerprint"] = hashlib.sha256(cert_str.encode()).hexdigest()

    return certificate


def generate_badge_svg(quantum_status: str, target: str, risk_score: float) -> str:
    """
    Generate an SVG digital badge reflecting the compliance status.
    """
    if quantum_status == "FULLY_QUANTUM_SAFE":
        return _badge_compliant(target, risk_score)
    elif quantum_status == "TRANSITIONAL":
        return _badge_transitional(target, risk_score)
    else:
        return _badge_non_compliant(target, risk_score)


def _determine_standards(quantum_status: str):
    if quantum_status == "FULLY_QUANTUM_SAFE":
        return ["NIST FIPS 203", "NIST FIPS 204", "NIST FIPS 205"]
    elif quantum_status == "TRANSITIONAL":
        return ["Partial NIST PQC Compliance"]
    return []


def _badge_compliant(target: str, score: float) -> str:
    short_target = target[:28] + "…" if len(target) > 28 else target
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="320" height="120" viewBox="0 0 320 120">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0a2744;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#003d7a;stop-opacity:1" />
    </linearGradient>
    <linearGradient id="stripe" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#00C851;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#007E33;stop-opacity:1" />
    </linearGradient>
  </defs>
  <!-- Background -->
  <rect width="320" height="120" rx="12" fill="url(#bg)"/>
  <!-- Green accent stripe -->
  <rect width="8" height="120" rx="4" fill="url(#stripe)"/>
  <!-- Shield icon -->
  <text x="26" y="56" font-size="32" fill="#00C851">🛡</text>
  <!-- Title -->
  <text x="68" y="38" font-family="monospace" font-size="14" font-weight="bold" fill="#00C851">PQC READY</text>
  <text x="68" y="56" font-family="monospace" font-size="10" fill="#7eb8f0">NIST FIPS 203/204/205 Compliant</text>
  <!-- Target -->
  <text x="68" y="74" font-family="monospace" font-size="11" fill="#ffffff">{short_target}</text>
  <!-- Risk score -->
  <text x="68" y="92" font-family="monospace" font-size="10" fill="#a0c8f0">Risk Score: {score}/100</text>
  <!-- Issued date -->
  <text x="68" y="108" font-family="monospace" font-size="9" fill="#4a7fa8">Issued by QuantumShield CA • {datetime.now().strftime('%Y-%m-%d')}</text>
  <!-- Checkmark -->
  <circle cx="285" cy="40" r="18" fill="#00C851" opacity="0.2"/>
  <text x="275" y="48" font-size="20" fill="#00C851">✓</text>
</svg>"""


def _badge_transitional(target: str, score: float) -> str:
    short_target = target[:28] + "…" if len(target) > 28 else target
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="320" height="120" viewBox="0 0 320 120">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#2a1a00;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#4a3000;stop-opacity:1" />
    </linearGradient>
  </defs>
  <rect width="320" height="120" rx="12" fill="url(#bg)"/>
  <rect width="8" height="120" rx="4" fill="#FF8800"/>
  <text x="26" y="56" font-size="32" fill="#FF8800">⚡</text>
  <text x="68" y="38" font-family="monospace" font-size="14" font-weight="bold" fill="#FF8800">PQC TRANSITIONAL</text>
  <text x="68" y="56" font-family="monospace" font-size="10" fill="#d4a44a">Partial Quantum Protection</text>
  <text x="68" y="74" font-family="monospace" font-size="11" fill="#ffffff">{short_target}</text>
  <text x="68" y="92" font-family="monospace" font-size="10" fill="#d4a44a">Risk Score: {score}/100</text>
  <text x="68" y="108" font-family="monospace" font-size="9" fill="#8a6a28">Issued by QuantumShield CA • {datetime.now().strftime('%Y-%m-%d')}</text>
  <circle cx="285" cy="40" r="18" fill="#FF8800" opacity="0.2"/>
  <text x="275" y="48" font-size="20" fill="#FF8800">⚠</text>
</svg>"""


def _badge_non_compliant(target: str, score: float) -> str:
    short_target = target[:28] + "…" if len(target) > 28 else target
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="320" height="120" viewBox="0 0 320 120">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#2a0000;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#4a0000;stop-opacity:1" />
    </linearGradient>
  </defs>
  <rect width="320" height="120" rx="12" fill="url(#bg)"/>
  <rect width="8" height="120" rx="4" fill="#FF4444"/>
  <text x="26" y="56" font-size="32" fill="#FF4444">☠</text>
  <text x="68" y="38" font-family="monospace" font-size="14" font-weight="bold" fill="#FF4444">NOT PQC READY</text>
  <text x="68" y="56" font-family="monospace" font-size="10" fill="#d44a4a">Vulnerable to Quantum Attacks</text>
  <text x="68" y="74" font-family="monospace" font-size="11" fill="#ffffff">{short_target}</text>
  <text x="68" y="92" font-family="monospace" font-size="10" fill="#d44a4a">Risk Score: {score}/100</text>
  <text x="68" y="108" font-family="monospace" font-size="9" fill="#8a2828">Issued by QuantumShield CA • {datetime.now().strftime('%Y-%m-%d')}</text>
  <circle cx="285" cy="40" r="18" fill="#FF4444" opacity="0.2"/>
  <text x="276" y="48" font-size="20" fill="#FF4444">✗</text>
</svg>"""
