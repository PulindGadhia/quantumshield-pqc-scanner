<<<<<<< HEAD
# QuantumShield — Quantum-Ready Cybersecurity for Future-Safe Banking

> **Hackathon Project** | PQC Scanner + CBOM Generator + Quantum Safety Validator

A complete, working system that scans public TLS endpoints, generates a
**Cryptographic Bill of Materials (CBOM)**, validates quantum safety against
**NIST FIPS 203/204/205** standards, and issues digital compliance badges.

---

## 🏗 Project Structure

```
quantum-cbom/
├── backend/
│   ├── main.py                      # FastAPI app entry point
│   ├── requirements.txt
│   ├── database/
│   │   └── db.py                    # SQLite schema + ORM models
│   ├── routers/
│   │   ├── scan.py                  # POST/GET /api/scan/
│   │   ├── cbom.py                  # GET /api/cbom/
│   │   ├── certificates.py          # GET /api/certificates/
│   │   └── dashboard.py             # GET /api/dashboard/stats
│   └── services/
│       ├── tls_scanner.py           # TLS handshake + cert parsing
│       ├── quantum_validator.py     # PQC compliance engine
│       ├── cbom_generator.py        # CycloneDX CBOM builder
│       └── certificate_engine.py   # Badge + cert issuer
├── frontend/
│   └── index.html                   # Single-file React dashboard
├── scripts/
│   └── demo.py                      # Hackathon demo script
└── docs/
    └── sample_scan_output.json      # Example output
```

---

## ⚡ Quick Start

### Prerequisites

- Python 3.9+
- pip

### 1. Install Backend Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Start the Backend

```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be live at:
- **API**: http://localhost:8000
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### 3. Open the Frontend

Open `frontend/index.html` in your browser directly, or serve it:

```bash
# Using Python
cd frontend
python -m http.server 5500

# Then open: http://localhost:5500
```

> **Note**: The frontend connects to `http://localhost:8000/api` by default.

### 4. Run a Demo Scan

```bash
cd scripts
python demo.py

# Scan a specific target
python demo.py --target your-bank.com --port 443
```

---

## 🔌 API Reference

### Scan an endpoint
```http
POST /api/scan/
Content-Type: application/json

{
  "target": "google.com",
  "port": 443
}
```

### Get scan history
```http
GET /api/scan/?skip=0&limit=50
```

### Get CBOM for a scan
```http
GET /api/cbom/{scan_id}
```

### Export CBOM as JSON file
```http
GET /api/cbom/{scan_id}/export
```

### Get digital badge (SVG)
```http
GET /api/certificates/{scan_id}/badge
```

### Dashboard statistics
```http
GET /api/dashboard/stats
```

---

## 🧪 Test Targets

| Target | Expected Result | Notes |
|---|---|---|
| `cloudflare.com` | TLSv1.3, HIGH risk | Classical ECDHE/ECDSA |
| `google.com` | TLSv1.3, HIGH risk | ECC cert, ECDHE kex |
| `github.com` | TLSv1.3, HIGH risk | RSA cert variant |
| `mozilla.org` | TLSv1.3, HIGH risk | ECC-256 cert |
| `expired.badssl.com` | HIGH risk | Expired certificate |
| `tls-v1-2.badssl.com` | HIGH risk | TLS 1.2 only |

> **Note**: All currently deployed public websites use classical cryptography.
> True FULLY_QUANTUM_SAFE status requires ML-KEM/ML-DSA which is not yet
> widely deployed (expected 2025–2026). The scanner correctly identifies
> all current sites as NOT_PQC_READY.

---

## 🔐 Quantum Safety Classification

| Status | Criteria |
|---|---|
| ✓ FULLY_QUANTUM_SAFE | ML-KEM key exchange + ML-DSA/SLH-DSA signatures + AES-256 |
| ⚠ TRANSITIONAL | Hybrid classical+PQC, or PQC signatures only |
| ✗ NOT_PQC_READY | RSA, ECC, ECDHE, DHE — all classical algorithms |

### NIST PQC Standards (August 2024)

| Algorithm | FIPS | Type | Replaces |
|---|---|---|---|
| ML-KEM (Kyber) | FIPS 203 | Key Encapsulation | ECDHE, RSA-KEM |
| ML-DSA (Dilithium) | FIPS 204 | Digital Signature | ECDSA, RSA-PSS |
| SLH-DSA (SPHINCS+) | FIPS 205 | Digital Signature | ECDSA (stateless) |

---

## 📊 Risk Scoring

| Factor | Max Points |
|---|---|
| Deprecated TLS (1.0/1.1) | +35 |
| Classical key exchange (ECDHE/RSA) | +40 |
| Classical signature (ECDSA/RSA) | +30 |
| Weak cipher (RC4/3DES/NULL) | +30 |
| RSA key < 2048 bits | +25 |
| Expired certificate | +20 |
| AES-128 (half security post-quantum) | +10 |
| TLS 1.2 (not 1.3) | +10 |

---

## ⚠️ Security Limitations

1. **Public TLS only**: Scans the TLS handshake layer. Internal application
   cryptography, database encryption, and key management are NOT assessed.

2. **Network reachability**: Targets must be reachable from the scanner host.
   Internal banking systems require deploying this scanner within the network.

3. **Certificate validation**: Scans proceed even with self-signed or invalid
   certificates (with a warning), to maximize coverage.

4. **No traffic interception**: Only TLS metadata is analyzed; no application
   data is accessed or logged.

5. **Rate limiting**: Be mindful of scan frequency against production systems.

6. **False negatives**: Servers with custom TLS stacks or non-standard
   cipher names may not be classified correctly.

---

## 🚀 Future Enhancements

1. **Nmap integration** — Port discovery to auto-identify TLS endpoints
2. **Internal network scanning** — Agent-based scanning for intranet systems
3. **CI/CD pipeline plugin** — GitHub Actions / Jenkins integration
4. **Certificate chain analysis** — Full chain PQC validation
5. **Historical trending** — Track migration progress over time
6. **Email/Slack alerts** — Notify on expiring certs or new vulnerabilities
7. **SBOM integration** — Link CBOM to software bill of materials
8. **Multi-tenant** — Separate dashboards per business unit
9. **Compliance reports** — FFIEC, ECB, SOC2 formatted PDF exports
10. **liboqs integration** — Actual PQC handshake testing with Open Quantum Safe

---

## 🎯 Demo Script for Presentation

```
1. Open dashboard → show 0 scans (fresh install)

2. Go to "New Scan" → scan google.com
   → Show: TLSv1.3, ECDHE, ECC-256
   → Show: NOT PQC READY badge
   → Show: Findings (2 FAIL, 1 WARNING)
   → Show: Remediation steps (migrate to ML-KEM, ML-DSA)

3. Scan cloudflare.com
   → Compare results side-by-side

4. Navigate to CBOM Registry
   → Show CycloneDX-format JSON
   → Export button → download CBOM.json

5. Navigate to Dashboard
   → Show risk distribution charts
   → Show % PQC Ready (0% — expected for current internet)
   → Show high-risk targets list

6. Navigate to PQC Standards
   → Explain NIST FIPS 203/204/205 table
   → Explain the banking compliance context

7. Click SVG badge → show NOT READY badge
   → Explain: badge would be green once migrated to PQC

8. Show API docs at http://localhost:8000/docs
   → Live demo of POST /api/scan/
```

---

## 📚 References

- [NIST FIPS 203 - ML-KEM](https://doi.org/10.6028/NIST.FIPS.203)
- [NIST FIPS 204 - ML-DSA](https://doi.org/10.6028/NIST.FIPS.204)
- [NIST FIPS 205 - SLH-DSA](https://doi.org/10.6028/NIST.FIPS.205)
- [CISA Post-Quantum Cryptography Initiative](https://www.cisa.gov/quantum)
- [CycloneDX CBOM Specification](https://cyclonedx.org/capabilities/cbom/)
- [Open Quantum Safe (liboqs)](https://openquantumsafe.org/)
- [NIST SP 800-208](https://doi.org/10.6028/NIST.SP.800-208)
=======
# 🔐 QuantumShield — AI-Powered PQC Security Scanner

QuantumShield is a Quantum-Ready TLS Security Scanner designed to evaluate public TLS endpoints against NIST Post-Quantum Cryptography (PQC) standards (FIPS 203/204/205).

It analyzes TLS configuration, certificate metadata, key exchange algorithms, and cryptographic strength to determine quantum readiness and compliance posture.

---

## 🚀 Features

- 🔍 TLS 1.2 / 1.3 Scanner
- 🧾 Certificate Deep Parsing
- ⚛ Post-Quantum Readiness Classification
- 🤖 AI-Based Risk Scoring
- 🛡 Harvest-Now-Decrypt-Later (HNDL) Risk Detection
- 📦 CBOM (Cryptographic Bill of Materials) Generation
- 📊 Migration Simulator (Before vs After Hybrid TLS)
- 🎯 Risk Level Classification (LOW / MEDIUM / HIGH)

---

## 🏛 NIST Standards Supported

- FIPS 203 — ML-KEM (Kyber)
- FIPS 204 — ML-DSA (Dilithium)
- FIPS 205 — SLH-DSA (SPHINCS+)

---

## 🛠 Installation

### 1️⃣ Clone Repository
git clone https://github.com/PulindGadhia/quantumshield-pqc-scanner.git

cd quantumshield-pqc-scanner


### 2️⃣ Create Virtual Environment

Windows:

python -m venv venv
venv\Scripts\activate


Mac/Linux:

python3 -m venv venv
source venv/bin/activate


### 3️⃣ Install Dependencies

pip install -r requirements.txt


### 4️⃣ Run Server

uvicorn main:app --reload


---

## 🌐 Open Application

Swagger Docs:

---

## 🌐 Open Application

Swagger Docs:
http://127.0.0.1:8000/docs


Frontend:

http://127.0.0.1:8000/


---

## 📊 Sample Scan Request

POST /api/scan/

{
"target": "google.com",
"port": 443
}


---

## 🧠 AI Risk Intelligence

QuantumShield integrates AI-based scoring to:
- Predict risk level
- Provide confidence score
- Estimate migration risk reduction

---

## ⚠ Security Limitations

- Only scans public TLS layer
- Does not inspect internal cryptographic implementations
- Requires target to be publicly reachable

---

## 👨‍💻 Author

Pulind Gadhia  
CSE (AI & ML)  
Quantum Security Enthusiast

---

## 📜 License

MIT License


>>>>>>> 89f013112887b09f86156120086294888147d522
