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


