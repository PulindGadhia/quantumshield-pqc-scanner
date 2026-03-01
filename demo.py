#!/usr/bin/env python3
"""
QuantumShield Demo Script
--------------------------
Runs a series of predefined TLS scans against public targets and
pretty-prints the results. Ideal for hackathon presentations.

Usage:
    python demo.py                  # Scan all demo targets
    python demo.py --target google.com
    python demo.py --api http://localhost:8000
"""

import argparse
import json
import time
import requests
from datetime import datetime

API = "http://localhost:8000/api"

DEMO_TARGETS = [
    ("google.com",       443, "Google — industry-leading TLS config"),
    ("cloudflare.com",   443, "Cloudflare — aggressive TLS 1.3 deployment"),
    ("github.com",       443, "GitHub — typical enterprise setup"),
    ("expired.badssl.com", 443, "BadSSL — expired certificate test"),
    ("mozilla.org",      443, "Mozilla — open standards leader"),
]

CYAN  = "\033[96m"
GREEN = "\033[92m"
RED   = "\033[91m"
YELLOW= "\033[93m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
RESET = "\033[0m"

def color_status(status):
    if status == "FULLY_QUANTUM_SAFE":
        return f"{GREEN}✓ FULLY QUANTUM SAFE{RESET}"
    if status == "TRANSITIONAL":
        return f"{YELLOW}⚠ TRANSITIONAL{RESET}"
    return f"{RED}✗ NOT PQC READY{RESET}"

def color_risk(level):
    c = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}.get(level, "")
    return f"{c}{level}{RESET}"

def print_banner():
    print(f"""
{BOLD}{CYAN}
╔══════════════════════════════════════════════════════════════╗
║         QuantumShield — PQC Cybersecurity Scanner            ║
║         Hackathon Demo — NIST FIPS 203/204/205              ║
╚══════════════════════════════════════════════════════════════╝
{RESET}""")

def print_scan_result(result):
    target = result.get("target", "?")
    port   = result.get("port", 443)

    print(f"\n  {BOLD}► {target}:{port}{RESET}")
    print(f"  {'─' * 55}")
    print(f"  {'TLS Version':<22} {result.get('tls_version','—')}")
    print(f"  {'Cipher Suite':<22} {result.get('cipher_suite','—')}")
    print(f"  {'Key Exchange':<22} {result.get('key_exchange','—')}")
    print(f"  {'Cert Type':<22} {result.get('cert_type','—')} ({result.get('key_size',0)} bits)")
    print(f"  {'Cert Expiry':<22} {result.get('cert_expiry','—')} ({result.get('days_until_expiry','?')} days)")
    print(f"  {'Signature Alg':<22} {result.get('signature_alg','—')}")
    print()
    print(f"  {'Quantum Status':<22} {color_status(result.get('quantum_status','?'))}")
    print(f"  {'Risk Level':<22} {color_risk(result.get('risk_level','?'))}")
    print(f"  {'Risk Score':<22} {result.get('risk_score', 0)}/100")
    print(f"  {'Badge Issued':<22} {'🏅 Yes' if result.get('is_compliant') else '✗ No'}")

    findings = result.get("findings", [])
    if findings:
        print(f"\n  {DIM}Key Findings:{RESET}")
        for f in findings[:4]:
            prefix = f[:4]
            c = RED if "CRIT" in f else YELLOW if "WARN" in f else GREEN if "PASS" in f else CYAN
            print(f"    {c}• {f[:90]}{RESET}")

    if result.get("scan_error"):
        print(f"\n  {YELLOW}Note: {result['scan_error'][:80]}{RESET}")

    print()

def run_demo(api_base, targets):
    print_banner()
    print(f"{DIM}API: {api_base}{RESET}")
    print(f"{DIM}Timestamp: {datetime.now().isoformat()}{RESET}\n")

    # Check API health
    try:
        r = requests.get(f"{api_base.rstrip('/api')}/", timeout=5)
        print(f"  {GREEN}✓ Backend API online{RESET}")
    except Exception:
        print(f"  {RED}✗ Cannot reach backend at {api_base}{RESET}")
        print(f"  {DIM}Start the backend: cd backend && uvicorn main:app --reload{RESET}\n")
        return

    results = []
    for target, port, desc in targets:
        print(f"\n  {CYAN}Scanning: {target}:{port}{RESET}  {DIM}# {desc}{RESET}")
        print(f"  {DIM}Please wait...{RESET}", end="", flush=True)

        try:
            r = requests.post(
                f"{api_base}/scan/",
                json={"target": target, "port": port},
                timeout=30,
            )
            result = r.json()
            print(f"\r  {GREEN}✓ Done{RESET}          ")
            print_scan_result(result)
            results.append(result)
        except requests.exceptions.Timeout:
            print(f"\r  {YELLOW}⚠ Timeout — host may be unreachable{RESET}")
        except Exception as e:
            print(f"\r  {RED}✗ Error: {e}{RESET}")

        time.sleep(1)  # Brief pause between scans

    # Summary
    if results:
        total    = len(results)
        pqc_ok   = sum(1 for r in results if r.get("quantum_status") == "FULLY_QUANTUM_SAFE")
        high_risk = sum(1 for r in results if r.get("risk_level") == "HIGH")
        avg_score = sum(r.get("risk_score", 0) for r in results) / total

        print(f"""
{BOLD}{CYAN}══════════════ SUMMARY ══════════════{RESET}
  Targets Scanned  : {total}
  PQC Ready        : {GREEN}{pqc_ok}/{total}{RESET}
  High Risk        : {RED}{high_risk}{RESET}
  Avg Risk Score   : {YELLOW}{avg_score:.1f}/100{RESET}

  {DIM}Full dashboard: http://localhost:5500/frontend/index.html{RESET}
  {DIM}API docs: http://localhost:8000/docs{RESET}
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QuantumShield Demo Scanner")
    parser.add_argument("--api", default=API, help="Backend API base URL")
    parser.add_argument("--target", help="Single target to scan")
    parser.add_argument("--port", type=int, default=443)
    args = parser.parse_args()

    api_base = args.api

    if args.target:
        targets = [(args.target, args.port, "Custom target")]
    else:
        targets = DEMO_TARGETS

    run_demo(api_base, targets)
