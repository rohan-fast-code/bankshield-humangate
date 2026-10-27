"""Generate a 120 attack catalog for defensive testing only.

Each entry is a high level attack type, not a working exploit.
Test signals are synthetic markers, for example injection_pattern,
not real payloads against a real bank. The point is to prove the
gate blocks or challenges every type, not to teach an exploit.
"""
import json
from pathlib import Path

GROUPS = [
    ("Web Application", [
        "Broken Access Control", "Cryptographic Failure", "Injection Attack",
        "Insecure Design", "Security Misconfiguration", "Vulnerable And Outdated Components",
        "Identification And Authentication Failure", "Software And Data Integrity Failure",
        "Security Logging And Monitoring Failure", "Server Side Request Forgery",
        "Stored Cross Site Scripting", "Reflected Cross Site Scripting",
        "Cross Site Request Forgery", "Clickjacking", "Open Redirect",
        "Directory Traversal", "File Inclusion", "Command Injection",
        "LDAP Injection", "XML External Entity Attack",
    ]),
    ("API", [
        "Broken Object Level Authorization", "Broken User Authentication API",
        "Excessive Data Exposure", "Lack Of Rate Limiting API",
        "Broken Function Level Authorization", "Mass Assignment API",
        "Security Misconfiguration API", "Injection API", "Improper Inventory Management",
        "Unsafe Consumption Of APIs", "API Enumeration", "API Token Leakage",
        "API Replay Attack", "API Version Abuse", "GraphQL Abuse",
    ]),
    ("Mobile Application", [
        "Improper Platform Usage", "Insecure Data Storage", "Insecure Communication Mobile",
        "Insecure Authentication Mobile", "Insufficient Cryptography Mobile",
        "Insecure Authorization Mobile", "Client Code Quality Issue", "Code Tampering",
        "Reverse Engineering Mobile", "Extraneous Functionality", "Root And Jailbreak Bypass",
        "Overlay Attack", "Keylogging Mobile", "Screen Capture Attack", "Sideloaded APK Attack",
    ]),
    ("Authentication And Session", [
        "Credential Stuffing", "Brute Force Password", "Password Spraying",
        "Session Hijacking", "Session Fixation", "Token Theft",
        "OTP Interception SMS", "SIM Swap Attack", "Push Fatigue Attack",
        "MFA Bypass", "Passkey Downgrade Attack", "Account Enumeration",
        "Password Reuse Attack", "Cookie Theft", "Refresh Token Abuse",
    ]),
    ("AI Agent", [
        "Prompt Injection Direct", "Indirect Prompt Injection", "Tool Poisoning",
        "Excessive Agency", "System Prompt Leakage", "Model Extraction",
        "Training Data Poisoning", "RAG Poisoning", "Vector Embedding Attack",
        "Unbounded Consumption", "Agent Tool Misuse", "Filesystem Capability Laundering",
        "MCP Server Abuse", "Agent Memory Leakage", "Agent Collusion",
        "Model Jailbreak", "Data Exfiltration Via Agent", "Agent Replay Attack",
        "Shadow AI Data Leak", "AI Reverse Engineering REA Style",
    ]),
    ("Banking Fraud And Transaction", [
        "Phishing Bank", "Vishing Call Fraud", "Smishing SMS Fraud",
        "Authorized Push Payment Scam", "Mule Account Transfer",
        "First Time Beneficiary Fraud", "Cross Border Fraud",
        "Card Not Present Fraud", "Card Skimming And Clone", "NFC Relay Attack",
        "Transaction Hijacking", "Man In Browser Attack", "Man In Middle Attack",
        "Synthetic Identity Fraud", "Account Opening Fraud",
    ]),
    ("Infrastructure Supply Chain And Insider", [
        "Supply Chain Package Compromise", "Dependency Confusion", "Malicious SDK",
        "Insider Data Theft", "Privilege Escalation Internal", "Cloud Misconfiguration",
        "Secrets In Repository", "CI Pipeline Abuse", "Application Layer DDoS",
        "Network DDoS", "DNS Hijacking", "Ransomware Device", "Ransomware Server",
        "Data Breach Exfiltration", "Insider Agent Misuse", "Third Party Vendor Breach",
        "Log Tampering", "Backup Theft", "Physical Device Theft", "Malicious Browser Extension",
    ]),
]

# Signal templates per group. These are synthetic test signals.
# payload_pattern is a marker name, not a real exploit string.
TEMPLATES = {
    "Web Application": {"route": "payment", "payload_pattern": "injection_pattern", "has_passkey_proof": False, "device_attestation_valid": False, "device_bound_token_valid": False, "is_headless": False, "requests_per_minute": 10, "api_coverage_percent": 10},
    "API": {"route": "payment", "payload_pattern": "api_abuse_pattern", "has_passkey_proof": False, "device_attestation_valid": False, "device_bound_token_valid": False, "is_headless": True, "requests_per_minute": 120, "api_coverage_percent": 90},
    "Mobile Application": {"route": "payment", "payload_pattern": "mobile_tamper_pattern", "has_passkey_proof": False, "device_attestation_valid": False, "device_bound_token_valid": False, "is_headless": False, "requests_per_minute": 20, "api_coverage_percent": 20},
    "Authentication And Session": {"route": "payment", "payload_pattern": "auth_abuse_pattern", "has_passkey_proof": False, "device_attestation_valid": False, "device_bound_token_valid": False, "is_headless": True, "requests_per_minute": 200, "api_coverage_percent": 10},
    "AI Agent": {"route": "payment", "payload_pattern": "agent_abuse_pattern", "has_passkey_proof": False, "device_attestation_valid": False, "device_bound_token_valid": False, "is_headless": True, "requests_per_minute": 150, "api_coverage_percent": 95},
    "Banking Fraud And Transaction": {"route": "payment", "payload_pattern": "fraud_pattern", "has_passkey_proof": False, "device_attestation_valid": False, "device_bound_token_valid": True, "is_headless": False, "requests_per_minute": 5, "api_coverage_percent": 5},
    "Infrastructure Supply Chain And Insider": {"route": "payment", "payload_pattern": "infra_abuse_pattern", "has_passkey_proof": False, "device_attestation_valid": False, "device_bound_token_valid": False, "is_headless": True, "requests_per_minute": 50, "api_coverage_percent": 30},
}

LAYERS = {
    "Web Application": "Gate pattern block plus server input validation plus output encoding",
    "API": "Gate plus server authorization check per object plus rate limit plus token binding",
    "Mobile Application": "Gate plus device attestation plus app integrity plus secure storage plus certificate pinning",
    "Authentication And Session": "Gate plus passkey plus device binding plus short lived tokens plus risk step up",
    "AI Agent": "Gate plus AgentGuard plus narrow tools plus human approval plus audit log",
    "Banking Fraud And Transaction": "Gate plus transaction signature bound to amount and payee plus first payee delay plus risk warning plus out of band confirmation",
    "Infrastructure Supply Chain And Insider": "Gate plus signed artifacts plus secret scanning plus least privilege plus audit plus backup encryption",
}


def main():
    catalog = []
    attack_id = 1
    for group, names in GROUPS:
        template = TEMPLATES[group]
        for name in names:
            entry = {
                "id": attack_id,
                "name": name,
                "category": group,
                "route": template["route"],
                "signals": template,
                "expected": "BLOCK_OR_CHALLENGE",
                "mitigation_layers": LAYERS[group],
                "note": "Defensive test signal only. Gate must never allow this simulation on a sensitive route.",
            }
            catalog.append(entry)
            attack_id += 1
    out = Path(__file__).resolve().parent / "attacks_catalog.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)
    print(f"Catalog generated: {len(catalog)} attacks")
    for group, names in GROUPS:
        print(group, len(names))


if __name__ == "__main__":
    main()
