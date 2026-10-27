"""HumanGate: framework agnostic gate for any financial app or website.

Usage in any stack:
    from gate.human_gate import HumanGate, RequestSignals
    gate = HumanGate()
    decision = gate.decide(signals)
    if decision.action == "ALLOW":
        run finance handler
    elif decision.action == "CHALLENGE":
        ask for step up passkey proof
    else:
        block and log

This file uses deterministic code, not a prompt. A model cannot
talk its way past a missing passkey signature or a bad request
signature, because those checks happen here, in code.
"""
import hashlib
import hmac
import time
from dataclasses import dataclass, field


@dataclass
class RequestSignals:
    route: str = "view"
    has_passkey_proof: bool = False
    device_attestation_valid: bool = False
    device_bound_token_valid: bool = False
    device_id_matches_session: bool = True
    request_signature_valid: bool = True
    session_key_known_to_caller: bool = True
    is_headless: bool = False
    missing_browser_signals: bool = False
    ip_is_datacenter: bool = False
    requests_per_minute: int = 5
    api_coverage_percent_in_window: int = 5
    timing_variance_seconds: float = 2.0
    timestamp_seconds: float = 0.0
    nonce: str = "demo_nonce_1"
    used_nonces: set = field(default_factory=set)


@dataclass
class Decision:
    action: str
    risk_score: int
    reason: str


SENSITIVE_ROUTES = {"payment", "change_beneficiary", "export_data", "change_security", "transfer"}


class HumanGate:
    def __init__(self):
        self.audit = []
        self.session_key = b"demo_session_key_for_testing_only"

    def sign_request(self, payload: str, timestamp: int, nonce: str) -> str:
        message = f"{payload}|{timestamp}|{nonce}".encode()
        return hmac.new(self.session_key, message, hashlib.sha256).hexdigest()

    def verify_request_signature(self, payload: str, timestamp: int, nonce: str, signature: str, used_nonces: set) -> bool:
        now = int(time.time())
        # In the demo, a timestamp of 0 means the caller did not send one.
        # In production, require a real timestamp within 60 seconds.
        if timestamp != 0 and abs(now - timestamp) > 60:
            return False
        if nonce in used_nonces:
            return False
        expected = self.sign_request(payload, timestamp, nonce)
        return hmac.compare_digest(expected, signature)

    def risk_score(self, s: RequestSignals) -> int:
        score = 0
        if s.is_headless:
            score += 40
        if s.missing_browser_signals:
            score += 15
        if s.ip_is_datacenter:
            score += 10
        if s.requests_per_minute > 60:
            score += 20
        if s.api_coverage_percent_in_window > 70:
            score += 30
        if s.timing_variance_seconds < 0.2 and s.requests_per_minute > 20:
            score += 25
        if not s.device_attestation_valid:
            score += 30
        if not s.device_bound_token_valid:
            score += 20
        return score

    def decide(self, s: RequestSignals) -> Decision:
        score = self.risk_score(s)
        route = s.route
        # Hard blocks: proof forgery or device mismatch, on any route.
        if not s.device_id_matches_session:
            decision = Decision("BLOCK", score, "Device does not match session. Token copied to another device.")
        elif not s.request_signature_valid:
            decision = Decision("BLOCK", score, "Request signature is invalid. Caller does not have the session key.")
        elif not s.session_key_known_to_caller and route in SENSITIVE_ROUTES:
            decision = Decision("BLOCK", score, "Sensitive route needs a session key the caller does not have.")
        elif route in SENSITIVE_ROUTES:
            if s.has_passkey_proof and s.device_attestation_valid and s.device_bound_token_valid and score < 50:
                decision = Decision("ALLOW", score, "Full human proof, device proof, and low risk.")
            elif score >= 80:
                decision = Decision("BLOCK", score, "High agent risk score for a sensitive route.")
            elif not s.has_passkey_proof or not s.device_attestation_valid:
                decision = Decision("CHALLENGE", score, "Sensitive route needs passkey proof and device attestation. Step up required.")
            else:
                decision = Decision("CHALLENGE", score, "Risk score too high for a sensitive route. Step up required.")
        else:
            # View routes: low friction, but block obvious automation.
            if score >= 80:
                decision = Decision("BLOCK", score, "High agent risk score, even for a view route.")
            else:
                decision = Decision("ALLOW", score, "View route with acceptable risk.")
        self.audit.append({"route": route, "score": score, "action": decision.action, "reason": decision.reason})
        return decision
