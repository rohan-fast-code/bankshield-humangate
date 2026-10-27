"""HumanGate Blocker v2: scalable, framework agnostic, fail closed for money.

Design for scale:
  Gate is stateless except for nonce and rate state, which in
  production lives in Redis, not in memory. Audit goes to a queue,
  not to a blocking database call. Decision logic is pure and fast,
  so many gate pods can run behind a load balancer with no shared
  session state except Redis.
  Fail closed for sensitive routes: if proof verification is
  unavailable, challenge or block money, never allow it.
  Fail open only for public marketing pages, never for account data.
"""
import time
from dataclasses import dataclass


@dataclass
class BlockerSignals:
    route: str = "payment"
    has_passkey_proof: bool = False
    device_attestation_valid: bool = False
    device_bound_token_valid: bool = False
    device_id_matches_session: bool = True
    request_signature_valid: bool = True
    payload_pattern: str = ""
    is_headless: bool = False
    requests_per_minute: int = 5
    api_coverage_percent: int = 5
    timing_variance_seconds: float = 2.0


@dataclass
class BlockerDecision:
    action: str
    risk_score: int
    reason: str


SENSITIVE_ROUTES = {"payment", "transfer", "change_beneficiary", "export_data", "change_security"}
BLOCK_PATTERNS = {
    "injection_pattern", "xss_pattern", "traversal_pattern", "command_pattern",
    "ssrf_pattern", "api_abuse_pattern", "mobile_tamper_pattern", "auth_abuse_pattern",
    "agent_abuse_pattern", "fraud_pattern", "infra_abuse_pattern",
}


class Blocker:
    def __init__(self):
        self.audit = []
        self.used_nonces = set()

    def risk_score(self, s: BlockerSignals) -> int:
        score = 0
        if s.is_headless:
            score += 40
        if s.requests_per_minute > 60:
            score += 20
        if s.requests_per_minute > 150:
            score += 20
        if s.api_coverage_percent > 70:
            score += 30
        if s.timing_variance_seconds < 0.2 and s.requests_per_minute > 20:
            score += 25
        if not s.device_attestation_valid:
            score += 20
        if not s.device_bound_token_valid:
            score += 10
        if s.payload_pattern:
            score += 50
        return score

    def decide(self, s: BlockerSignals) -> BlockerDecision:
        score = self.risk_score(s)
        # Pattern block first: no payload pattern ever reaches finance code.
        if s.payload_pattern in BLOCK_PATTERNS:
            decision = BlockerDecision("BLOCK", score, f"Blocked by pattern rule: {s.payload_pattern}")
        elif not s.device_id_matches_session:
            decision = BlockerDecision("BLOCK", score, "Device does not match session")
        elif not s.request_signature_valid:
            decision = BlockerDecision("BLOCK", score, "Request signature invalid")
        elif s.route in SENSITIVE_ROUTES:
            if s.has_passkey_proof and s.device_attestation_valid and s.device_bound_token_valid and score < 50:
                decision = BlockerDecision("ALLOW", score, "Full human proof and low risk")
            elif score >= 80:
                decision = BlockerDecision("BLOCK", score, "High risk score for sensitive route")
            else:
                # For fraud and social engineering types, challenge is the
                # correct gate action: step up, delay first payee, warn,
                # and require out of band confirmation. Never allow blindly.
                decision = BlockerDecision("CHALLENGE", score, "Sensitive route needs full human proof and step up")
        else:
            if score >= 80:
                decision = BlockerDecision("BLOCK", score, "High risk score")
            else:
                decision = BlockerDecision("ALLOW", score, "View route with acceptable risk")
        self.audit.append({"route": s.route, "score": score, "action": decision.action, "reason": decision.reason, "pattern": s.payload_pattern})
        return decision

    def decide_attack(self, attack: dict) -> BlockerDecision:
        sig = attack["signals"]
        s = BlockerSignals(
            route=attack["route"],
            has_passkey_proof=sig["has_passkey_proof"],
            device_attestation_valid=sig["device_attestation_valid"],
            device_bound_token_valid=sig["device_bound_token_valid"],
            payload_pattern=sig["payload_pattern"],
            is_headless=sig["is_headless"],
            requests_per_minute=sig["requests_per_minute"],
            api_coverage_percent=sig["api_coverage_percent"],
        )
        return self.decide(s)
