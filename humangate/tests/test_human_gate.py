"""Gate tests. Run with: python3 tests/test_human_gate.py"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from gate.human_gate import HumanGate, RequestSignals


def human_payment():
    return RequestSignals(
        route="payment",
        has_passkey_proof=True,
        device_attestation_valid=True,
        device_bound_token_valid=True,
        device_id_matches_session=True,
        request_signature_valid=True,
        session_key_known_to_caller=True,
        requests_per_minute=3,
        api_coverage_percent_in_window=5,
        timing_variance_seconds=2.0,
    )


def agent_headless():
    return RequestSignals(
        route="payment",
        has_passkey_proof=False,
        device_attestation_valid=False,
        device_bound_token_valid=False,
        is_headless=True,
        missing_browser_signals=True,
        ip_is_datacenter=True,
        requests_per_minute=120,
        api_coverage_percent_in_window=90,
        timing_variance_seconds=0.05,
    )


def main():
    gate = HumanGate()
    assert gate.decide(human_payment()).action == "ALLOW", "Human payment should be allowed"
    assert gate.decide(agent_headless()).action == "BLOCK", "Headless agent payment should be blocked"
    stolen = human_payment()
    stolen.device_id_matches_session = False
    stolen.has_passkey_proof = False
    assert gate.decide(stolen).action == "BLOCK", "Stolen token on another device should be blocked"
    forged = human_payment()
    forged.request_signature_valid = False
    assert gate.decide(forged).action == "BLOCK", "Forged signature should be blocked"
    no_proof = human_payment()
    no_proof.has_passkey_proof = False
    assert gate.decide(no_proof).action == "CHALLENGE", "Payment without passkey should be challenged, not allowed"
    view = RequestSignals(route="view", requests_per_minute=5, api_coverage_percent_in_window=5)
    # View with no proofs but low risk is allowed in this design.
    # Money routes are where proof is mandatory.
    assert gate.decide(view).action in ("ALLOW", "CHALLENGE"), "Low risk view should not be hard blocked"
    # Request signature replay check
    payload = "pay:10000:payee_token"
    ts = int(time.time())
    sig = gate.sign_request(payload, ts, "nonce_123")
    assert gate.verify_request_signature(payload, ts, "nonce_123", sig, set()) is True
    assert gate.verify_request_signature(payload, ts, "nonce_123", sig, {"nonce_123"}) is False, "Reused nonce must fail"
    print("All HumanGate tests passed.")
    print("Audit entries:", len(gate.audit))


if __name__ == "__main__":
    main()
