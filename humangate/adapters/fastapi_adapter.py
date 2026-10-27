"""FastAPI adapter example. Copy this pattern into any Python web stack.

In a real app, build RequestSignals from real verified data:
passkey proof from WebAuthn verification, attestation from the
platform token, token validity from your auth service, and
request signature from the session key service. Do not trust
headers sent by the client as proof by themselves.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from gate.human_gate import HumanGate, RequestSignals

GATE = HumanGate()


def guard_payment(signals: RequestSignals):
    decision = GATE.decide(signals)
    if decision.action == "ALLOW":
        return {"allowed": True, "reason": decision.reason}
    if decision.action == "CHALLENGE":
        return {"allowed": False, "challenge": "passkey_step_up_required", "reason": decision.reason}
    return {"allowed": False, "blocked": True, "reason": decision.reason}
