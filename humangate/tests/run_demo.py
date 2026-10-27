"""Demo: human in, agents out. Run with: python3 tests/run_demo.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from gate.human_gate import HumanGate, RequestSignals
from test_human_gate import agent_headless, human_payment


def main():
    gate = HumanGate()
    cases = [
        ("Human payment, full proof", human_payment()),
        ("Agent, headless and systematic", agent_headless()),
        ("Agent, stolen token, wrong device", RequestSignals(route="payment", has_passkey_proof=False, device_attestation_valid=True, device_bound_token_valid=True, device_id_matches_session=False)),
        ("Agent, copied UI, no session key", RequestSignals(route="payment", has_passkey_proof=False, device_attestation_valid=False, device_bound_token_valid=False, session_key_known_to_caller=False, request_signature_valid=False)),
        ("Agent, API mapping in minutes", RequestSignals(route="export_data", has_passkey_proof=False, device_attestation_valid=False, device_bound_token_valid=False, requests_per_minute=200, api_coverage_percent_in_window=95, timing_variance_seconds=0.02)),
        ("Human view, low risk", RequestSignals(route="view", requests_per_minute=4, api_coverage_percent_in_window=4)),
    ]
    for name, signals in cases:
        d = gate.decide(signals)
        print(f"{name}: {d.action} score={d.risk_score} reason={d.reason}")
    print("\nAudit log:")
    for entry in gate.audit:
        print(entry)


if __name__ == "__main__":
    main()
