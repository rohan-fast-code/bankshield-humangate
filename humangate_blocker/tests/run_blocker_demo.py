"""Demo: human in, 120 attacks out. Run with: python3 tests/run_blocker_demo.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from gate.blocker import Blocker, BlockerSignals


def main():
    gate = Blocker()
    human = BlockerSignals(route="payment", has_passkey_proof=True, device_attestation_valid=True, device_bound_token_valid=True, payload_pattern="", requests_per_minute=3, api_coverage_percent=5)
    print("Human payment:", gate.decide(human))
    # Show first 5 attacks as examples, full test covers all 120.
    import json
    catalog = json.loads((Path(__file__).resolve().parent.parent / "attacks_catalog.json").read_text())
    for attack in catalog[:5]:
        print(attack["id"], attack["name"], gate.decide_attack(attack))


if __name__ == "__main__":
    main()
