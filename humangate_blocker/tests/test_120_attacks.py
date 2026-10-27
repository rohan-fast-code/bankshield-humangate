"""Test 120 attacks against the blocker. Run with: python3 tests/test_120_attacks.py

Pass rule: no attack simulation on a sensitive route may be ALLOWED.
BLOCK is best. CHALLENGE is also a pass, because it stops blind
money movement and forces step up, delay, warning, or out of band
confirmation. That distinction is honest: social engineering and
insider types cannot be fully blocked by a gate alone, they must
be challenged and alerted, with human and server layers behind.
"""
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from gate.blocker import Blocker


def main():
    catalog_path = Path(__file__).resolve().parent.parent / "attacks_catalog.json"
    with open(catalog_path, "r", encoding="utf-8") as f:
        catalog = json.load(f)
    print(f"Total attacks in catalog: {len(catalog)}")
    assert len(catalog) >= 100, "Catalog must contain at least 100 attacks"
    blocker = Blocker()
    results = Counter()
    failures = []
    by_category = {}
    for attack in catalog:
        decision = blocker.decide_attack(attack)
        results[decision.action] += 1
        by_category.setdefault(attack["category"], Counter())[decision.action] += 1
        if decision.action == "ALLOW":
            failures.append((attack["id"], attack["name"], decision))
    print("\nBy category:")
    for category, counts in by_category.items():
        print(f"  {category}: {dict(counts)}")
    print("\nOverall:", dict(results))
    print("Blocked or challenged:", results["BLOCK"] + results["CHALLENGE"], "out of", len(catalog))
    print("Allowed (must be zero):", results["ALLOW"])
    if failures:
        print("\nFAILURES:")
        for attack_id, name, decision in failures:
            print(attack_id, name, decision)
        return 1
    print("\nPASS: No attack simulation was allowed on a sensitive route.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
