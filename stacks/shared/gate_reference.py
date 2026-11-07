"""BankShield shared gate specification v1: Python reference implementation.

Implements docs/GATE_SPEC.md exactly. Go and Rust implementations in
stacks/go and stacks/rust must agree with this reference on every shared
test vector. Demo only: all signals are synthetic, no real bank data.
"""
import json
import sys

SENSITIVE = {"pay", "trf", "ben", "exp", "sec"}


def score(s):
    total = 0
    if s["hl"]:
        total += 40
    if s["mb"]:
        total += 15
    if s["dc"]:
        total += 10
    if s["rpm"] > 60:
        total += 20
    if s["rpm"] > 150:
        total += 20
    if s["cov"] > 70:
        total += 30
    if s["tv"] < 0.2 and s["rpm"] > 20:
        total += 25
    if s["ov"]:
        total += 20
    if s["np"]:
        total += 15
    if not s["dp"]:
        total += 30
    if not s["dt"]:
        total += 20
    return total


def decide(s):
    """Return A (ALLOW), C (CHALLENGE) or B (BLOCK)."""
    if s["dm"]:
        return "B"
    if s["nr"]:
        return "B"
    if not s["sk"]:
        return "B"
    value = score(s)
    if s["r"] in SENSITIVE:
        full_proof = s["pk"] and s["dp"] and s["dt"]
        if full_proof and value < 50:
            return "A"
        if value >= 80:
            return "B"
        return "C"
    if value >= 80:
        return "B"
    return "A"


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "test_vectors.json"
    with open(path) as handle:
        cases = json.load(handle)
    failures = []
    counts = {"A": 0, "C": 0, "B": 0}
    attack_allow_on_sensitive = 0
    legit_false_positives = 0
    for case in cases:
        got = decide(case["s"])
        counts[got] += 1
        if got != case["e"]:
            failures.append((case["i"], case["t"], case["e"], got))
        if case["k"] == "a" and case["s"]["r"] in SENSITIVE and got == "A":
            attack_allow_on_sensitive += 1
        if case["k"] == "l" and got != "A":
            legit_false_positives += 1
    print(f"cases={len(cases)} allow={counts['A']} challenge={counts['C']} block={counts['B']}")
    print(f"attack_allow_on_sensitive={attack_allow_on_sensitive}")
    print(f"legit_false_positives={legit_false_positives}")
    if failures:
        print(f"FAILURES={len(failures)} first={failures[:5]}")
        return 1
    if attack_allow_on_sensitive or legit_false_positives:
        print("PASS RULE VIOLATION")
        return 1
    print("ALL VECTORS PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
