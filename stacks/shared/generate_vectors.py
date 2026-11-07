"""Generate the shared BankShield gate test vectors (spec v1).

Fixed seed, so regeneration is deterministic. The scenario templates in
this file define the expected decision for every case; the Python, Go and
Rust implementations are tested against these expectations. The generator
cross checks every case against the Python reference implementation of
the specification and refuses to write a file that contains a mismatch,
an attack ALLOW on a sensitive route, or a legitimate false positive.

Demo only: all signals are synthetic, no real bank data.

Run: python3 generate_vectors.py
Writes: test_vectors.json next to this file (compact encoding, short
field names, booleans as 0/1, decisions as A/C/B, group codes).
"""
import json
import os
import random
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gate_reference import decide, SENSITIVE  # noqa: E402

SEED = 20261107
rng = random.Random(SEED)

SENS = ["pay", "trf", "ben", "exp", "sec"]
NONSENS = ["view", "login", "prof"]


def base(route):
    return {
        "r": route, "pk": 1, "dp": 1, "dt": 1, "sk": 1, "nr": 0, "dm": 0,
        "hl": 0, "mb": 0, "dc": 0, "rpm": rng.randint(4, 25),
        "cov": rng.randint(2, 20), "tv": round(rng.uniform(0.7, 3.5), 2),
        "ov": 0, "np": 0, "amt": rng.randint(500, 80000),
    }


def vary(s, **kw):
    s.update(kw)
    return s


# ---- Attack and fraud scenario templates. Each returns (signals, expected).

def t_device_mismatch(rng):
    s = base(rng.choice(SENS))
    return vary(s, dm=1), "B"


def t_stolen_token_wrong_device(rng):
    s = base(rng.choice(["pay", "trf", "sec"]))
    return vary(s, dm=1, dt=1, dc=rng.randint(0, 1)), "B"


def t_session_hijack(rng):
    s = base(rng.choice(SENS))
    if rng.random() < 0.5:
        vary(s, dm=1, mb=1)
    else:
        vary(s, sk=0, dc=1)
    return s, "B"


def t_nonce_replay(rng):
    s = base(rng.choice(SENS + ["login"]))
    return vary(s, nr=1), "B"


def t_signature_invalid(rng):
    s = base(rng.choice(SENS + ["login"]))
    return vary(s, sk=0), "B"


def t_signature_reused_changed(rng):
    s = base(rng.choice(["pay", "trf"]))
    return vary(s, sk=0, np=1, amt=rng.randint(90000, 900000)), "B"


def t_headless_full_combo(rng):
    s = base(rng.choice(SENS))
    return vary(s, hl=1, dp=0, dt=0), "B"  # score 90


def t_datacenter_headless_noproof(rng):
    s = base(rng.choice(SENS))
    return vary(s, hl=1, dc=1, dp=0, dt=0), "B"  # score 100


def t_probing_then_payment(rng):
    s = base(rng.choice(["pay", "trf"]))
    return vary(s, hl=1, cov=rng.randint(78, 98), rpm=rng.randint(90, 140),
                tv=round(rng.uniform(0.02, 0.15), 2)), "B"  # score 95


def t_burst_high_rate(rng):
    s = base(rng.choice(SENS))
    style = rng.random()
    if style < 0.5:
        vary(s, hl=1, rpm=rng.randint(160, 400))  # 40 headless + 40 rate = 80
    else:
        vary(s, dp=0, rpm=rng.randint(160, 400),
             tv=round(rng.uniform(0.02, 0.15), 2))  # 30 + 40 + 25 = 95
    return s, "B"


def t_nonsensitive_score_block(rng):
    s = base(rng.choice(NONSENS))
    return vary(s, hl=1, dp=0, dt=0, cov=rng.randint(75, 99)), "B"  # score 120


def t_overlay_combo_block(rng):
    s = base(rng.choice(["pay", "trf"]))
    return vary(s, ov=1, hl=1, dp=0), "B"  # score 90


def t_new_payee_no_proof(rng):
    s = base(rng.choice(["pay", "trf"]))
    return vary(s, np=1, pk=0), "C"  # score 15, no full proof


def t_new_payee_device_missing(rng):
    s = base(rng.choice(["pay", "trf"]))
    return vary(s, np=1, dp=0), "C"  # score 45


def t_high_value_new_payee_stepup(rng):
    s = base(rng.choice(["pay", "trf"]))
    return vary(s, np=1, pk=0, amt=rng.randint(200000, 1500000)), "C"


def t_beneficiary_then_transfer(rng):
    s = base(rng.choice(["ben", "trf"]))
    if rng.random() < 0.5:
        vary(s, np=1, dp=0)  # score 45
    else:
        vary(s, np=1, pk=0, mb=1)  # score 30
    return s, "C"


def t_missing_passkey(rng):
    s = base(rng.choice(SENS))
    return vary(s, pk=0), "C"


def t_missing_device_proof(rng):
    s = base(rng.choice(SENS))
    return vary(s, dp=0), "C"  # score 30


def t_missing_device_token(rng):
    s = base(rng.choice(SENS))
    return vary(s, dt=0), "C"  # score 20


def t_full_proof_elevated_risk(rng):
    s = base(rng.choice(SENS))
    if rng.random() < 0.5:
        vary(s, hl=1, dc=1)  # score 50
    else:
        vary(s, mb=1, ov=1, np=1)  # score 50
    return s, "C"


def t_overlay_stepup(rng):
    s = base(rng.choice(["pay", "trf", "ben"]))
    if rng.random() < 0.5:
        vary(s, ov=1, dp=0)  # score 50
    else:
        vary(s, ov=1, np=1, mb=1)  # score 50
    return s, "C"


def t_moderate_rate_no_proof(rng):
    s = base(rng.choice(SENS))
    return vary(s, pk=0, dp=0, rpm=rng.randint(65, 120)), "C"  # score 50


ATTACK_POOLS = {
    "WA": [t_signature_invalid, t_device_mismatch, t_missing_passkey,
           t_headless_full_combo, t_missing_device_proof,
           t_full_proof_elevated_risk, t_nonsensitive_score_block,
           t_moderate_rate_no_proof, t_nonce_replay, t_missing_device_token],
    "API": [t_probing_then_payment, t_nonce_replay, t_signature_invalid,
            t_burst_high_rate, t_nonsensitive_score_block,
            t_missing_device_token, t_headless_full_combo,
            t_moderate_rate_no_proof],
    "MOB": [t_stolen_token_wrong_device, t_overlay_stepup,
            t_overlay_combo_block, t_missing_device_proof,
            t_device_mismatch, t_missing_device_token, t_session_hijack],
    "AUTH": [t_nonce_replay, t_session_hijack, t_signature_reused_changed,
             t_signature_invalid, t_missing_passkey,
             t_stolen_token_wrong_device, t_moderate_rate_no_proof,
             t_missing_device_proof],
    "AI": [t_probing_then_payment, t_headless_full_combo,
           t_datacenter_headless_noproof, t_burst_high_rate,
           t_nonsensitive_score_block, t_full_proof_elevated_risk,
           t_missing_passkey, t_signature_invalid],
    "FRAUD": [t_new_payee_no_proof, t_new_payee_device_missing,
              t_beneficiary_then_transfer, t_signature_reused_changed,
              t_overlay_stepup, t_high_value_new_payee_stepup,
              t_stolen_token_wrong_device, t_session_hijack, t_nonce_replay,
              t_burst_high_rate],
    "INFRA": [t_datacenter_headless_noproof, t_signature_invalid,
              t_device_mismatch, t_missing_device_token,
              t_headless_full_combo, t_nonce_replay,
              t_nonsensitive_score_block],
}

ATTACK_COUNTS = {"WA": 350, "API": 350, "MOB": 300, "AUTH": 350,
                 "AI": 400, "FRAUD": 450, "INFRA": 300}


# ---- Legitimate scenario templates. All must ALLOW (false positive guard).

def l_payment(rng):
    return base("pay"), "A"


def l_transfer(rng):
    return base("trf"), "A"


def l_new_payee(rng):
    s = base(rng.choice(["pay", "trf"]))
    return vary(s, np=1), "A"  # score 15 with full proof


def l_high_value(rng):
    s = base(rng.choice(["pay", "trf"]))
    return vary(s, amt=rng.randint(100000, 900000),
                np=rng.randint(0, 1)), "A"  # score at most 15


def l_beneficiary(rng):
    return base("ben"), "A"


def l_export_security(rng):
    return base(rng.choice(["exp", "sec"])), "A"


def l_view(rng):
    s = base(rng.choice(["view", "prof"]))
    vary(s, pk=0)
    if rng.random() < 0.5:
        vary(s, dp=0, dt=0)  # score 50, still ALLOW on a view route
    return s, "A"


def l_login(rng):
    s = base("login")
    return vary(s, pk=rng.randint(0, 1), dp=0), "A"  # score 30


LEGIT_TEMPLATES = [(l_payment, 90), (l_transfer, 70), (l_new_payee, 60),
                   (l_high_value, 50), (l_beneficiary, 40),
                   (l_export_security, 40), (l_view, 90), (l_login, 60)]


def build_cases():
    cases = []
    next_id = 1
    for group, count in ATTACK_COUNTS.items():
        pool = ATTACK_POOLS[group]
        for n in range(count):
            template = pool[n % len(pool)]
            signals, expected = template(rng)
            cases.append({"i": next_id, "g": group, "k": "a",
                          "t": template.__name__[2:], "s": signals,
                          "e": expected})
            next_id += 1
    for template, count in LEGIT_TEMPLATES:
        for _ in range(count):
            signals, expected = template(rng)
            cases.append({"i": next_id, "g": "LEGIT", "k": "l",
                          "t": template.__name__[2:], "s": signals,
                          "e": expected})
            next_id += 1
    return cases


def main():
    cases = build_cases()
    problems = []
    for case in cases:
        got = decide(case["s"])
        if got != case["e"]:
            problems.append((case["i"], case["t"], case["e"], got))
        if case["k"] == "a" and case["s"]["r"] in SENSITIVE and got == "A":
            problems.append((case["i"], case["t"], "attack allowed"))
        if case["k"] == "l" and got != "A":
            problems.append((case["i"], case["t"], "legit false positive"))
    if problems:
        print(f"REFUSING TO WRITE: {len(problems)} problems, first: {problems[:5]}")
        return 1
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "test_vectors.json")
    with open(out, "w") as handle:
        json.dump(cases, handle, separators=(",", ":"))
    groups = Counter(c["g"] for c in cases)
    decisions = Counter(c["e"] for c in cases)
    print(f"wrote {out}")
    print(f"total={len(cases)} groups={dict(groups)} decisions={dict(decisions)}")
    print(f"size_bytes={os.path.getsize(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
