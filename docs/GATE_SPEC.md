# BankShield Shared Gate Specification v2

One gate specification, implemented identically in Python (reference),
Go, Rust, Java, and TypeScript, and tested against one shared set of test
vectors (`stacks/shared/test_vectors.json`). The specification merges the
signal sets and weights of the two existing Python gates in this repository
(`humangate/gate/human_gate.py` and `humangate_blocker/gate/blocker.py`).

Demo only: every signal in the vectors is synthetic. No real bank data is
used anywhere in this specification or its tests.

## Scope note: the Wells Fargo incident of 16 November 2026 was not a hack

The Wells Fargo outage of 16 November 2026 was a software bug, not a
cyberattack. JPMorgan Chase confirmed a software bug in its on-premise
hardware systems, said there is no evidence it was cyber related, and an
FBI official cited in reporting said there was no indication of malicious
or external cyber activity. Wells Fargo itself reported technical issues
only. That outage must never be presented as an attack in BankShield
documentation, and no gate rule in this specification is based on it.

## Routes

| Code | Route | Sensitive |
| --- | --- | --- |
| pay | payment | yes |
| trf | transfer | yes |
| ben | change beneficiary | yes |
| exp | export data | yes |
| sec | change security settings | yes |
| view | view route | no |
| login | login | no |
| prof | profile view | no |

## Signals

Each request is described by one signals object. Field names are short so
the shared vector file stays compact. Booleans are 0 or 1.

| Field | Meaning |
| --- | --- |
| r | route code (see above) |
| pk | passkey proof present and valid |
| dp | device proof (attestation) valid |
| dt | device bound token valid |
| sk | session key signature valid for this exact request |
| nr | nonce replayed (this nonce was already used) |
| dm | token device mismatch (token used on a different device) |
| hl | headless or automated browser signal |
| mb | missing browser signals |
| dc | datacenter IP |
| rpm | requests per minute from this session |
| cov | API coverage percent in the current window |
| tv | timing variance in seconds (low values mean machine regular timing) |
| ov | overlay or accessibility abuse detected during entry |
| np | new payee (payee was added recently, money routes) |
| amt | amount in rupees. Informational only, never scored. |
| ac | an approval relationship or beneficiary was changed recently |
| dd | the disbursement destination was changed from the approved destination |
| ag | an agent is acting beyond its authorized task scope |
| pi | inbound content (email, invoice, or web page) contains embedded instructions |
| mc | a mule chain pattern, rapid hops across accounts |
| rd | a record deletion or tampering attempt |

The six new signals (ac, dd, ag, pi, mc, rd) are 0 or 1, and default to
0 when absent from a vector. Legitimate cases have all six at 0, so their
scores and decisions are unchanged by v2.

A signature that was created for a different payee or a different amount
does not verify for the changed request, so that scenario is represented
with sk = 0. A stolen token used on the wrong device is dm = 1. A hijacked
session shows up as dm = 1 or sk = 0. Systematic API probing before a
payment attempt shows up as high cov and rpm on the payment request.

## Risk score

Start at 0 and add:

| Condition | Points |
| --- | --- |
| hl = 1 | 40 |
| mb = 1 | 15 |
| dc = 1 | 10 |
| rpm > 60 | 20 |
| rpm > 150 | 20 more |
| cov > 70 | 30 |
| tv < 0.2 and rpm > 20 | 25 |
| ov = 1 | 20 |
| np = 1 | 15 |
| dp = 0 | 30 |
| dt = 0 | 20 |
| ac = 1 | 25 |
| dd = 1 | 50 |
| ag = 1 | 35 |
| pi = 1 | 45 |
| mc = 1 | 40 |
| rd = 1 | 40 |

## Decision

Apply in this exact order. Decisions are ALLOW, CHALLENGE, or BLOCK
(written A, C, or B in the vector file).

1. If dm = 1, BLOCK on any route.
2. If nr = 1, BLOCK on any route.
3. If sk = 0, BLOCK on any route.
4. On a sensitive route:
   - If dd = 1, BLOCK.
   - If mc = 1, BLOCK.
   - If rd = 1, BLOCK.
   - If pi = 1, BLOCK.
   - If ag = 1, BLOCK.
   - If ac = 1, never ALLOW: CHALLENGE at minimum, BLOCK if the score
     reaches 80.
5. On a sensitive route:
   - Full proof means pk = 1 and dp = 1 and dt = 1.
   - Full proof and score < 50: ALLOW.
   - Score >= 80: BLOCK.
   - Anything else: CHALLENGE.
6. On a non sensitive route:
   - Score >= 80: BLOCK.
   - Anything else: ALLOW.

Consequences that must always hold:

- Sensitive routes with a replayed nonce or a device mismatch BLOCK.
- A sensitive route without full proof never ALLOWs.
- An attack case never receives ALLOW on a sensitive route.
- Legitimate cases are the false positive measure: a legitimate case that
  does not ALLOW is a false positive.

## Changes in v2

Version 2 adds a threat-model layer on top of the v1 rules. Every v1 rule
is unchanged; the v1 hard blocks (dm, nr, sk) still come first, and the
v1 score terms still apply exactly as before.

New signals (all 0 or 1, default 0 when absent):

- ac: an approval relationship or beneficiary was changed recently.
- dd: the disbursement destination was changed from the approved destination.
- ag: an agent is acting beyond its authorized task scope.
- pi: inbound content (email, invoice, or web page) contains embedded instructions.
- mc: a mule chain pattern, rapid hops across accounts.
- rd: a record deletion or tampering attempt.

New scoring, added to the existing v1 score: ac = 1 adds 25; dd = 1
adds 50; ag = 1 adds 35; pi = 1 adds 45; mc = 1 adds 40; rd = 1 adds 40.

New decision rules, applied in the exact order given in the Decision
section above, after the existing v1 hard blocks:

- On a sensitive route, dd = 1, mc = 1, rd = 1, pi = 1, and ag = 1 each
  BLOCK, in that order.
- On a sensitive route, ac = 1 never ALLOWs: CHALLENGE at minimum, BLOCK
  if the score reaches 80.
- On a sensitive route, full proof (pk = 1 and dp = 1 and dt = 1) and
  score < 50 ALLOWs; score >= 80 BLOCKs; anything else CHALLENGEs.
- On a non-sensitive route, score >= 80 BLOCKs and anything else ALLOWs.

The shared vectors grow from 5000 cases to 5600 cases in v2, with 600 new
cases in seven families: disbursement_diversion, approval_tampering_stepup,
approval_tampering_high_risk, agent_overreach, prompt_injection_payment,
mule_chain_transfer, and record_deletion_after_transfer. Cases 1 to 5000
are unchanged from v1. The threat model behind the new signals is
described in docs/THREAT_MODEL_2026.md.

## Test vectors

`stacks/shared/test_vectors.json` is generated by
`stacks/shared/generate_vectors.py` with a fixed seed, so regeneration is
byte stable apart from ordering of keys in JSON objects. Each case is:

```json
{"i": 1, "g": "FRAUD", "k": "a", "t": "new_payee_no_proof", "s": {"r": "pay", "pk": 0, "dp": 0, "dt": 1, "sk": 1, "nr": 0, "dm": 0, "hl": 0, "mb": 0, "dc": 0, "rpm": 12, "cov": 8, "tv": 1.4, "ov": 0, "np": 1, "amt": 45000}, "e": "C"}
```

- i: sequential case id.
- g: group code. WA Web Application, API API, MOB Mobile Application,
  AUTH Authentication And Session, AI AI Agent, FRAUD Banking Fraud And
  Transaction, INFRA Infrastructure Supply Chain And Insider,
  LEGIT Legitimate.
- k: a for attack or fraud, l for legitimate.
- t: scenario template name. The template defines the expected decision;
  implementations are tested against it, they do not define it.
- s: signals object.
- e: expected decision, A, C, or B.
