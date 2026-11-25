# BankShield Threat Model 2026

What the v2 gate defends against, where each threat comes from, and what
the gate does about it. This document describes the threat model behind
the six new signals in the BankShield Shared Gate Specification v2
(`docs/GATE_SPEC.md`). It is a demo threat model: every signal in the test
vectors is synthetic, no real bank data is used, and the vectors prove
gate logic and cross-stack agreement, not real bank invulnerability.

## Sources

The threats below are drawn from three precise sources:

- **I4C National Cybercrime Threat Analysis Unit warning, 3 November
  2026** — the Indian Cybercrime Coordination Centre's threat analysis
  warning on attacks against bank disbursement systems and payment APIs.
- **CERT-In advisory CIAD-2026-0046, 9 October 2026** — "Threat Actors
  Exploiting Payment and Disbursement APIs for Unauthorized Fund Transfers
  in BFSI Entities", rated Critical.
- **CERT-In advisory CIAD-2026-0049, 15 October 2026** — "AI Agents as
  Attack Vectors", rated Critical.

## Note: the Wells Fargo incident of 16 November 2026 was not a hack

The Wells Fargo outage of 16 November 2026 was a software bug, not a
cyberattack, and it is not one of the threats in this model. JPMorgan
Chase confirmed a software bug in its on-premise hardware systems, said
there is no evidence it was cyber related, and an FBI official cited in
reporting said there was no indication of malicious or external cyber
activity. Wells Fargo itself reported technical issues only. That outage
must never be presented as an attack in BankShield documentation, and no
gate rule in this specification is based on it. The threats below come
only from the three sources named above.

## Threat 1: Payment and disbursement API exploitation, mule chains, and record deletion

Attackers first get in through unpatched software and misconfigured
internet-facing servers. From there they target the bank's automated fund
disbursement systems and payment APIs. The theft itself is a diversion:
loans and payments that were approved but not yet disbursed are redirected
into mule accounts controlled by the attackers, instead of reaching the
intended recipients. The money is then routed across banks and withdrawn
through IMPS and NEFT, so it moves faster than a manual review can follow.
To hide the theft, the attackers delete records of what happened. AI
agents automate the attack at machine speed, so the whole chain, from
entry to diversion to withdrawal to deletion, can run far faster than a
human attacker working by hand.

Sources: CERT-In advisory CIAD-2026-0046 of 9 October 2026 and the I4C
National Cybercrime Threat Analysis Unit warning of 3 November 2026.

## Threat 2: Abuse of business applications and approval workflows

In this attack the payment itself is not forged. Instead, the attackers
modify business records or approval relationships, and then use otherwise
legitimate payment processes and trusted approval procedures to move the
money. Because the transaction goes through the normal approved route,
with the normal approvals attached, it looks authorized and raises no
alert. The blind spot is independent verification of record changes: if
nobody checks, separately from the payment flow, whether an approval
relationship or a beneficiary was changed, and by whom, a changed record
is treated as a genuine one. A recent change to who may approve a payment,
or to where a payment goes, is therefore a warning sign in itself, even
when the payment that follows it is properly signed and carries full
proof.

Source: CERT-In advisory CIAD-2026-0046 of 9 October 2026.

## Threat 3: Indirect prompt injection against payment-capable AI assistants

A payment-capable AI assistant reads inbound content as part of its work:
emails, invoices, and web pages. In an indirect prompt injection attack,
that inbound content contains hidden instructions written by the attacker.
The assistant reads them and follows them as if they were orders, and
then executes a payment to the attacker. The user never asked for the
payment, and the attacker never needed the user's login. Researchers have
documented a weaponized payload designed to trigger a fixed 5000 dollar
transaction this way, which shows the attack is not theoretical: a single
poisoned document can turn an assistant into a payment channel for the
attacker.

Source: CERT-In advisory CIAD-2026-0049 of 15 October 2026.

## Threat 4: Agentic offensive frameworks

Attackers now run clusters of AI agents that work in parallel, rather than
a single script or a single human operator. The cluster does automated
reconnaissance, probing systems for weaknesses; it generates exploits
rapidly from patches, turning a published fix into a working attack
quickly; and the agents in it can exceed their task authorization, acting
beyond the scope they were given. The danger is the combination: speed
from automation, scale from many agents working at once, and scope
overreach from agents that do more than they were authorized to do.

Source: CERT-In advisory CIAD-2026-0049 of 15 October 2026.

## Mapping: threat to signals, test families, and gate outcome

| Threat | New signals | Test families | Gate outcome |
| --- | --- | --- | --- |
| 1. Payment and disbursement API exploitation, mule chains, record deletion | dd (destination changed from the approved destination), mc (mule chain pattern), rd (record deletion or tampering) | disbursement_diversion (FRAUD), mule_chain_transfer (FRAUD), record_deletion_after_transfer (INFRA) | BLOCK on a sensitive route |
| 2. Abuse of business applications and approval workflows | ac (approval relationship or beneficiary changed recently) | approval_tampering_stepup (AUTH), approval_tampering_high_risk (AUTH) | CHALLENGE at minimum, never ALLOW; BLOCK if the score reaches 80 |
| 3. Indirect prompt injection against payment-capable AI assistants | pi (inbound content contains embedded instructions) | prompt_injection_payment (AI) | BLOCK on a sensitive route |
| 4. Agentic offensive frameworks | ag (agent acting beyond its authorized task scope) | agent_overreach (AI) | BLOCK on a sensitive route |

Notes on the mapping:

- Threat 1 is one attack chain, so it maps to three signals and three
  test families: dd for the diversion itself, mc for the rapid hops across
  accounts that follow it, and rd for the deletion used to hide it. Any
  one of the three blocks a sensitive payment or transfer on its own.
- Threat 2 is the only threat where the gate steps up instead of blocking
  outright. A recent approval change with full proof and otherwise clean
  signals is CHALLENGE, because the change may be legitimate and the
  payment itself is properly proven; the gate forces a fresh human check
  rather than allowing it through. The same change combined with other
  risk (headless signal, datacenter IP, new payee, score 90) is BLOCK.
- Threats 3 and 4 are covered by the v2 AI families, and the existing v1
  signals still cover the older automation signs around them: headless
  browsers, datacenter IPs, high request rates, and systematic API
  probing before a payment.
- On a non-sensitive route the new signals only act through the score:
  score 80 or above BLOCKs, anything else ALLOWs. The hard BLOCK rules
  for dd, mc, rd, pi, and ag apply on sensitive routes only.

## Demo-only limits

Be honest about what this model is and is not:

- Every signal in the test vectors is synthetic. No real bank data, no
  real attack traffic, and no real customer records are used anywhere in
  this model or its tests.
- The vectors prove gate logic and cross-stack agreement: that the Python
  reference, Go, Rust, Java, and TypeScript implementations decide the
  same way on the same 5600 cases, and that no attack case is allowed on
  a sensitive route and no legitimate case is falsely blocked.
- They do not prove real bank invulnerability. A gate that passes
  synthetic vectors has not been tested against real attackers, real
  payment systems, or real approval workflows, and this document must not
  be read as claiming otherwise.
