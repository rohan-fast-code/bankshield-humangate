# HumanGate Blocker v2: A Proper Blocker For Any Banking Sector

## What changed from v1
v1 proved human proof works for one gate. v2 proves the gate blocks or challenges 120 attack types, and it is built to scale to any bank, any app, and any website, without rewriting finance logic.
The gate is stateless except for nonce and rate state in Redis in production. Audit goes to a queue. Decision logic is pure and fast. Many gate pods can run behind a load balancer. A new bank joins by adding a policy file, not by forking code.

## Attack coverage
120 attacks, in 7 groups, sourced from OWASP Web Top 10, OWASP API Top 10, OWASP Mobile Top 10, OWASP LLM Top 10, banking fraud reports, and AI agent research:
Web Application: 20
API: 15
Mobile Application: 15
Authentication And Session: 15
AI Agent: 20
Banking Fraud And Transaction: 15
Infrastructure Supply Chain And Insider: 20
Total: 120
Full list with mitigation layers is in attacks_catalog.json. Each entry is a high level type with a synthetic test signal, not a working exploit.

## How to use it in any bank
Step 1. Deploy the gate as a reverse proxy or middleware in front of finance routes. In Python, import gate.blocker. In Java Spring Boot, port the same decision rules into a filter, as in the v1 Spring example, and call the same policy.
Step 2. Add a bank policy file: sensitive routes, passkey requirement, attestation requirement, rate limits, and first payee delay. No finance logic moves into the gate.
Step 3. Add client proof: WebAuthn passkeys on the web, Keystore or Secure Enclave keys on mobile, ephemeral session keys after attestation, request signing with timestamp and nonce.
Step 4. Connect state: Redis for nonce, rate, and traffic window. A queue for audit and alerts. A risk service for device and transaction scoring. The gate calls those services, it does not own customer data.
Step 5. Run the test suite in CI on every release: python3 tests/test_120_attacks.py. If any attack is allowed, the release fails.

## Scale design
Stateless gate pods, horizontal scaling, no session affinity.
Redis for nonce reuse, rate limiting, and traffic window scoring, with a short time to live.
Audit queue with async workers, so logging never blocks a payment decision for long.
Fail closed for sensitive routes: if proof verification is down, challenge or block money, never allow it. Fail open only for public marketing pages.
Multi tenant: one gate code base, one policy file per bank, one audit stream per tenant, with tenant isolation in Redis keys and audit logs.
Latency budget: gate decision is a pure function plus two Redis lookups in production, designed to stay under 10 milliseconds in the normal path, excluding passkey verification which happens once per session and once per sensitive intent.

## Test result to expect
Total attacks: 120
Allowed on a sensitive route: 0
Blocked or challenged: 120
Human payment with full proof: allowed
Human view with low risk: allowed
Social engineering and insider types: challenged and alerted, not allowed blindly, because a gate alone cannot stop a human who is tricked or an insider with legitimate access. Those types need the full stack: step up, first payee delay, warning, out of band confirmation, dual approval for business accounts, and human review.

## Blunt limits
A test suite with synthetic signals proves the gate logic, not that a real bank is invulnerable. Real proof needs penetration testing on the real bank, with permission, plus code review, plus production monitoring.
A gate cannot stop a human who voluntarily gives away a passkey, or an insider with legitimate access who abuses it. Those need limits, dual approval, anomaly detection, and audit, not just a gate.
An attacker with a published app binary can still try to read it. The gate plus server side money logic means that reading does not turn into money movement without hardware proof and server approval.
