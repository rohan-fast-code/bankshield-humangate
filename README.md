# BankShield HumanGate: Open Source Blocker For Banking Apps And Websites

BankShield HumanGate is an open source, framework agnostic gate that stops AI agents and automated attacks from reaching finance code, account data, and money movement in banking apps and websites.

It does not try to guess whether a visitor is human by looking at a CAPTCHA or a browser string. Modern agents fake those easily. It lets traffic in only when it carries proof that a real human, on a real registered device, with a hardware backed key, intended that exact action.

An agent with copied screens, copied code, a password, or a stolen token cannot produce that proof. So it is stopped at the gate, before it reaches finance code, before it reaches account data, and before it can move money.

## What is inside

1. BankGuard, in bankguard: a repo design where finance code is absent from the agent workspace, plus a policy gateway that allows interface reads only, denies direct writes, blocks reverse tools, and logs every attempt.
2. HumanGate, in humangate: a universal gate for any app or website, based on three proofs: human proof with a passkey, device proof with attestation and device binding, and request proof with a signed, timestamped, one time nonce request.
3. HumanGate Blocker v2, in humangate_blocker: a scalable blocker tested against a catalog of 120 attack types, in 7 groups: Web Application, API, Mobile Application, Authentication And Session, AI Agent, Banking Fraud And Transaction, and Infrastructure Supply Chain And Insider.
4. Docs, in docs: the original BankShield idea and a summary of 11 latest research papers that shaped this design.

## Test results, verified in this repo

BankGuard gateway tests: passed.
BankGuard leak scan: passed, no banned finance pattern found in the agent repo.
BankGuard hostile agent simulation: 9 hostile attempts denied, 3 safe attempts allowed as interface reads or draft proposals only.
HumanGate tests: passed, human payment allowed, headless agent payment blocked, stolen token on a wrong device blocked, forged signature blocked.
HumanGate Blocker v2: 120 attacks tested, 120 blocked, 0 allowed on a sensitive route.

Run all tests yourself, with Python 3 only, no extra dependencies:

```
python3 bankguard/tests/test_agent_guard.py
python3 bankguard/tests/run_agent_simulation.py
python3 bankguard/scripts/scan_for_finance_leak.py
python3 humangate/tests/test_human_gate.py
python3 humangate/tests/run_demo.py
python3 humangate_blocker/tests/test_120_attacks.py
```

Note: the blocker test uses synthetic marker signals, not real exploits against a real bank. It proves gate logic. Real proof for a real bank still needs permission based penetration testing, code review, and production monitoring.

## How to use it in any bank

1. Deploy the gate as a reverse proxy or middleware in front of finance routes. In Python, import the gate modules in this repo. In Java Spring Boot, port the same decision rules into a filter, see humangate/adapters/SpringGateFilter.java for the pattern.
2. Add a bank policy file for sensitive routes, passkey requirement, attestation requirement, rate limits, and first payee delay.
3. Add client proof: WebAuthn passkeys on the web, Keystore or Secure Enclave keys on mobile, ephemeral session keys after attestation, and request signing with timestamp and nonce.
4. Connect state in production: Redis for nonce, rate, and traffic window state, a queue for audit and alerts, and a risk service for device and transaction scoring.
5. Keep finance logic behind the gate, on the server, with hardware security modules and tokenization. The gate is the front door. It does not replace server authority.

## The core invariant

Even with full UI source, full public API documentation, and a fully decompiled app, an attacker agent must still lack all of these at the same time: a non exportable private key in secure hardware, a fresh server attestation, a transaction signature bound to amount and payee, and a risk approval from the server. If any one is missing, money does not move.

## Not only a demo: built for real financial services, when implemented properly

This repo ships as a demo and research codebase, with demo values only in its tests, so anyone can run it and check the gate logic without real bank code, real customer data, real secrets, or real keys.

That demo form is not the limit of the project. This is also a production oriented design for real financial services, when it is implemented properly in a real service. The gate is stack independent, it works as a sidecar proxy or middleware in front of finance routes, it uses the same decision rules across Python, Java Spring, Node, Go, .NET, PHP, Ruby, Rust, mobile, and web, and it is meant to sit in front of real money routes, not only in a classroom example.

When implemented in a real financial service, it works well because money logic stays on the server, behind the gate, with hardware security modules and tokenization, with Redis for nonce, rate, and traffic window state, with an audit queue and alerts, and with a risk service for device and transaction scoring. The gate itself is the front door. It does not replace server authority, and a real deployment must still connect those production pieces, do its own threat modelling, do permission based penetration testing and code review, and complete its own compliance review.

What this project is not, even in a real deployment: it is not a certified banking product on its own, and copying this repo alone does not make a service compliant. A bank must do the production work listed above before using any part of this code in production.
Do not test this against a real bank app or website without written permission from that bank. Test only on apps you own or have written permission to test.
A gate cannot stop a human who voluntarily gives away a passkey, or an insider with legitimate access who abuses it. Those need limits, dual approval, anomaly detection, and human review behind the gate.

## Contributing

We welcome contributions, like REA style open development, but with a defensive mission. See CONTRIBUTING.md for how to propose a change, add an attack type to the catalog, add a test, or fix a bug.

If you are interested online, vetting happens first. See docs/CONTRIBUTOR_VETTING.md. We check your GitHub profile properly: are you actively contributing, where are you contributing, what are your contributions, and have you contributed to REA, official repo morluto/rea, or not, with exact links verified. Only after vetting do we send the contributor form, and that form is given by the maintainer later, see docs/CONTRIBUTOR_FORM.md. No form is sent before vetting, and no form link is invented here.
Good first contributions: add a new attack type with a test signal and a mitigation layer, add an adapter for a new framework, improve docs, or improve test coverage.
All contributions need tests. A new attack type without a test will not be merged. A change to finance related code, if it ever appears, needs a human finance owner review.

## Security

If you find a security issue in this repo, do not open a public issue with exploit details. See SECURITY.md for responsible disclosure.

## License

MIT License. See LICENSE for the full text. Copyright 2026 Rohan Bhambare.

## Topics for GitHub

banking, security, fintech, ai agents, reverse engineering, app security, api security, mobile security, passkeys, webauthn, fraud prevention, open source, python, spring boot, mcp, agent security, owasp

## Acknowledgement

Built from the BankShield Sentinel idea, the AgentGuard gateway, and HumanGate, after studying AI reverse engineering trends in October 2026, including REA style agent tooling. This project is the defensive inverse of that trend: give agents fewer tools, narrower scopes, and human proof, instead of more tools to take software apart.
