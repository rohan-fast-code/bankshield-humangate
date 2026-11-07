<p align="center">
  <img width="240px" height="240px" alt="BankShield HumanGate Logo" src="https://github.com/user-attachments/assets/e03afbaa-9eb1-4b2c-bd48-b28627ed6ae6" />
</p>

<h1 align="center">BankShield HumanGate</h1>

<p align="center"><strong>Stop AI agents from moving money without human proof.</strong></p>

<p align="center">
  <img src="https://img.shields.io/github/license/rohan-fast-code/bankshield-humangate" alt="MIT license">
  <img src="https://img.shields.io/github/v/release/rohan-fast-code/bankshield-humangate" alt="Latest release">
  <img src="https://img.shields.io/badge/stacks-Python%20%7C%20Go%20%7C%20Rust-blue" alt="Python, Go and Rust stacks">
  <img src="https://img.shields.io/badge/proof-passkey%20and%20WebAuthn-purple" alt="Passkey and WebAuthn proof">
  <img src="https://img.shields.io/badge/demo%20only-no%20real%20bank%20data-orange" alt="Demo only, no real bank data">
</p>

<p align="center">
  <a href="https://www.producthunt.com/products/bankshield-humangate?embed=true&amp;utm_source=badge-featured&amp;utm_medium=badge&amp;utm_campaign=badge-bankshield-humangate" target="_blank" rel="noopener noreferrer"><img alt="BankShield HumanGate - Stop AI agents from moving money without human proof | Product Hunt" width="250" height="54" src="https://api.producthunt.com/widgets/embed-image/v1/featured.svg?post_id=1307761&amp;theme=dark&amp;t=1794061505970"></a>
</p>

BankShield HumanGate is an open source, framework agnostic gate that stops AI agents and automated attacks from reaching finance code, account data, and money movement in banking apps and websites.

It does not try to guess whether a visitor is human by looking at a CAPTCHA or a browser string. Modern agents fake those easily. It lets traffic in only when it carries proof that a real human, on a real registered device, with a hardware backed key, intended that exact action.

An agent with copied screens, copied code, a password, or a stolen token cannot produce that proof. So it is stopped at the gate, before it reaches finance code, before it reaches account data, and before it can move money.

## Why this matters

Bank accounts are now attacked by software, not only by people. Automated agents and bots can copy an app screen by screen, study its code, guess or reuse passwords, replay stolen tokens, and try thousands of actions at machine speed, day and night, without getting tired. When one of those attempts succeeds on a money route, real money leaves a real account, and the account holder finds out after the loss.

Passwords, CAPTCHAs, and browser checks were built for human attackers and simple bots. They do not prove that a human intended a specific payment to a specific payee. That proof is the missing layer, and it is the layer this project builds, openly, so any bank, fintech, or security team can study it, test it, and adapt it.

## What the gate does

- BankGuard: keeps finance code out of the agent workspace entirely. Agents see a public interface only, direct writes are denied, reverse engineering tools are blocked inside the workspace, and every attempt is logged.
- HumanGate: decides who may act on a route, using three proofs together: human proof with a passkey, device proof with attestation and device binding, and request proof with a signed, timestamped, one time nonce request.
- AgentGuard: an MCP policy gateway for agent tools. Finance related reads return the public interface only, writes are denied by default and need human owner approval, secrets are never shown raw, and every call is audit logged.
- HumanGate Blocker: a scalable blocker in front of sensitive routes, fail closed for money, tested against a catalog of 120 attack types in 7 groups.
- One shared gate specification (docs/GATE_SPEC.md), implemented in Python, Go, and Rust in stacks, and tested against the same 3000 shared test cases.
- Docs, in docs: the original BankShield idea, the shared gate specification, the Go and Rust support notes, and summaries of the research that shaped this design.

## Verified test results

Verified locally on 2026-11-07. Every number below comes from an actual run in this repository.

| Stack | Test run | Cases | ALLOW | CHALLENGE | BLOCK |
| --- | --- | --- | --- | --- | --- |
| Python reference | stacks/shared/gate_reference.py | 3000 | 500 | 889 | 1611 |
| Go | stacks/go, go test | 3000 | 500 | 889 | 1611 |
| Rust | stacks/rust, cargo test | 3000 | 500 | 889 | 1611 |

Pass rules on the shared cases: attack cases allowed on a sensitive route: 0. Legitimate cases denied (false positives): 0. The three stacks agree on every one of the 3000 cases.

The 3000 shared cases are 2500 attack and fraud cases across 7 groups (Web Application 350, API 350, Mobile Application 300, Authentication And Session 350, AI Agent 400, Banking Fraud And Transaction 450, Infrastructure Supply Chain And Insider 300) plus 500 legitimate cases. Money movement scenarios carry the extra weight: payment to a new payee, beneficiary addition followed by a transfer, a stolen token used on the wrong device, a replayed nonce, a signature reused for a different payee or a different amount, overlay or accessibility abuse during payment entry, session hijack before a sensitive action, systematic API probing before a payment attempt, and high value and high rate bursts.

Existing suites, unchanged and still passing: BankGuard gateway tests passed, BankGuard finance leak scan passed, BankGuard hostile agent simulation denied 9 hostile attempts and allowed 3 safe ones, HumanGate tests passed, and HumanGate Blocker v2 tested 120 attacks with 120 blocked or challenged and 0 allowed on a sensitive route.

Note: the tests use synthetic marker signals, not real exploits against a real bank. They prove gate logic and cross stack agreement. Real proof for a real bank still needs permission based penetration testing, code review, and production monitoring. See docs/GO_RUST_SUPPORT.md for full commands and limits.

## Try it in two minutes

You need Python 3 only for the first two commands. Go and Rust are needed only for their own stacks.

```
git clone https://github.com/rohan-fast-code/bankshield-humangate.git
cd bankshield-humangate
python3 humangate_blocker/tests/test_120_attacks.py
python3 stacks/shared/gate_reference.py stacks/shared/test_vectors.json
cd stacks/go && go test ./...
cd ../rust && cargo test
```

## Star and share

If this project helps you think about agent proof for banking, please star the repository so other builders can find it.

Share it: [X](https://twitter.com/intent/tweet?text=BankShield%20HumanGate%3A%20an%20open%20source%20gate%20that%20stops%20AI%20agents%20from%20moving%20money%20without%20human%20proof.%20Python%2C%20Go%20and%20Rust%2C%203000%20shared%20test%20cases.&url=https://github.com/rohan-fast-code/bankshield-humangate) · [LinkedIn](https://www.linkedin.com/sharing/share-offsite/?url=https://github.com/rohan-fast-code/bankshield-humangate) · [WhatsApp](https://wa.me/?text=BankShield%20HumanGate%3A%20an%20open%20source%20gate%20that%20stops%20AI%20agents%20from%20moving%20money%20without%20human%20proof.%20https://github.com/rohan-fast-code/bankshield-humangate) · [Telegram](https://t.me/share/url?url=https://github.com/rohan-fast-code/bankshield-humangate&text=BankShield%20HumanGate%3A%20an%20open%20source%20gate%20that%20stops%20AI%20agents%20from%20moving%20money%20without%20human%20proof.)

## Built for real financial services, only when implemented properly

This repo ships as a demo and research codebase, with demo values only in its tests, so anyone can run it and check the gate logic without real bank code, real customer data, real secrets, or real keys.

That demo form is not the limit of the project. This is also a production oriented design for real financial services, when it is implemented properly in a real service. The gate is stack independent, it works as a sidecar proxy or middleware in front of finance routes, and it is meant to sit in front of real money routes, not only in a classroom example.

How to use it in a real service:

1. Deploy the gate as a reverse proxy or middleware in front of finance routes. In Python, import the gate modules in this repo. In Go and Rust, use the stacks in this repo. In Java Spring Boot, port the same decision rules into a filter, see humangate/adapters/SpringGateFilter.java for the pattern.
2. Add a bank policy file for sensitive routes, passkey requirement, attestation requirement, rate limits, and first payee delay.
3. Add client proof: WebAuthn passkeys on the web, Keystore or Secure Enclave keys on mobile, ephemeral session keys after attestation, and request signing with timestamp and nonce.
4. Connect state in production: Redis for nonce, rate, and traffic window state, a queue for audit and alerts, and a risk service for device and transaction scoring.
5. Keep finance logic behind the gate, on the server, with hardware security modules and tokenization. The gate is the front door. It does not replace server authority.

When implemented in a real financial service, it works well because money logic stays on the server, behind the gate, with hardware security modules and tokenization, with Redis for nonce, rate, and traffic window state, with an audit queue and alerts, and with a risk service for device and transaction scoring. A real deployment must still connect those production pieces, do its own threat modelling, do permission based penetration testing and code review, and complete its own compliance review.

What this project is not, even in a real deployment: it is not a certified banking product on its own, and copying this repo alone does not make a service compliant. A bank must do the production work listed above before using any part of this code in production.
Do not test this against a real bank app or website without written permission from that bank. Test only on apps you own or have written permission to test.
A gate cannot stop a human who voluntarily gives away a passkey, or an insider with legitimate access who abuses it. Those need limits, dual approval, anomaly detection, and human review behind the gate.

## The core invariant

Even with full UI source, full public API documentation, and a fully decompiled app, an attacker agent must still lack all of these at the same time: a non exportable private key in secure hardware, a fresh server attestation, a transaction signature bound to amount and payee, and a risk approval from the server. If any one is missing, money does not move.

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
