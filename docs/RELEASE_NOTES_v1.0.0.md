# Release Notes: v1.0.0, First Public Release

Tag: v1.0.0
Target: main
Author: rohan-fast-code
License: MIT

## What is in v1.0.0

1. BankGuard: repo gating with a policy gateway, interface only reads, denied direct writes, blocked reverse tools, and audit logging.
2. HumanGate: universal gate with passkey proof, device attestation and binding, and signed, timestamped, one time nonce requests.
3. HumanGate Blocker v2: scalable blocker with a 120 attack catalog in 7 groups, Web Application, API, Mobile Application, Authentication And Session, AI Agent, Banking Fraud And Transaction, and Infrastructure Supply Chain And Insider.
4. Contributor vetting: check profile first, verify activity, places, and types of contribution, verify REA contribution in morluto/rea separately, and send the contributor form only after vetting, when the maintainer provides it later. Form placeholder is in docs/CONTRIBUTOR_FORM.md, with no form link invented.
5. Docs: BankShield idea, research papers summary, security policy, contributing guide, code of conduct, and release safety guide.

## Tests verified before this release

1. BankGuard gateway tests: passed.
2. BankGuard leak scan: passed, no banned finance pattern found in the agent repo.
3. BankGuard hostile agent simulation: 9 hostile attempts denied, 3 safe attempts allowed as interface reads or draft proposals only.
4. HumanGate tests: passed, human payment allowed, headless agent payment blocked, stolen token on a wrong device blocked, forged signature blocked.
5. HumanGate Blocker v2: 120 attacks tested, 120 blocked, 0 allowed on a sensitive route.

Run them yourself from the release source:
python3 bankguard/tests/test_agent_guard.py
python3 humangate/tests/test_human_gate.py
python3 humangate_blocker/tests/test_120_attacks.py

## Limits, read before use

1. This is a demo and research codebase, not a certified banking product.
2. Blocker tests use synthetic marker signals, not real exploits against a real bank. They prove gate logic, not that a real bank is invulnerable.
3. Test only on apps you own or have written permission to test. Do not test against a real bank without written permission.
4. A gate cannot stop a human who voluntarily gives away a passkey, or an insider with legitimate access who abuses it. Those need limits, dual approval, anomaly detection, and human review behind the gate.
5. No real secret, no real key, and no real customer data are in this release. All keys and tokens in tests are demo values only.

## How to judge this release safely

See docs/RELEASES.md, in order: check the account rohan-fast-code/bankshield-humangate only, check the tag commit on main, read these notes, run the tests yourself, search for secrets, and remember the demo scope. Do not download a binary claiming to be this release from another account or site.

## Known gaps in v1.0.0

1. GitHub Actions CI workflow file, .github/workflows/ci.yml, is in the local repo but could not be uploaded by the GitHub App, because the app lacks workflow permission. Add it manually, or grant workflow permission, to run CI automatically on GitHub.
2. Repo description and topics are set in the GitHub web UI, in the About section, because the GitHub App tool cannot set them directly. The proper description and topics are listed in README and in the release setup notes below.

## Proper description for GitHub About

Open source HumanGate blocker for banking apps and websites: passkey and device proof, AI agent gating, AgentGuard, 120 attack test suite, and contributor vetting before form. Demo only, no real bank data.

## Proper topics for GitHub About

banking, security, fintech, ai-agents, reverse-engineering, app-security, api-security, mobile-security, passkeys, webauthn, fraud-prevention, open-source, python, spring-boot, mcp, agent-security, owasp
