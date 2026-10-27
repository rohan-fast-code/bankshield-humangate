# Contributing to BankShield HumanGate

Thank you for helping make banking apps safer from AI agents and automated attacks. This guide keeps contributions safe, tested, and reviewable.

## Vetting first, form later

If you show interest online, the maintainer checks your GitHub profile first, before any assignment and before any form is sent. See docs/CONTRIBUTOR_VETTING.md for the full process, and docs/CONTRIBUTOR_VETTING_CHECKLIST.md for the record used for each person. The check covers: are you actively contributing, where are you contributing, what are your contributions, and have you contributed to REA, official repo morluto/rea, or not, with exact merged links verified. Stars and forks alone are not contributions. The contributor form is sent only after vetting, and only when the maintainer provides it later, see docs/CONTRIBUTOR_FORM.md. Do not ask for the form before vetting is done, and do not expect a form link in this repo until the maintainer adds it.

## How to contribute

1. Fork the repo, create a branch from main, and make a small, focused change.
2. Add or update tests for every behaviour change. Run all tests in README before you open a pull request.
3. Open a pull request with a clear title, a description of what changed and why, and test results.
4. A maintainer will review. Changes to gate decision logic need two reviews. Changes that touch any finance related path, if such a path ever appears, need a human finance owner review.

## Good first issues

1. Add a new attack type to humangate_blocker/attacks_catalog.json, with a category, a synthetic test signal, and a mitigation layer, and verify the 120 attack test still passes with your new total.
2. Add an adapter for a new framework, for example Node, Go, or Django, following the FastAPI and Spring examples.
3. Improve docs, fix a typo, or add a diagram in text form.
4. Fix a bug found by running the test suite, with a regression test.

## Rules for safety

1. Never commit a real secret, a real key, a real token, or real customer data. Use demo values only, clearly labelled as demo.
2. Never add a working exploit against a real bank, a real app, or a real website. Attack entries in the catalog are high level types with synthetic markers only.
3. Test only on apps you own or have written permission to test.
4. Do not bypass the gate in tests to make a test pass. If a test fails, fix the gate or fix the test signal, with a clear explanation in the pull request.
5. Keep changes small. One attack type, one adapter, or one bug fix per pull request is best.

## Code style

Python code should run with Python 3 only, with no extra dependencies for the core gate and tests. Keep functions small, names clear, and decisions deterministic. A model must not be able to talk its way past a check, so checks must live in code, not in prompts or comments.

## Reporting a bug

Open an issue with the bug report template. Include steps to reproduce with demo data only, expected result, actual result, and test output. If the bug is a security issue, follow SECURITY.md instead of opening a public issue.
