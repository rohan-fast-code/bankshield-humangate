# 🤝 Contributing to BankShield HumanGate

Thank you for helping make banking apps safer from AI agents and automated attacks. This guide keeps contributions safe, tested, and reviewable, and it shows you exactly how to go from your first look at the repo to a merged pull request.

If you are new here, start with the [README](README.md): run the gate in two minutes, read the shared spec, and say hello in [Discussions](https://github.com/rohan-fast-code/bankshield-humangate/discussions). This guide picks up from there.

## 🧭 How to contribute in four steps

1. **Fork the repo, create a branch from main, and make a small, focused change.** One attack type, one adapter, or one bug fix per pull request is best.
2. **Add or update tests for every behaviour change.** Run all tests in the README before you open a pull request. A new attack type without a test will not be merged.
3. **Open a pull request with a clear title, a description of what changed and why, and test results.** Tell us the commands you ran and what they printed.
4. **A maintainer will review.** Changes to gate decision logic need two reviews. Changes that touch any finance related path, if such a path ever appears, need a human finance owner review.

## 🛠️ Setup and test commands, one per stack

Python 3 is the only tool you need for the core gate and its tests, with no extra dependencies. Go, Rust, Java, and TypeScript are needed only for their own stacks.

| Stack | Setup | Test command |
| --- | --- | --- |
| Python | Python 3 only | `python3 humangate_blocker/tests/test_120_attacks.py` and `python3 stacks/shared/gate_reference.py stacks/shared/test_vectors.json` |
| Go | Go 1.27 or later | `cd stacks/go && go test ./...` |
| Rust | Rust stable with cargo | `cd stacks/rust && cargo test` |
| Java | Java 21 with Maven | `cd stacks/java && mvn test` |
| TypeScript | Node with npm | `cd stacks/typescript && npm test` |

Every stack must pass all 6,200 shared test cases with identical decisions: 900 ALLOW, 1,687 CHALLENGE, 3,613 BLOCK. If your change moves even one decision, stop and check the spec first. Vectors must still pass identically in all five stacks, and no decision may change without a spec change.

## 🗺️ Contribution paths

Pick the path that fits you best:

- **New attack cases:** add a new attack type with a test signal and the expected decision. New cases must come from the committed generator with the fixed seed, never hand edited JSON. See the open issue for new attack test families.
- **Language ports:** add a new stack that implements the shared spec, or polish an existing one. See the open issue for the C# port.
- **Hard review:** read the gate code and the spec, try to break the logic, and file what you find with a test that proves it.
- **Documentation:** improve the docs, fix a typo, or add a diagram in text form. Clear docs help new contributors more than most code changes.
- **Benchmarks:** measure the gate, make it faster or lighter, and show the before and after numbers in your pull request.
- **Examples and adapters:** add a middleware example or an adapter for a new framework, following the FastAPI and Spring examples. See the open issues for the FastAPI middleware example, the Stripe test mode demo, and the command line tool.

## 🌱 Good first issues

Small first tasks are listed in the repository issues labelled `good first issue`, each with the files involved and how it is verified. Right now those are the C# port, the Stripe test mode demo, the command line tool, new attack test families, and the FastAPI middleware example.

Four more first tasks, any time:

1. Add a new attack type to humangate_blocker/attacks_catalog.json, with a category, a synthetic test signal, and a mitigation layer, and verify the 120 attack test still passes with your new total.
2. Add an adapter for a new framework, for example Node, Go, or Django, following the FastAPI and Spring examples.
3. Improve docs, fix a typo, or add a diagram in text form.
4. Fix a bug found by running the test suite, with a regression test.

Comment on the issue before you start, so two people do not build the same thing.

## 🪜 Contributor ladder

- **First time contributor:** your first merged pull request. You followed the guide, added tests, and the checks stayed green.
- **Regular contributor:** several merged pull requests across more than one area, with reviews that keep getting shorter because your work keeps getting cleaner.
- **Reviewer:** you review other people's pull requests, catch real problems, and help keep the gate honest. Reviewers are picked by the maintainer from regular contributors.

## 🔍 Vetting first, form later

If you show interest online, the maintainer checks your GitHub profile first, before any assignment and before any form is sent. See docs/CONTRIBUTOR_VETTING.md for the full process, and docs/CONTRIBUTOR_VETTING_CHECKLIST.md for the record used for each person. The check covers: are you actively contributing, where are you contributing, what are your contributions, and have you contributed to REA, official repo morluto/rea, or not, with exact merged links verified. Stars and forks alone are not contributions. The contributor form is sent only after vetting, and only when the maintainer provides it later, see docs/CONTRIBUTOR_FORM.md. Do not ask for the form before vetting is done, and do not expect a form link in this repo until the maintainer adds it.

## 🛡️ Rules for safety

1. Never commit a real secret, a real key, a real token, or real customer data. Use demo values only, clearly labelled as demo.
2. Never add a working exploit against a real bank, a real app, or a real website. Attack entries in the catalog are high level types with synthetic markers only.
3. Test only on apps you own or have written permission to test.
4. Do not bypass the gate in tests to make a test pass. If a test fails, fix the gate or fix the test signal, with a clear explanation in the pull request.
5. Keep changes small. One attack type, one adapter, or one bug fix per pull request is best.

## ✍️ Code style

Python code should run with Python 3 only, with no extra dependencies for the core gate and tests. Keep functions small, names clear, and decisions deterministic. A model must not be able to talk its way past a check, so checks must live in code, not in prompts or comments.

## 🐛 Reporting a bug

Open an issue with the bug report template. Include steps to reproduce with demo data only, expected result, actual result, and test output. If the bug is a security issue, follow SECURITY.md instead of opening a public issue.

## 💬 Talk to us

Stuck on setup, unsure which issue to pick, or not sure your idea fits? Ask in [Discussions](https://github.com/rohan-fast-code/bankshield-humangate/discussions) before you write code. A short question there can save you a long wrong turn, and the maintainer would rather answer it early than review a pull request that heads the wrong way.
