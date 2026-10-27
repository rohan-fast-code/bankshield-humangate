# Security Policy

## Supported versions

This repo ships as a demo and research codebase, and the main branch is the only supported version for security fixes in this repo. There are no long term support branches yet.

## Not only a demo: use in real financial services

This design is built for real financial services, when it is implemented properly, not only for demo use. The demo in this repo uses demo values only, so the gate logic can be checked safely. A real deployment must add the production pieces that the demo does not ship as a finished system:

1. Server authority for all money logic, with hardware security modules and tokenization, behind the gate.
2. Redis or an equivalent store for nonce, rate, and traffic window state, so a request proof cannot be replayed.
3. An audit queue, alerts, monitoring, and incident response, so a blocked or suspicious attempt is seen and acted on.
4. A risk service for device and transaction scoring, with limits, dual approval, and human review for high value or unusual actions.
5. Its own threat modelling, permission based penetration testing, code review, and compliance review, before any production use.

Until those pieces are in place and reviewed, treat a deployment as a demo, not as a production banking control. Copying this repo alone does not make a service certified or compliant.

## Reporting a vulnerability

If you find a security issue in this repo, do not open a public issue with exploit details, and do not test it against a real bank.

Open a private security advisory on GitHub, or contact the maintainer through GitHub, with:
1. A description of the issue, with demo data only.
2. Steps to reproduce in this repo, with demo data only.
3. The impact you expect, and a suggested fix if you have one.

We will acknowledge your report, investigate, and fix it in a pull request. We will credit you in the fix, unless you ask not to be credited.

## Scope

In scope: code in this repo, gate decision logic, test suite, and docs that could mislead a bank into an unsafe deployment.
Out of scope: real banks, real apps, real websites, and production systems you do not own. Do not test those without written permission.

## Safe use

This project, on its own, is not a certified banking product. A bank must do its own threat modelling, penetration testing with permission, code review, and compliance review before using any part of this code in production. When those steps are done and the production pieces above are connected, this gate is intended to work well in front of real finance routes, as a front door control, not as a replacement for server authority.
