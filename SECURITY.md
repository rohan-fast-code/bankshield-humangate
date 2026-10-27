# Security Policy

## Supported versions

This is a demo and research codebase. The main branch is the only supported version for security fixes in this repo. There are no long term support branches yet.

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

This project is not a certified banking product. A bank must do its own threat modelling, penetration testing with permission, code review, and compliance review before using any part of this code in production.
