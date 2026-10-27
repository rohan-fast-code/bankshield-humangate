# BankGuard Repo: A Repo No AI Agent Can Read Finance Code From

## The one rule that makes this work
Finance code is not in this repo at all.
If finance code were in this repo, any agent with repo access could read it, no matter what prompt or guard you add. A guard that sits on top of files an agent can already open is not a wall. It is a suggestion.
So this repo contains only three things: screens, a public interface, and a gateway. Real finance logic lives in a separate private service, in a separate private repo, with zero agent access. This repo talks to that service through an API only.

## Repo layout
app/finance_interface.py : Data shapes only. No fee logic, no fraud logic, no limits, no SQL, no secrets. An agent may read this file. It learns nothing useful about money.
app/finance_client.py : Sends a payment intent to the finance service and returns the result. It does not decide anything.
app/ui.py : Demo screens only.
gateway/agent_guard.py : The only way an agent is allowed to touch this repo. It enforces read, write, and tool policy in code, not in a prompt.
gateway/safe_tools.py : The only tools an agent gets. Read interface, run tests, call the sandbox API, propose a UI change as a draft. No shell, no raw file write, no decompiler.
tests/test_agent_guard.py : Automated tests for the gateway.
tests/run_agent_simulation.py : Simulates a hostile agent trying to read finance code, change finance code, and run reverse tools. Run it and watch every attempt fail.
scripts/scan_for_finance_leak.py : CI scan. Fails the build if finance logic leaks into this repo.
.github/CODEOWNERS : Finance paths, if they ever appear by mistake, require a human finance owner. In normal use there are no finance paths here to own.
.agentignore : Paths an agent must never be given, even by accident.

## How an agent is connected
Do not give the agent shell access, editor file access, or a GitHub token with repo read access.
Connect the agent only through gateway/safe_tools.py, as its MCP server or tool server.
Give the agent a separate identity, read only, short lived token, scoped to this repo only, with no access to the private finance repo and no production access.
Run the agent in a sandbox that mounts only this repo, never the finance repo, never a secrets folder, never production credentials.

## How the finance service is connected in production
The finance service is a separate deployment, owned by human finance engineers only.
It holds fees, limits, fraud rules, ledger writes, and signing keys in a hardware security module.
This repo never imports it as code. It calls it over an authenticated API, with a short lived sender bound token, and the service verifies attestation, risk, and a transaction signature bound to amount and payee before it moves money.
To set this up for real, create two GitHub repos: bank_app_public for this code, and bank_finance_private for finance code. Give the agent identity access to bank_app_public only. Give no agent identity access to bank_finance_private. Ever.

## What the gateway blocks, in code
Read of any path matching a protected pattern: finance core, ledger, fraud, pricing, fee logic, secrets, keys, env files.
Write to any protected path, and write directly to main. The agent may only propose a UI change as a draft branch for human review.
Tool calls for Ghidra, JADX, IDA, Hopper, Frida, strings, decompilers, and any reverse tool against a finance target.
Read of any file outside the declared repo root, using canonical path resolution, so path tricks like dot dot slash do not work.
Any tool call with a secret pattern in its arguments.

## What the gateway allows
Read finance_interface.py, ui.py, and docs.
Run UI tests in a sandbox.
Call the sandbox finance API with fake test data, never real customer data.
Propose a UI change. That proposal becomes a pull request for a human to review. It does not merge itself.

## Run the demo
python3 tests/run_agent_simulation.py
Expected result: every hostile attempt is denied, every safe attempt succeeds, and the audit log shows who tried what.
python3 tests/test_agent_guard.py
Expected result: all gateway tests pass.

## Blunt limits, read before you trust this
This repo stops an agent inside your system, where you control the tools, the token, and the sandbox.
It does not stop an attacker agent on an attacker machine that already has your published app binary. For that attacker, use the BankShield server side design: money logic on the server, hardware backed transaction signatures, and risk approval. A clone of screens cannot move money without those proofs.
If you give an agent direct shell access, direct repo clone access, or a human token, this gateway is bypassed. The gateway only works when it is the only path the agent has.
