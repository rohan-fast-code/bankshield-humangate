# HumanGate: A Universal System That Does Not Let An AI Agent Into A Financial App Or Website

## What this system is
HumanGate is a gate that sits in front of any financial app or website, between the internet and the finance code. It does not try to guess whether a visitor is a human by looking at a CAPTCHA or a user agent string. Those are easy for a modern agent to fake.
It lets traffic in only when it carries proof that a real human, on a real registered device, with a hardware backed key, intended that exact action.
An agent that only has copied screens, copied code, a password, or a stolen token cannot produce that proof. So it is stopped at the gate, before it reaches finance code, before it reaches account data, and before it can move money.

## The three proofs, in plain language
1. Human proof. A passkey signature, made in secure hardware, bound to the exact intent: amount, payee, and account for a payment. A signature for one payment cannot be reused for another payment.
2. Device proof. Attestation from the platform: Play Integrity on Android, App Attest on iOS, and device binding on the web. The session token is bound to that device. A token copied to another device is useless.
3. Request proof. Every sensitive request is signed with an ephemeral session key, with a timestamp and a one time nonce. An old request cannot be replayed, and a forged request cannot be signed without the session key, which an agent does not have.

If any proof is missing for a sensitive route, the gate does not let the request through. It challenges or blocks, depending on risk. Viewing a balance can stay low friction. Moving money, changing a beneficiary, exporting data, or changing security settings always needs full proof.

## How it fits any app or website, without rewriting finance logic
Step 1. Copy the gate folder into your project, or run it as a separate service in front of your app. The gate is framework agnostic. It takes request signals in and returns a decision out: ALLOW, CHALLENGE, or BLOCK.
Step 2. Route sensitive routes through the gate. In Python, use adapters/fastapi_adapter.py as an example. In Java Spring Boot, use adapters/SpringGateFilter.java as an example. In any other stack, call the same decision function before your finance handler runs.
Step 3. Add human proof in the client. On the web, use WebAuthn passkeys. On mobile, use a Keystore or Secure Enclave key with biometric unlock. Provision an ephemeral session key only after attestation, and let it expire in minutes.
Step 4. Keep finance logic behind the gate. The gate is not a replacement for server side authority, hardware security modules, tokenization, or risk scoring. It is the front door that makes sure only human proved traffic ever reaches that logic.

## How the gate decides
The gate uses deterministic code, not a prompt and not a model guess.
It scores risk from signals: headless browser, missing browser signals, datacenter IP, high request rate, systematic API coverage in a short window, regular machine timing, and missing attestation.
It checks proofs for the route: view routes need low risk only, sensitive routes need passkey proof plus device attestation plus a valid device bound token plus a valid request signature.
If the risk score is high and proofs are missing, the gate blocks.
If proofs are partial, the gate challenges with step up authentication.
If proofs are full and risk is low, the gate allows.
Every decision is logged: session, route, signals, score, decision, and reason.

## What this system blocks, in the demo
An agent with no passkey, no attestation, headless signals, and systematic probing.
An agent with a stolen password token but a different device and no passkey signature.
An agent with copied UI source but no session key, so its request signature is invalid.
An agent that maps the whole API in minutes, because the traffic window score rises and the gate blocks before the map is complete.
An agent that replays an old payment request, because the timestamp is stale or the nonce was already used.

## What this system allows
A real human on a registered device, with a passkey, attestation, and a valid session, doing normal banking at normal speed.
A real human viewing a balance with low friction, then stepping up with a passkey only when money is about to move.

## Run the demo
python3 tests/test_human_gate.py
python3 tests/run_demo.py
Expected result: human payment is allowed, all agent variants are blocked or challenged, and the audit log shows why.

## Blunt limits, read before you trust this
No system can perfectly tell a human from an agent that is running on a real human device with the human full cooperation, or from malware that has already taken over that device. If a human voluntarily hands an agent their passkey and biometric, that is social engineering, not a gate failure, and it needs separate controls such as out of band confirmation and transaction limits.
An agent that only browses public marketing pages will still see those pages. The gate protects account data and money movement, not public content.
CAPTCHA alone is not used here, because modern agents solve CAPTCHAs. Passkeys work because the private key never leaves secure hardware and cannot be copied by reading code.
This prototype uses demo verification for passkeys and attestation. In production, verify WebAuthn signatures against the registered public key, verify Play Integrity and App Attest tokens with the platform, verify request signatures with the session key from your key service, and store nonces in a real store, not in memory.
