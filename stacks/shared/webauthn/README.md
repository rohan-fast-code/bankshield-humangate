# BankShield HumanGate — Python WebAuthn server verification

Real WebAuthn server-side verification for the Python stack. This
replaces the demo-only passkey flag (`pk=1`) in the shared gate with a
real registration ceremony and authentication ceremony, using the
`webauthn` library (duo-labs py_webauthn 3.x).

The gate itself (`stacks/shared/gate_reference.py`) is untouched: no
decision logic, weight, decision order, or test vector changes. The
vectors still test the gate; WebAuthn is the real path that produces
the proof the gate consumes.

## What was built

- `store.py` — `CredentialRecord` and `InMemoryCredentialStore`. The
  store holds credential id, public key (COSE bytes), sign count, and
  transports. It never stores private key material: the private key
  never leaves the authenticator, and there is deliberately no field
  for it. Production must replace the in-memory store with a
  database-backed store implementing the same interface.
- `service.py` — `WebAuthnService` with the four ceremonies:
  `begin_registration` / `finish_registration` and
  `begin_authentication` / `finish_authentication`, against a relying
  party id and origin passed in by the caller (no hardcoded production
  origin). Challenges are single-use: each `finish_*` call pops the
  challenge, so verifying the same response twice fails. Sign counts
  must advance on every authentication, so a cloned authenticator is
  rejected.
- `gate_wiring.py` — `signals_with_passkey_proof(signals, verified)`
  returns a copy of a signals dict with `pk=1`, only from a verified
  authentication result. An unverified result raises instead of
  silently becoming a proof.
- `requirements.txt` — `webauthn==3.0.1` (plus `cbor2` /
  `cryptography`, test-only, already pulled in as transitive
  dependencies). The gate itself still has zero dependencies.

Note: the PyPI name `py_webauthn` resolves to a stale 0.0.8 release
that cannot load on this system (its `oscrypto` dependency fails to
detect libcrypto), so the maintained `webauthn` package is used
instead. It is the same duo-labs py_webauthn library, version 3.x.

## Attestation

The library verifies attestation statements for the formats it
supports (`packed`, `tpm`, `android-key`, `android-safetynet`,
`fido-u2f`, `apple`, `none`). The verification result records the
attestation format (`attestation_format`) and the trust path
(`trust_path`). By default no root certificates are pinned:
verification uses the library default, which for `fmt="none"` means
there is no attestation statement and no trust path at all.
**Production must pin to a trusted attestation authority list**
(pass `pem_root_certs_by_fmt` to `WebAuthnService`) instead of relying
on the library default.

## Install and test

Install inside a virtual environment, never into the repo:

```
python3 -m venv ~/workspace/bankshield-webauthn-venv
~/workspace/bankshield-webauthn-venv/bin/pip install -r stacks/shared/webauthn/requirements.txt
```

Run the tests from `stacks/shared` (the `webauthn` library lives in
the venv, not in the system Python):

```
~/workspace/bankshield-webauthn-venv/bin/python -m unittest discover -s webauthn/tests -v
```

7 tests, all passing: full registration then authentication succeeds;
tampered signature fails; wrong origin fails (registration and
authentication); replayed challenge fails (registration and
authentication); sign count that does not advance fails; unknown
credential fails; gate wiring turns a verified authentication into
`pk=1` (and a full-proof low-risk payment then ALLOWs, while the same
signals without the proof CHALLENGE).

## Honest limit

A real passkey check on a real phone or security key still needs a
real authenticator and is **not** covered by the unit tests. The tests
use a simulated authenticator that generates a fresh P-256 keypair in
the test process; they prove the server verification logic, not that
any real device, browser, or platform authenticator works with it.
Challenges in the in-memory holder also have no expiry; production
must give them a short TTL (for example in Redis).
