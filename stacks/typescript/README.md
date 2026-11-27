# BankShield HumanGate — TypeScript Stack

TypeScript implementation of the shared BankShield HumanGate gate
specification v2 (`docs/GATE_SPEC.md`), adding signals ac, dd, ag, pi, mc, rd.

This stack evaluates synthetic signals and returns one of three decisions:
ALLOW, CHALLENGE, or BLOCK. Sensitive routes are `pay`, `trf`, `ben`, `exp`,
and `sec`. Non sensitive routes are `view`, `login`, and `prof`.

It mirrors the Python reference (`stacks/shared/gate_reference.py`), the
Go implementation (`stacks/go/gate/gate.go`), and the Rust implementation
(`stacks/rust/src/lib.rs`). All four must agree on every shared test
vector in `stacks/shared/test_vectors.json`.

## Demo only note

This is a demo implementation only. It operates on synthetic signals only,
with no real bank data, no real accounts, and no real payment processing.
It is not a production security control and copying this code alone does
not make any service certified, compliant, or safe for real financial use.

## Layout

- `package.json` — package `bankshield-humangate-ts`, type `module`, no
  runtime dependencies. Scripts: `test`, `example`, `typecheck`.
- `tsconfig.json` — strict TypeScript, `NodeNext` modules, `noEmit`.
- `src/gate.ts` — `Signals` interface, `Decision` type
  (`"ALLOW" | "CHALLENGE" | "BLOCK"`), `score`, `isSensitive`, and
  `decide`. Uses only erasable TypeScript syntax (interfaces and type
  annotations; no enums, namespaces, or parameter properties), so it runs
  directly under Node 24 native TypeScript support with no build step.
- `examples/example.ts` — three demo cases: a full proof payment that
  ALLOWs, a replayed nonce that BLOCKs, and a missing passkey case that
  CHALLENGEs.
- `test/vectors.test.ts` — shared vector test using `node:test` and
  `node:assert`. It loads `../shared/test_vectors.json` relative to this
  project directory (the file is not copied), asserts every case, and
  checks the hard pass rules.
- `package-lock.json` — lockfile for the devDependencies only
  (`typescript` and `@types/node`).

## Gate logic summary

Risk score additions:

- headless 40, missing browser signals 15, datacenter IP 10
- requests per minute above 60 adds 20, above 150 adds another 20
- API coverage above 70 percent adds 30
- timing variance below 0.2 seconds with rpm above 20 adds 25
- overlay abuse 20, new payee 15
- missing device proof 30, missing device bound token 20
- spec v2 additions: approval changed 25, changed disbursement destination 50, agent beyond scope 35, embedded instructions 45, mule chain 40, record deletion 40
- amount is informational only and is never scored

Decision order:

1. Device mismatch blocks.
2. Replayed nonce blocks.
3. Invalid session key signature blocks.
4. Sensitive route: changed disbursement destination, mule chain, record deletion, embedded instructions, or agent beyond scope blocks; a recently changed approval never allows (challenge at minimum, block at score 80 or above).
5. Sensitive route: full proof (passkey plus device proof plus device bound
   token) with score below 50 allows; score at or above 80 blocks; otherwise
   challenge.
6. Non sensitive route: score at or above 80 blocks; otherwise allow.

## How to run

Requires Node 24 (native TypeScript support) and npm. No build step is
needed. Install the devDependencies once for the typecheck script:

```sh
npm install
```

Run the shared vector test:

```sh
npm test
```

Run the example:

```sh
npm run example
```

Typecheck without emitting output:

```sh
npm run typecheck
```

## Verified counts

Verified on 27 November 2026 against the expanded shared vector file
(6,200 cases, spec v2). Final run:

```text
cases=6200 allow=900 challenge=1687 block=3613
attack_allow_on_sensitive=0
legit_false_positives=0
✔ shared test vectors
ℹ tests 1
ℹ pass 1
ℹ fail 0
```

An earlier run against the previous 3,000 case file also passed, with
`cases=3000 allow=500 challenge=889 block=1611`, matching the Go and Rust
counts for the same 3,000 vectors.

The example prints:

```text
full proof payment: ALLOW
replayed nonce payment: BLOCK
missing passkey payment: CHALLENGE
```

Typecheck (`tsc --noEmit`, TypeScript 7.0.2) passes with no errors.

## Honest limits

- Demo only: every signal in the vectors is synthetic. No real bank data
  is used anywhere in this implementation or its tests.
- The gate is a pure function of the signals it is given. It does not
  verify passkeys, device attestations, tokens, or session signatures
  itself; it trusts the 0/1 signal values supplied by the caller. A real
  system must produce those signals from real cryptographic verification.
- It is not a production banking control, is not certified or compliant by
  itself, and must not be used to protect real accounts or real money
  movement without proper server authority, threat modelling, independent
  security review, penetration testing, and compliance review.
- Amount (`amt`) is informational only and is never scored, by design.
