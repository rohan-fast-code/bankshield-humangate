# BankShield HumanGate: Rust Gate

## What it is

This is the Rust implementation of the shared gate specification for the BankShield HumanGate project. It is a small, pure decision library with no network, storage, or banking integration. Given a set of synthetic signals for a request, it computes a risk score and returns one of three decisions: ALLOW, CHALLENGE, or BLOCK.

Sensitive routes are pay, trf, ben, exp, and sec. Non sensitive routes are view, login, and prof.

Hard rules, checked first and in order, block on token device mismatch, on a replayed nonce, and on an invalid session key signature. After those rules, sensitive routes require full proof (passkey proof plus device proof plus device bound token) with a score below 50 to allow, block at a score of 80 or above, and challenge otherwise. Non sensitive routes block at a score of 80 or above and allow otherwise.

## Layout

- `Cargo.toml` — package `bankshield-gate`, edition 2021, dependencies `serde` (with derive) and `serde_json` only.
- `src/lib.rs` — `Signals` struct with serde field renames matching the short signal names (`tv` as `f64`, all other fields integers or string), `Decision` enum (`Allow`, `Challenge`, `Block`), `score`, `decide`, and a helper mapping a decision to ALLOW, CHALLENGE, or BLOCK.
- `src/bin/example.rs` — small example program: one sensitive payment with full proof and one replay case.
- `tests/vectors.rs` — integration test that loads the shared test vector file and asserts every case.
- `../shared/test_vectors.json` — shared test vectors by default (see below).

## How to run tests

From this crate root:

```bash
cargo test
cargo test -- --nocapture
```

The vector test loads its file from the environment variable `BSG_VECTORS` if set, otherwise from `../shared/test_vectors.json` relative to the crate root. To use a specific file:

```bash
BSG_VECTORS=/path/to/test_vectors.json cargo test -- --nocapture
```

The test prints the total verified count with a breakdown by outcome and fails on any mismatch.

Run the example with:

```bash
cargo run --bin example
```

## Demo only note

This code is for demonstration and evaluation only. It is not a production banking control, is not certified or compliant by itself, and must not be used to protect real accounts or real money movement without proper server authority, threat modelling, independent security review, penetration testing, and compliance review.

## Synthetic signals only, no real bank data

All signals, test vectors, and examples in this crate are synthetic. Do not feed real bank data, real customer data, real credentials, or real session material into this code. Amount (`amt`) is informational only and is never scored.
