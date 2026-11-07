# BankShield HumanGate — Go Stack

Go implementation of the shared BankShield HumanGate gate specification.

This stack evaluates synthetic signals and returns one of three decisions:
ALLOW, CHALLENGE, or BLOCK. Sensitive routes are `pay`, `trf`, `ben`, `exp`,
and `sec`. Non sensitive routes include `view`, `login`, and `prof`.

## Demo only note

This is a demo implementation only. It operates on synthetic signals only,
with no real bank data, no real accounts, and no real payment processing.
It is not a production security control and copying this code alone does
not make any service certified, compliant, or safe for real financial use.

## Layout

- `go.mod` — module `bankshield/stacks/go`
- `gate/gate.go` — package `gate` with `Signals`, `Score`, and `Decide`
- `gate/gate_test.go` — shared vector test plus unit tests for hard blocks
- `examples/middleware/main.go` — demo `net/http` middleware using headers
- `sample_test_vectors.json` — small local sample vectors for local checking

## Gate logic summary

Risk score additions:

- headless 40, missing browser signals 15, datacenter IP 10
- requests per minute above 60 adds 20, above 150 adds another 20
- API coverage above 70 percent adds 30
- timing variance below 0.2 seconds with rpm above 20 adds 25
- overlay abuse 20, new payee 15
- missing device proof 30, missing device bound token 20
- amount is informational only and is never scored

Decision order:

1. Device mismatch blocks.
2. Replayed nonce blocks.
3. Invalid session key signature blocks.
4. Sensitive route: full proof (passkey plus device proof plus device bound
   token) with score below 50 allows; score at or above 80 blocks; otherwise
   challenge.
5. Non sensitive route: score at or above 80 blocks; otherwise allow.

## How to run tests

Run all tests:

```sh
go test ./...
```

Run the shared vector test verbosely against the shared vector file. By
default the test loads `../../shared/test_vectors.json` relative to the
`gate` package directory. Override the location with `BSG_VECTORS`:

```sh
BSG_VECTORS=/path/to/test_vectors.json go test ./... -run TestVectors -v
```

Run against the bundled sample vectors:

```sh
BSG_VECTORS=$PWD/sample_test_vectors.json go test ./... -v
```

Format and vet:

```sh
gofmt -l .
go vet ./...
```

## Middleware demo

The middleware example builds `Signals` from simple demo headers such as
`X-Route`, `X-Passkey`, and `X-Device-Proof`, calls `gate.Decide`, returns
403 on BLOCK, 401 with a challenge body on CHALLENGE, and passes through on
ALLOW.

```sh
go run ./examples/middleware
```

This header scheme is a demo convention only, not a real attestation
protocol.

## Synthetic signals only

All examples and tests use synthetic signals only. Do not feed real bank
data, real customer data, or real credentials into this code.
