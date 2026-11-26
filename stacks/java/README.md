# BankShield HumanGate — Java Stack

Java implementation of the shared BankShield HumanGate gate specification v2
(see `../../docs/GATE_SPEC.md`), adding signals ac, dd, ag, pi, mc, rd. It mirrors the Go implementation in
`../go/gate/gate.go` and the Python reference in
`../shared/gate_reference.py`: the same signals, the same risk score, and
the same decision order, verified against the same shared test vectors in
`../shared/test_vectors.json`.

This stack evaluates synthetic signals and returns one of three decisions:
ALLOW, CHALLENGE, or BLOCK. Sensitive routes are `pay`, `trf`, `ben`, `exp`,
and `sec`. Non-sensitive routes include `view`, `login`, and `prof`.

## Demo only note

This is a demo implementation only. It operates on synthetic signals only,
with no real bank data, no real accounts, and no real payment processing.
It is not a production security control and copying this code alone does
not make any service certified, compliant, or safe for real financial use.

## Layout

- `pom.xml` — Maven project, Java 21, `com.bankshield:humangate-java`.
  No main-code dependencies; the only dependency is JUnit 6
  (`org.junit.jupiter:junit-jupiter:6.1.3`, test scope).
- `src/main/java/com/bankshield/gate/Gate.java` — `Gate` with the `Signals`
  record, the `Decision` enum (`ALLOW`, `CHALLENGE`, `BLOCK`), `score()` and
  `decide()`.
- `src/main/java/com/bankshield/gate/example/Example.java` — small demo
  main running three cases.
- `src/test/java/com/bankshield/gate/VectorsTest.java` — shared vector test
  plus unit tests for the hard blocks. Java has no built-in JSON parser, so
  the test includes a small hand-written JSON parser in the test sources
  only; no JSON library dependency is added.

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
6. Non-sensitive route: score at or above 80 blocks; otherwise allow.

## How to build and test

```sh
export JAVA_HOME=/home/hatch/workspace/tools/jdk-21.0.13+9
export PATH=$JAVA_HOME/bin:/home/hatch/workspace/tools/apache-maven-3.9.11/bin:$PATH
cd stacks/java
mvn test
```

The test loads `../shared/test_vectors.json` from the repository (resolved
relative to the project directory; it is never copied into this stack).
Override the location with `BSG_VECTORS`, matching the Go and Rust stacks:

```sh
BSG_VECTORS=/path/to/test_vectors.json mvn test
```

Run the demo example:

```sh
mvn compile
java -cp target/classes com.bankshield.gate.example.Example
```

Expected output:

```
full proof payment -> ALLOW (score 0)
replayed nonce payment -> BLOCK (score 0)
missing passkey payment -> CHALLENGE (score 0)
```

## Verified counts

Final run, 26 November 2026 (OpenJDK 21.0.13, Maven 3.9.11, JUnit 6.1.3,
Surefire 3.6.1, compiler plugin 3.16.0), spec v2:

```
verified 5600 cases: ALLOW=900 CHALLENGE=1587 BLOCK=3113
attack_allow_on_sensitive=0
legit_false_positives=0
[INFO] Tests run: 11, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

All 5600 shared vectors pass, with zero attack cases allowed on a sensitive
route and zero legitimate cases that do not ALLOW. (The vector file was
expanded from 5000 to 5600 cases by a parallel worker while this stack was
being updated; the counts above are from the final run against the 5600-case
file.)

## Honest limits

- Demo only: every signal in the vectors is synthetic. No real bank data,
  no real accounts, and no real payment processing anywhere in this code
  or its tests.
- The gate trusts the signals it is given; it does not verify passkeys,
  device attestation, or session signatures itself. Real attestation and
  signature verification are out of scope for this demo.
- The test's hand-written JSON parser covers the JSON used by the vector
  file (objects, arrays, strings with escapes, numbers, booleans, null).
  It is test-only code, not a general-purpose JSON library.
- The build needs Maven plugin and JUnit downloads from Maven Central on
  first run; after that it works offline from the local Maven cache.
