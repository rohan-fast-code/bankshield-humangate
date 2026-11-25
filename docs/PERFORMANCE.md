# Performance: time and space, measured

Added on 2026-11-25. Every number in this document comes from a run on
this machine on 2026-11-25. No number is estimated, modelled, or copied
from another project. If a number changes, rerun the command listed next
to it and update this document with the new measured output.

## Machine and toolchains

Linux VM, AMD EPYC 9D25 processor. Python 3.12.3, Go 1.27.3, Rust
1.99.1, OpenJDK 21.0.13 Temurin with Apache Maven 3.9.11, Node v24.22.1
with npm 10.9.4 and TypeScript 7.0.2. This is a shared virtual machine,
so latencies vary a little between runs; the ranges below are from
repeated runs, not a single best run.

## Measured results

Median and p99 are per decision of the gate decision function itself,
measured on a fixed set of representative signals (clean full proof
ALLOW, missing proof CHALLENGE, high score BLOCK, the hard BLOCK exits
for device mismatch, replayed nonce and invalid session key, the spec v2
BLOCK and CHALLENGE paths, and a clean non sensitive ALLOW), built once
before timing starts. Decisions per second is the sustained throughput
of the decision function. Peak memory is the peak resident memory or
heap used during a sustained run of at least 1,000,000 decisions.

| Stack | Median latency | p99 latency | Decisions per second | Artifact size | Peak memory under sustained run |
| --- | --- | --- | --- | --- | --- |
| Python reference | 667 to 692 ns | 714 ns to 5.9 us (noisy on this shared VM) | about 1.47M | gate_reference.py 3,361 bytes | 112 bytes traced peak over 1,000,000 decisions |
| Go | 26.40 ns per op | 42 to 56 ns | about 37.9M | middleware example binary 8,733,569 bytes; gate package archive 17,986 bytes | 2,536 KiB RSS over 5,000,000 decisions |
| Rust | 13.17 ns | 23.64 ns | 71,271,294 | example binary 293,200 bytes; gate rlib 182,990 bytes | 5,005,312 bytes RSS over 356,357,120 decisions |
| Java | 50 to 60 ns | 70 to 80 ns | 8,425,052 | jar 11,190 bytes | 10,809,440 bytes peak heap used over 1,000,000 decisions |
| TypeScript | 80.0 ns | 131 to 240 ns | 5,683,720 | src directory 7,091 bytes, no build step | 101,883,904 bytes peak RSS, 12,415,904 bytes peak heap over 1,000,000 decisions |

Allocations per decision: Go reports 0 B/op and 0 allocs/op for both
decide and score. Rust decide takes a reference and returns a Copy
enum, with no per request allocation in the hot path. Python decide
returns one of the interned string literals and allocates nothing per
request beyond the small dict reads; the 112 byte traced peak confirms
that. Java and TypeScript reuse a preallocated timing buffer and make no
per request allocation inside decide.

## How to reproduce each number

Python, from the repository root:

```
python3 stacks/shared/bench_decide.py
```

Go, from stacks/go (GOTOOLCHAIN=local GOPROXY=off). The benchmark
file is stacks/go/gate/bench_test.go:

```
go test -bench=BenchmarkDecide -benchtime=3s -benchmem ./gate/
go test -bench=. -benchtime=5s -benchmem ./...
```

Rust, from stacks/rust. The benchmark is the binary
stacks/rust/src/bin/bench.rs, run in release mode:

```
cargo run --release --bin bench
```

Java, from stacks/java. The JMH benchmark is
stacks/java/src/test/java/com/bankshield/gate/DecideBenchmark.java and
the supplementary sustained run harness is
stacks/java/src/main/java/com/bankshield/gate/bench/Bench.java:

```
mvn -q test-compile dependency:build-classpath -Dmdep.outputFile=/tmp/jmh-cp.txt -Dmdep.includeScope=test
java -cp "target/test-classes:target/classes:$(cat /tmp/jmh-cp.txt)" org.openjdk.jmh.Main DecideBenchmark -wi 3 -i 3 -f 0
mvn -q package -DskipTests
java -cp target/classes com.bankshield.gate.bench.Bench
```

TypeScript, from stacks/typescript. The benchmark is
stacks/typescript/bench/bench.ts:

```
node bench/bench.ts
npm run bench
```

Artifact sizes:

```
go build -o /tmp/gate-go-example ./examples/middleware   # from stacks/go
cargo build --release                                    # from stacks/rust, then ls -l target/release/example target/release/libbankshield_gate.rlib
mvn -q package -DskipTests                               # from stacks/java, then ls -l target/humangate-java-1.0.0.jar
du -sb src                                               # from stacks/typescript
wc -c stacks/shared/gate_reference.py                    # from the repository root
```

## Design choices that keep the decision constant time

The decision function in every stack is fixed arithmetic over the
signal fields. There is no loop over test vectors, no input or output,
no regular expression, and no per request allocation in the decision
path. That is true by construction in all five implementations, and it
is stated in a comment at each decision function.

The risk weights and the decision thresholds are compile time
constants in every stack: named constants in Go, Rust, Java, and
TypeScript, and fixed literals in the Python score function. The
sensitive route table is a constant too: a switch in Go, a match in
Rust, a Set built once at class load in Java, a Set built once at
module load in TypeScript, and a module level set in Python. Nothing
about the weights or the route table is computed per request.

The runtime gate never loads the shared test vector file. The vectors
are test data only. That was checked by searching the gate library and
example code in all five stacks for any reference to test_vectors.json,
any file reading, and any JSON parsing in the decision path: the only
vector loading in the repository is in the test files and in the
standalone main function of the Python reference checker, which is a
test runner, not the decision path. The gate itself carries only the
weights table and a small amount of state.

Per request memory is kept at a minimum: the decision takes the signals
and returns a single decision value, builds no large intermediate
object, and reuses buffers where the language makes that idiomatic (the
benchmark harnesses use preallocated timing buffers for the same
reason).

## What the sizes mean

Read the artifact sizes with their context. The Go middleware example
binary is 8,733,569 bytes because it is a complete HTTP server binary
including the Go runtime; the gate itself is the 17,986 byte package
archive. The Rust example binary is 293,200 bytes and the gate library
is 182,990 bytes, both built with strip and link time optimization.
The Java jar is 11,190 bytes and holds the gate, the example, and the
bench harness classes. The TypeScript stack has no build step, so its
size is the 7,091 byte source directory; the 101,883,904 byte peak RSS
is the Node runtime plus the bench, not the gate. The Java peak heap
used is 10,809,440 bytes; the 2,080,374,784 byte max heap figure is the
JVM default heap cap, not memory used.

## Caveats, stated plainly

- The Python p99 varies widely between runs on this shared virtual
  machine (714 ns to 5.9 us across runs). The median is stable at about
  670 to 690 ns. The p99 range is reported as a range for that reason.
- The Java and TypeScript latencies include the timer call overhead
  around each single decision, so they are upper bounds on the true
  decide cost; the decisions per second figures include loop, timer, and
  checksum work, so they are lower bounds on throughput.
- The JMH forked mode failed on this machine (the forked VM could not
  connect back, java.net.SocketException: Connection reset), so the JMH
  numbers were measured in process with -f 0. That has less fork
  isolation than the default forked mode. The supplementary Bench
  harness cross checks it: median 50 to 60 ns and p99 70 to 80 ns in
  both harnesses.
- The Go latency benchmark does fixed work per iteration and ignores
  the harness iteration count, so its harness ns/op line (0.1403 ns/op)
  is meaningless and is not reported. The printed median and p99 lines
  are the real measurement.
- Rust allocations per op were not measured by a harness; the claim
  rests on the code shape (reference in, Copy enum out) and the
  measured peak RSS.
- Optimization never changed a decision. After every optimization, all
  five stacks were rerun against all 5600 shared vectors and still
  produce the identical split: ALLOW 900, CHALLENGE 1587, BLOCK 3113,
  with 0 attack cases allowed on a sensitive route and 0 legitimate
  false positives. If an optimization ever changes a decision, the
  optimization is wrong, not the vector.

## Limits

A fast gate is not a safe bank. These numbers measure the decision
function only, on synthetic signals, on one machine. They say nothing
about passkey verification, device attestation, nonce storage, network
latency, or any real production path. The demo only limits in
docs/MULTI_LANGUAGE_SUPPORT.md still apply in full.
