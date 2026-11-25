package com.bankshield.gate;

import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import com.bankshield.gate.Gate.Decision;
import com.bankshield.gate.Gate.Signals;

/**
 * JMH benchmark for {@link Gate#decide(Signals)}.
 *
 * <p>Measures the decision function directly on a fixed set of
 * representative signals, one per decision path (ALLOW, CHALLENGE, BLOCK,
 * hard blocks, v2 sensitive-route blocks, non-sensitive routes), cycled
 * round-robin. SampleTime mode reports the latency distribution
 * (including median and p99) in nanoseconds per decide() call.
 *
 * <p>Run with (from stacks/java, after {@code mvn test-compile} and
 * building the test classpath):
 * <pre>
 *   mvn dependency:build-classpath -Dmdep.outputFile=/tmp/jmh-cp.txt -Dmdep.includeScope=test -q
 *   java -cp target/test-classes:target/classes:$(cat /tmp/jmh-cp.txt) \
 *       org.openjdk.jmh.Main DecideBenchmark -wi 3 -i 3 -f 1
 * </pre>
 * The fallback harness in {@code com.bankshield.gate.bench.Bench} exists
 * only if JMH cannot be used.
 */
@BenchmarkMode(Mode.SampleTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@State(Scope.Thread)
public class DecideBenchmark {

    private Signals[] signals;
    private int index;

    @Setup
    public void setup() {
        signals = new Signals[] {
            // Clean full-proof payment -> ALLOW, score 0.
            new Signals("pay", 1, 1, 1, 1, 0, 0, 0, 0, 0, 10, 10, 1.0, 0, 0, 0, 0, 0, 0, 0, 0, 1000),
            // Missing passkey on a sensitive route -> CHALLENGE.
            new Signals("pay", 0, 1, 1, 1, 0, 0, 0, 0, 0, 10, 10, 1.0, 0, 0, 0, 0, 0, 0, 0, 0, 1000),
            // Headless + high coverage + high rpm, full proof -> BLOCK (score >= 80).
            new Signals("trf", 1, 1, 1, 1, 0, 0, 1, 0, 0, 200, 90, 0.1, 0, 0, 0, 0, 0, 0, 0, 0, 50000),
            // Device mismatch -> BLOCK (hard block, any route).
            new Signals("pay", 1, 1, 1, 1, 0, 1, 0, 0, 0, 10, 10, 1.0, 0, 0, 0, 0, 0, 0, 0, 0, 1000),
            // Replayed nonce -> BLOCK (hard block).
            new Signals("view", 1, 1, 1, 1, 1, 0, 0, 0, 0, 10, 10, 1.0, 0, 0, 0, 0, 0, 0, 0, 0, 1000),
            // Invalid session key -> BLOCK (hard block).
            new Signals("pay", 1, 1, 1, 0, 0, 0, 0, 0, 0, 10, 10, 1.0, 0, 0, 0, 0, 0, 0, 0, 0, 1000),
            // Disbursement destination changed on a sensitive route -> BLOCK (v2).
            new Signals("pay", 1, 1, 1, 1, 0, 0, 0, 0, 0, 10, 10, 1.0, 0, 0, 0, 1, 0, 0, 0, 0, 1000),
            // Approval changed on a sensitive route, low score -> CHALLENGE (v2).
            new Signals("ben", 1, 1, 1, 1, 0, 0, 0, 0, 0, 10, 10, 1.0, 0, 0, 1, 0, 0, 0, 0, 0, 1000),
            // Clean non-sensitive view -> ALLOW.
            new Signals("view", 1, 1, 1, 1, 0, 0, 0, 0, 0, 10, 10, 1.0, 0, 0, 0, 0, 0, 0, 0, 0, 1000),
            // Prompt injection on a sensitive route -> BLOCK (v2).
            new Signals("pay", 1, 1, 1, 1, 0, 0, 0, 0, 0, 10, 10, 1.0, 0, 0, 0, 0, 0, 1, 0, 0, 1000),
        };
        index = 0;
    }

    @Benchmark
    public Decision decide() {
        Signals s = signals[index];
        index = (index + 1) % signals.length;
        return Gate.decide(s);
    }
}
