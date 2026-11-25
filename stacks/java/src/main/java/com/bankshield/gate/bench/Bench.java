package com.bankshield.gate.bench;

import java.util.Arrays;

import com.bankshield.gate.Gate;
import com.bankshield.gate.Gate.Decision;
import com.bankshield.gate.Gate.Signals;

/**
 * Sustained-run harness for {@link Gate#decide(Signals)}.
 *
 * <p>Supplementary to the JMH benchmark in
 * {@code src/test/java/com/bankshield/gate/DecideBenchmark.java} (which is
 * the latency authority): this harness exists to report throughput
 * (decisions per second) and heap use under a sustained run, which JMH
 * SampleTime does not report. It measures decide() directly on a fixed
 * set of representative signals, one per decision path, cycled
 * round-robin.
 *
 * <p>Method: warm up, then time each individual decide() call with
 * {@link System#nanoTime()} and store the elapsed nanoseconds in a
 * preallocated {@code long[]} (no per-decision allocation in the harness
 * itself beyond the decide() call under test). The timings are sorted
 * and median / p99 are reported. Decisions per second is computed from
 * the total timed wall time. Peak heap used is sampled from the runtime
 * ({@code totalMemory - freeMemory}) during the run.
 *
 * <p>Run with:
 * <pre>
 *   mvn package -DskipTests
 *   java -cp target/classes com.bankshield.gate.bench.Bench
 * </pre>
 */
public final class Bench {

    private static final int WARMUP = 200_000;
    private static final int N = 1_000_000;

    private Bench() {
    }

    public static void main(String[] args) {
        Signals[] signals = {
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

        // Warmup: exercise every branch so JIT compilation settles before timing.
        int checksum = 0;
        for (int i = 0; i < WARMUP; i++) {
            checksum += Gate.decide(signals[i % signals.length]).ordinal();
        }

        Runtime runtime = Runtime.getRuntime();
        long[] timings = new long[N];
        long peakHeapUsed = 0;
        long start = System.nanoTime();
        for (int i = 0; i < N; i++) {
            Signals s = signals[i % signals.length];
            long t0 = System.nanoTime();
            Decision d = Gate.decide(s);
            long t1 = System.nanoTime();
            timings[i] = t1 - t0;
            checksum += d.ordinal();
            if ((i & 0xffff) == 0) {
                long used = runtime.totalMemory() - runtime.freeMemory();
                if (used > peakHeapUsed) {
                    peakHeapUsed = used;
                }
            }
        }
        long end = System.nanoTime();
        double totalSeconds = (end - start) / 1_000_000_000.0;

        Arrays.sort(timings);
        long median = timings[N / 2];
        long p99 = timings[(int) (N * 0.99)];
        double mean = 0;
        for (long t : timings) {
            mean += t;
        }
        mean /= N;
        long finalUsed = runtime.totalMemory() - runtime.freeMemory();
        if (finalUsed > peakHeapUsed) {
            peakHeapUsed = finalUsed;
        }

        System.out.println("decisions=" + N + " warmup=" + WARMUP + " checksum=" + checksum);
        System.out.println("median_ns=" + median);
        System.out.println("p99_ns=" + p99);
        System.out.println("mean_ns=" + String.format("%.1f", mean));
        System.out.println("decisions_per_second=" + Math.round(N / totalSeconds));
        System.out.println("total_time_s=" + String.format("%.3f", totalSeconds));
        System.out.println("peak_heap_used_bytes=" + peakHeapUsed);
        System.out.println("final_heap_used_bytes=" + finalUsed);
        System.out.println("max_heap_bytes=" + runtime.maxMemory());
    }
}
