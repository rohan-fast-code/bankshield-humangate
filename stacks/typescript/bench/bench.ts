/**
 * BankShield HumanGate TypeScript benchmark.
 *
 * Measures decide() directly on a fixed set of representative signals,
 * covering every decision branch (ALLOW, CHALLENGE, BLOCK, hard blocks,
 * v2 sensitive-route blocks, non-sensitive routes).
 *
 * Method: warm up, then time each individual decide() call with
 * performance.now() and store the elapsed nanoseconds in a preallocated
 * Float64Array (no per-decision allocation in the harness itself beyond
 * the decide() call under test). The timings are sorted and median / p99
 * are reported. Decisions per second is computed from the total timed
 * wall time. Peak RSS and peak heapUsed are sampled from
 * process.memoryUsage() during the run.
 *
 * Run with: node bench/bench.ts   (or: npm run bench)
 */
import { performance } from "node:perf_hooks";
import { decide } from "../src/gate.ts";
import type { Signals } from "../src/gate.ts";

// Fixed representative signals: one per decision path, cycled round-robin.
const SIGNALS: readonly Signals[] = [
  // Clean full-proof payment -> ALLOW, score 0.
  { r: "pay", pk: 1, dp: 1, dt: 1, sk: 1, nr: 0, dm: 0, hl: 0, mb: 0, dc: 0, rpm: 10, cov: 10, tv: 1.0, ov: 0, np: 0, ac: 0, dd: 0, ag: 0, pi: 0, mc: 0, rd: 0, amt: 1000 },
  // Missing passkey on a sensitive route -> CHALLENGE.
  { r: "pay", pk: 0, dp: 1, dt: 1, sk: 1, nr: 0, dm: 0, hl: 0, mb: 0, dc: 0, rpm: 10, cov: 10, tv: 1.0, ov: 0, np: 0, ac: 0, dd: 0, ag: 0, pi: 0, mc: 0, rd: 0, amt: 1000 },
  // Headless + high coverage + high rpm, full proof -> BLOCK (score >= 80).
  { r: "trf", pk: 1, dp: 1, dt: 1, sk: 1, nr: 0, dm: 0, hl: 1, mb: 0, dc: 0, rpm: 200, cov: 90, tv: 0.1, ov: 0, np: 0, ac: 0, dd: 0, ag: 0, pi: 0, mc: 0, rd: 0, amt: 50000 },
  // Device mismatch -> BLOCK (hard block, any route).
  { r: "pay", pk: 1, dp: 1, dt: 1, sk: 1, nr: 0, dm: 1, hl: 0, mb: 0, dc: 0, rpm: 10, cov: 10, tv: 1.0, ov: 0, np: 0, ac: 0, dd: 0, ag: 0, pi: 0, mc: 0, rd: 0, amt: 1000 },
  // Replayed nonce -> BLOCK (hard block).
  { r: "view", pk: 1, dp: 1, dt: 1, sk: 1, nr: 1, dm: 0, hl: 0, mb: 0, dc: 0, rpm: 10, cov: 10, tv: 1.0, ov: 0, np: 0, ac: 0, dd: 0, ag: 0, pi: 0, mc: 0, rd: 0, amt: 0 },
  // Invalid session key -> BLOCK (hard block).
  { r: "pay", pk: 1, dp: 1, dt: 1, sk: 0, nr: 0, dm: 0, hl: 0, mb: 0, dc: 0, rpm: 10, cov: 10, tv: 1.0, ov: 0, np: 0, ac: 0, dd: 0, ag: 0, pi: 0, mc: 0, rd: 0, amt: 1000 },
  // Disbursement destination changed on a sensitive route -> BLOCK (v2).
  { r: "pay", pk: 1, dp: 1, dt: 1, sk: 1, nr: 0, dm: 0, hl: 0, mb: 0, dc: 0, rpm: 10, cov: 10, tv: 1.0, ov: 0, np: 0, ac: 0, dd: 1, ag: 0, pi: 0, mc: 0, rd: 0, amt: 45000 },
  // Approval changed on a sensitive route, low score -> CHALLENGE (v2).
  { r: "ben", pk: 1, dp: 1, dt: 1, sk: 1, nr: 0, dm: 0, hl: 0, mb: 0, dc: 0, rpm: 10, cov: 10, tv: 1.0, ov: 0, np: 0, ac: 1, dd: 0, ag: 0, pi: 0, mc: 0, rd: 0, amt: 0 },
  // Clean non-sensitive view -> ALLOW.
  { r: "view", pk: 1, dp: 1, dt: 1, sk: 1, nr: 0, dm: 0, hl: 0, mb: 0, dc: 0, rpm: 10, cov: 10, tv: 1.0, ov: 0, np: 0, ac: 0, dd: 0, ag: 0, pi: 0, mc: 0, rd: 0, amt: 0 },
  // Prompt injection on a sensitive route -> BLOCK (v2).
  { r: "pay", pk: 1, dp: 1, dt: 1, sk: 1, nr: 0, dm: 0, hl: 0, mb: 0, dc: 0, rpm: 10, cov: 10, tv: 1.0, ov: 0, np: 0, ac: 0, dd: 0, ag: 0, pi: 1, mc: 0, rd: 0, amt: 45000 },
];

const WARMUP = 200_000;
const N = 1_000_000;

function main(): void {
  // Warmup: exercise every branch so JIT compilation settles before timing.
  let checksum = 0;
  for (let i = 0; i < WARMUP; i++) {
    const d = decide(SIGNALS[i % SIGNALS.length]);
    checksum += d.length;
  }

  // Timed run: one performance.now() pair per decide(), elapsed ns stored
  // in a preallocated buffer (no allocation per timed decision in the harness).
  const timings = new Float64Array(N);
  let peakRss = 0;
  let peakHeapUsed = 0;
  const runStart = performance.now();
  for (let i = 0; i < N; i++) {
    const s = SIGNALS[i % SIGNALS.length];
    const t0 = performance.now();
    const d = decide(s);
    const t1 = performance.now();
    timings[i] = (t1 - t0) * 1e6; // ms -> ns
    checksum += d.length;
    if ((i & 0xffff) === 0) {
      const m = process.memoryUsage();
      if (m.rss > peakRss) peakRss = m.rss;
      if (m.heapUsed > peakHeapUsed) peakHeapUsed = m.heapUsed;
    }
  }
  const runEnd = performance.now();
  const totalSeconds = (runEnd - runStart) / 1000;

  timings.sort();
  const median = timings[Math.floor(N / 2)];
  const p99 = timings[Math.floor(N * 0.99)];
  const mean = timings.reduce((a, b) => a + b, 0) / N;
  const finalMem = process.memoryUsage();
  if (finalMem.rss > peakRss) peakRss = finalMem.rss;
  if (finalMem.heapUsed > peakHeapUsed) peakHeapUsed = finalMem.heapUsed;

  console.log(`decisions=${N} warmup=${WARMUP} checksum=${checksum}`);
  console.log(`median_ns=${median.toFixed(1)}`);
  console.log(`p99_ns=${p99.toFixed(1)}`);
  console.log(`mean_ns=${mean.toFixed(1)}`);
  console.log(`decisions_per_second=${Math.round(N / totalSeconds)}`);
  console.log(`total_time_s=${totalSeconds.toFixed(3)}`);
  console.log(`peak_rss_bytes=${peakRss}`);
  console.log(`peak_heap_used_bytes=${peakHeapUsed}`);
  console.log(`final_rss_bytes=${finalMem.rss}`);
  console.log(`final_heap_used_bytes=${finalMem.heapUsed}`);
}

main();
