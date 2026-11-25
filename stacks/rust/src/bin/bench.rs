// Benchmark binary for the BankShield HumanGate Rust gate.
//
// The stable toolchain has no built-in bench harness, so this binary
// warms up, then runs `decide` in a sustained loop (at least 1,000,000
// decisions and at least 5 seconds, whichever is larger) and prints
// median and p99 decision latency, decisions per second, and peak
// resident memory (VmHWM from /proc/self/status).
//
// Latency method: timing a single ~nanosecond call with `Instant`
// would drown the measurement in clock overhead, so decisions are
// timed in batches of 1024. Each batch time is stored in a
// preallocated buffer, the buffer is sorted, and the median and p99
// batch times are divided by the batch size to give per-decision
// latency. The signal set is fixed and built once before timing, so
// no allocation or setup work is measured. Results are accumulated
// into counters printed at the end (plus `black_box` on the input)
// so the compiler cannot eliminate the loop as dead code.
//
// This binary reads /proc/self/status for its own peak RSS only. The
// gate library itself (`src/lib.rs`) does no file reading at all.
use bankshield_gate::{decide, Decision, Signals};
use std::fs;
use std::hint::black_box;
use std::time::{Duration, Instant};

const BATCH: usize = 1024;
const WARMUP_DECISIONS: usize = 200_000;
const MIN_DECISIONS: u64 = 1_000_000;
const MIN_DURATION: Duration = Duration::from_secs(5);

/// Fixed representative signals covering every decision path: sensitive
/// ALLOW (full proof, low score), sensitive CHALLENGE (score in the
/// middle band), sensitive BLOCK (score >= 80), the three hard BLOCK
/// exits (dm, nr, sk), non-sensitive ALLOW and BLOCK, and the spec v2
/// sensitive signals (dd BLOCK, pi BLOCK, ac CHALLENGE).
fn representative_signals() -> Vec<Signals> {
    let clean = Signals {
        r: "pay".to_string(),
        pk: 1,
        dp: 1,
        dt: 1,
        sk: 1,
        nr: 0,
        dm: 0,
        hl: 0,
        mb: 0,
        dc: 0,
        rpm: 10,
        cov: 10,
        tv: 1.0,
        ov: 0,
        np: 0,
        amt: 1000,
        ac: 0,
        dd: 0,
        ag: 0,
        pi: 0,
        mc: 0,
        rd: 0,
    };
    let mut challenge = clean.clone();
    challenge.dp = 0; // score 30 (no device proof), no full proof
    challenge.cov = 75; // +30 -> score 60, still CHALLENGE
    let mut block_score = clean.clone();
    block_score.hl = 1; // +40
    block_score.cov = 85; // +30
    block_score.dp = 0; // +30 -> score 100 -> BLOCK
    let mut dm = clean.clone();
    dm.dm = 1;
    let mut nr = clean.clone();
    nr.nr = 1;
    let mut no_sk = clean.clone();
    no_sk.sk = 0;
    let mut view_allow = clean.clone();
    view_allow.r = "view".to_string();
    let mut view_block = clean.clone();
    view_block.r = "view".to_string();
    view_block.hl = 1; // +40
    view_block.cov = 85; // +30
    view_block.rpm = 200; // +20 +20 -> score 110 -> BLOCK
    let mut dd = clean.clone();
    dd.dd = 1;
    let mut pi = clean.clone();
    pi.pi = 1;
    let mut ac = clean.clone();
    ac.ac = 1; // score 25, never ALLOW -> CHALLENGE
    vec![
        clean,
        challenge,
        block_score,
        dm,
        nr,
        no_sk,
        view_allow,
        view_block,
        dd,
        pi,
        ac,
    ]
}

/// Peak resident memory of this process in bytes, from VmHWM.
fn peak_rss_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: u64 = rest.trim().split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

fn median(sorted: &[u64]) -> u64 {
    sorted[sorted.len() / 2]
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    let idx = ((p * sorted.len() as f64) as usize).min(sorted.len() - 1);
    sorted[idx]
}

fn main() {
    let signals = representative_signals();
    let n = signals.len();
    let mut counts = [0u64; 3]; // ALLOW, CHALLENGE, BLOCK
    let mut idx = 0usize;

    // Warmup: exercise every path before timing starts.
    for _ in 0..WARMUP_DECISIONS {
        match decide(black_box(&signals[idx])) {
            Decision::Allow => counts[0] += 1,
            Decision::Challenge => counts[1] += 1,
            Decision::Block => counts[2] += 1,
        }
        idx = (idx + 1) % n;
    }

    // Timed loop: at least MIN_DECISIONS decisions AND at least
    // MIN_DURATION elapsed, whichever is larger.
    let mut batch_ns: Vec<u64> = Vec::with_capacity(16384); // preallocated
    let mut total: u64 = 0;
    let start = Instant::now();
    while total < MIN_DECISIONS || start.elapsed() < MIN_DURATION {
        let t0 = Instant::now();
        for _ in 0..BATCH {
            match decide(black_box(&signals[idx])) {
                Decision::Allow => counts[0] += 1,
                Decision::Challenge => counts[1] += 1,
                Decision::Block => counts[2] += 1,
            }
            idx = (idx + 1) % n;
        }
        batch_ns.push(t0.elapsed().as_nanos() as u64);
        total += BATCH as u64;
    }
    let elapsed = start.elapsed();

    batch_ns.sort_unstable();
    let median_ns = median(&batch_ns) as f64 / BATCH as f64;
    let p99_ns = percentile(&batch_ns, 0.99) as f64 / BATCH as f64;
    let decisions_per_sec = total as f64 / elapsed.as_secs_f64();
    let peak_rss = peak_rss_bytes();

    println!(
        "rust bench: decisions={} batches={} batch_size={}",
        total,
        batch_ns.len(),
        BATCH
    );
    println!("rust bench: elapsed={:.3}s", elapsed.as_secs_f64());
    println!("rust bench: median decision latency={:.2} ns", median_ns);
    println!("rust bench: p99 decision latency={:.2} ns", p99_ns);
    println!("rust bench: decisions per second={:.0}", decisions_per_sec);
    match peak_rss {
        Some(bytes) => println!(
            "rust bench: peak RSS (VmHWM)={} bytes ({} KiB)",
            bytes,
            bytes / 1024
        ),
        None => println!("rust bench: peak RSS (VmHWM)=unavailable"),
    }
    println!(
        "rust bench: decision counts ALLOW={} CHALLENGE={} BLOCK={}",
        counts[0], counts[1], counts[2]
    );
    // Keep the counters observable so the timed loop cannot be
    // optimised away.
    black_box(counts);
}
