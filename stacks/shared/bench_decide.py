"""Benchmark for BankShield HumanGate Python reference decide().

Measures decide() from gate_reference directly with timeit. The
representative signal dicts are built once, at import, before any
timing, so dict construction is not measured. Timing and the sustained
memory run are separate phases: tracemalloc is only active during the
memory phase, so it cannot inflate the latency numbers.

Usage: python3 stacks/shared/bench_decide.py
"""
import os
import statistics
import sys
import timeit
import tracemalloc

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gate_reference import decide  # noqa: E402

# Representative signal dicts, built once before timing. They cover
# every branch of decide()/score(): clean allow, sensitive allow with
# full proof, sensitive challenge, high-score block, the three early
# blocks (dm / nr / missing sk), and each new gate signal
# (ac, dd, ag, pi, mc, rd) on a sensitive route, plus rpm / cov / tv
# threshold edges. All keys decide()/score() read are present.
CASES = [
    # Clean legitimate, non-sensitive, low score -> A
    {"r": "bal", "pk": 1, "dp": 1, "dt": 1, "sk": 1, "nr": 0, "dm": 0,
     "hl": 0, "mb": 0, "dc": 0, "rpm": 5, "cov": 10, "tv": 2.0,
     "ov": 0, "np": 0, "amt": 100, "ac": 0, "dd": 0, "ag": 0,
     "pi": 0, "mc": 0, "rd": 0},
    # Legitimate sensitive route, full proof, low score -> A
    {"r": "pay", "pk": 1, "dp": 1, "dt": 1, "sk": 1, "nr": 0, "dm": 0,
     "hl": 0, "mb": 0, "dc": 0, "rpm": 5, "cov": 10, "tv": 2.0,
     "ov": 0, "np": 0, "amt": 250, "ac": 0, "dd": 0, "ag": 0,
     "pi": 0, "mc": 0, "rd": 0},
    # Sensitive route, mid score, no full proof -> C
    {"r": "trf", "pk": 1, "dp": 0, "dt": 1, "sk": 1, "nr": 0, "dm": 0,
     "hl": 0, "mb": 1, "dc": 0, "rpm": 30, "cov": 40, "tv": 1.0,
     "ov": 0, "np": 0, "amt": 900, "ac": 0, "dd": 0, "ag": 0,
     "pi": 0, "mc": 0, "rd": 0},
    # Sensitive route, high score -> B
    {"r": "ben", "pk": 0, "dp": 0, "dt": 0, "sk": 1, "nr": 0, "dm": 0,
     "hl": 1, "mb": 1, "dc": 1, "rpm": 80, "cov": 80, "tv": 0.1,
     "ov": 1, "np": 1, "amt": 5000, "ac": 0, "dd": 0, "ag": 0,
     "pi": 0, "mc": 0, "rd": 0},
    # Non-sensitive, high score -> B
    {"r": "bal", "pk": 0, "dp": 0, "dt": 0, "sk": 1, "nr": 0, "dm": 0,
     "hl": 1, "mb": 0, "dc": 0, "rpm": 200, "cov": 90, "tv": 0.1,
     "ov": 0, "np": 0, "amt": 50, "ac": 0, "dd": 0, "ag": 0,
     "pi": 0, "mc": 0, "rd": 0},
    # Early block: device mismatch -> B
    {"r": "pay", "pk": 1, "dp": 1, "dt": 1, "sk": 1, "nr": 0, "dm": 1,
     "hl": 0, "mb": 0, "dc": 0, "rpm": 5, "cov": 10, "tv": 2.0,
     "ov": 0, "np": 0, "amt": 100, "ac": 0, "dd": 0, "ag": 0,
     "pi": 0, "mc": 0, "rd": 0},
    # Early block: no session key -> B
    {"r": "pay", "pk": 1, "dp": 1, "dt": 1, "sk": 0, "nr": 0, "dm": 0,
     "hl": 0, "mb": 0, "dc": 0, "rpm": 5, "cov": 10, "tv": 2.0,
     "ov": 0, "np": 0, "amt": 100, "ac": 0, "dd": 0, "ag": 0,
     "pi": 0, "mc": 0, "rd": 0},
    # Early block: new request flag -> B
    {"r": "exp", "pk": 1, "dp": 1, "dt": 1, "sk": 1, "nr": 1, "dm": 0,
     "hl": 0, "mb": 0, "dc": 0, "rpm": 5, "cov": 10, "tv": 2.0,
     "ov": 0, "np": 0, "amt": 100, "ac": 0, "dd": 0, "ag": 0,
     "pi": 0, "mc": 0, "rd": 0},
    # Sensitive + approval-workflow abuse signal, low score -> C
    {"r": "pay", "pk": 1, "dp": 1, "dt": 1, "sk": 1, "nr": 0, "dm": 0,
     "hl": 0, "mb": 0, "dc": 0, "rpm": 10, "cov": 10, "tv": 2.0,
     "ov": 0, "np": 0, "amt": 100, "ac": 1, "dd": 0, "ag": 0,
     "pi": 0, "mc": 0, "rd": 0},
    # Sensitive + disbursement diversion signal -> B
    {"r": "trf", "pk": 1, "dp": 1, "dt": 1, "sk": 1, "nr": 0, "dm": 0,
     "hl": 0, "mb": 0, "dc": 0, "rpm": 10, "cov": 10, "tv": 2.0,
     "ov": 0, "np": 0, "amt": 100, "ac": 0, "dd": 1, "ag": 0,
     "pi": 0, "mc": 0, "rd": 0},
    # Sensitive + prompt-injection signal -> B
    {"r": "sec", "pk": 1, "dp": 1, "dt": 1, "sk": 1, "nr": 0, "dm": 0,
     "hl": 0, "mb": 0, "dc": 0, "rpm": 10, "cov": 10, "tv": 2.0,
     "ov": 0, "np": 0, "amt": 100, "ac": 0, "dd": 0, "ag": 0,
     "pi": 1, "mc": 0, "rd": 0},
    # Sensitive + mule-account / rapid-drain signals -> B
    {"r": "pay", "pk": 1, "dp": 1, "dt": 1, "sk": 1, "nr": 0, "dm": 0,
     "hl": 0, "mb": 0, "dc": 0, "rpm": 10, "cov": 10, "tv": 2.0,
     "ov": 0, "np": 0, "amt": 100, "ac": 0, "dd": 0, "ag": 1,
     "pi": 0, "mc": 1, "rd": 1},
]

EXPECTED = ["A", "A", "C", "B", "B", "B", "B", "B", "C", "B", "B", "B"]


def _run_batch():
    for case in CASES:
        decide(case)


def _percentile(values, pct):
    ordered = sorted(values)
    index = (len(ordered) - 1) * pct / 100.0
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = index - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def main():
    # Sanity: every representative case must decide as expected, so the
    # benchmark is timing real decisions, not a degenerate path.
    got = [decide(case) for case in CASES]
    assert got == EXPECTED, f"unexpected decisions: {got} != {EXPECTED}"

    # Warmup (untimed): 10,000 decisions, so caches / branch state settle.
    for _ in range(10_000):
        decide(CASES[0])

    # Timed phase, via timeit, tracemalloc off. Each repeat runs the
    # whole CASES batch 1,000 times = 12,000 decisions; 101 repeats give
    # 101 per-decision latency samples for median / p99.
    repeats = 101
    number = 1000
    timer = timeit.Timer(_run_batch)
    times = timer.repeat(repeat=repeats, number=number)
    decisions_per_repeat = number * len(CASES)
    per_decision_ns = [
        t / decisions_per_repeat * 1e9 for t in times
    ]
    median_ns = statistics.median(per_decision_ns)
    p99_ns = _percentile(per_decision_ns, 99)
    decisions_per_second = 1e9 / median_ns

    # Sustained phase: at least 1,000,000 decisions, peak memory via
    # tracemalloc (peak traced bytes). Timing is not taken from this
    # phase because tracemalloc adds overhead.
    sustained = 1_000_000
    tracemalloc.start()
    count = 0
    while count < sustained:
        for case in CASES:
            decide(case)
            count += 1
            if count >= sustained:
                break
    _current, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print(f"python={sys.version.split()[0]}")
    print(f"cases={len(CASES)} repeats={repeats} "
          f"decisions_per_repeat={decisions_per_repeat}")
    print(f"median_ns_per_decision={median_ns:.1f}")
    print(f"p99_ns_per_decision={p99_ns:.1f}")
    print(f"decisions_per_second={decisions_per_second:,.0f}")
    print(f"sustained_decisions={sustained}")
    print(f"peak_memory_bytes={peak_bytes} "
          f"(tracemalloc peak traced bytes)")
    print(f"peak_memory_kib={peak_bytes / 1024:.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
