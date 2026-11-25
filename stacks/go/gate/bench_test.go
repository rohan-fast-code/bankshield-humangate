package gate

import (
	"fmt"
	"sort"
	"testing"
	"time"
)

// benchSink is a package-level sink so the compiler cannot eliminate
// the Decide/Score calls inside the benchmarks as dead code.
var benchSink int

// representativeSignals is a fixed set of signals covering every
// decision path: sensitive ALLOW (full proof, low score), sensitive
// CHALLENGE (score in the middle band), sensitive BLOCK (score >= 80),
// the three hard BLOCK exits (dm, nr, sk), non-sensitive ALLOW and
// BLOCK, and the spec v2 sensitive signals (dd BLOCK, pi BLOCK,
// ac CHALLENGE). The set is built once, outside the timed region, so
// no allocation or setup work is measured.
func representativeSignals() []Signals {
	clean := Signals{
		Route:          "pay",
		Passkey:        1,
		DeviceProof:    1,
		DeviceToken:    1,
		SessionKey:     1,
		NonceReplayed:  0,
		DeviceMismatch: 0,
		Headless:       0,
		MissingBrowser: 0,
		Datacenter:     0,
		RPM:            10,
		Coverage:       10,
		TimingVariance: 1.0,
		Overlay:        0,
		NewPayee:       0,
		Amount:         1000,
	}
	challenge := clean
	challenge.DeviceProof = 0 // score 30 (no device proof), no full proof -> CHALLENGE
	challenge.Coverage = 75   // +30 -> score 60, still CHALLENGE
	blockScore := clean
	blockScore.Headless = 1    // +40
	blockScore.Coverage = 85   // +30
	blockScore.DeviceProof = 0 // +30 -> score 100 -> BLOCK
	dm := clean
	dm.DeviceMismatch = 1
	nr := clean
	nr.NonceReplayed = 1
	noSK := clean
	noSK.SessionKey = 0
	viewAllow := clean
	viewAllow.Route = "view"
	viewBlock := clean
	viewBlock.Route = "view"
	viewBlock.Headless = 1  // +40
	viewBlock.Coverage = 85 // +30
	viewBlock.RPM = 200     // +20 +20 -> score 110 -> BLOCK
	dd := clean
	dd.DestChanged = 1
	pi := clean
	pi.PromptInjection = 1
	ac := clean
	ac.ApprovalChanged = 1 // score 25, never ALLOW -> CHALLENGE
	return []Signals{
		clean, challenge, blockScore, dm, nr, noSK,
		viewAllow, viewBlock, dd, pi, ac,
	}
}

// BenchmarkDecide measures the gate decision over the fixed
// representative signal set, cycling through it so every decision
// path is exercised. The testing harness warms up and calibrates the
// run itself; b.ReportAllocs reports allocations per op.
func BenchmarkDecide(b *testing.B) {
	signals := representativeSignals()
	b.ReportAllocs()
	b.ResetTimer()
	sink := 0
	for i := 0; i < b.N; i++ {
		sink += len(Decide(signals[i%len(signals)]))
	}
	benchSink = sink
}

// BenchmarkScore measures Score alone over the same fixed set.
func BenchmarkScore(b *testing.B) {
	signals := representativeSignals()
	b.ReportAllocs()
	b.ResetTimer()
	sink := 0
	for i := 0; i < b.N; i++ {
		sink += Score(signals[i%len(signals)])
	}
	benchSink = sink
}

// BenchmarkDecideLatency collects per-decision latency honestly: it
// times batches of 1000 decisions (timing a single ~nanosecond call
// with time.Now would drown the measurement in clock overhead),
// stores each batch time in a preallocated buffer, sorts the buffer,
// and reports the median and p99 batch time divided by the batch size.
// Method: 100 warmup batches, then 5000 timed batches of 1000
// decisions = 5,000,000 decisions. Printed with fmt so the numbers
// appear in plain `go test -bench` output without -v.
func BenchmarkDecideLatency(b *testing.B) {
	signals := representativeSignals()
	const batchSize = 1000
	const warmupBatches = 100
	const timedBatches = 5000

	// Warmup: exercise every path before timing starts.
	idx := 0
	sink := 0
	for w := 0; w < warmupBatches; w++ {
		for j := 0; j < batchSize; j++ {
			sink += len(Decide(signals[idx%len(signals)]))
			idx++
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	times := make([]int64, 0, timedBatches) // preallocated batch buffer
	start := time.Now()
	for n := 0; n < timedBatches; n++ {
		t0 := time.Now()
		for j := 0; j < batchSize; j++ {
			sink += len(Decide(signals[idx%len(signals)]))
			idx++
		}
		times = append(times, time.Since(t0).Nanoseconds())
	}
	elapsed := time.Since(start)
	benchSink = sink

	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	median := float64(times[len(times)/2]) / batchSize
	p99 := float64(times[int(0.99*float64(len(times)))]) / batchSize
	total := int64(timedBatches) * batchSize
	dps := float64(total) / elapsed.Seconds()
	fmt.Printf("decide latency: decisions=%d batches=%d batch_size=%d median=%.2f ns p99=%.2f ns decisions_per_sec=%.0f\n",
		total, timedBatches, batchSize, median, p99, dps)
}
