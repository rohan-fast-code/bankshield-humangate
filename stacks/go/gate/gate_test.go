package gate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// vectorCase mirrors the shared test vector file format:
//
//	{"i":1,"g":"FRAUD","k":"a","t":"template","s":{...signals...},"e":"B"}
//
// where e is A = ALLOW, C = CHALLENGE, B = BLOCK.
type vectorCase struct {
	I int     `json:"i"`
	G string  `json:"g"`
	K string  `json:"k"`
	T string  `json:"t"`
	S Signals `json:"s"`
	E string  `json:"e"`
}

func expectedDecision(code string) string {
	switch code {
	case "A":
		return Allow
	case "C":
		return Challenge
	case "B":
		return Block
	default:
		return ""
	}
}

func vectorsPath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("BSG_VECTORS"); p != "" {
		return p
	}
	// Default: ../../shared/test_vectors.json relative to this package directory.
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "shared", "test_vectors.json")
}

// TestVectors loads the shared vector file, asserts every case, counts
// outcomes, and logs the total verified count.
func TestVectors(t *testing.T) {
	path := vectorsPath(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read test vectors from %s: %v", path, err)
	}
	var cases []vectorCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatalf("failed to parse test vectors from %s: %v", path, err)
	}
	if len(cases) == 0 {
		t.Fatalf("no test vectors found in %s", path)
	}

	var counts = map[string]int{
		Allow:     0,
		Challenge: 0,
		Block:     0,
	}

	for _, c := range cases {
		want := expectedDecision(c.E)
		if want == "" {
			t.Fatalf("case %d: unknown expected code %q", c.I, c.E)
		}
		got := Decide(c.S)
		counts[got]++
		if got != want {
			t.Errorf("case %d (g=%q k=%q t=%q): Decide(%+v) = %s (score=%d), want %s (code %s)",
				c.I, c.G, c.K, c.T, c.S, got, Score(c.S), want, c.E)
		}
	}

	t.Logf("verified %d test vectors: ALLOW=%d CHALLENGE=%d BLOCK=%d",
		len(cases), counts[Allow], counts[Challenge], counts[Block])
}

// cleanSensitive returns a clean, fully proved sensitive signal set.
func cleanSensitive() Signals {
	return Signals{
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
}

func TestHardBlockDeviceMismatch(t *testing.T) {
	s := cleanSensitive()
	s.DeviceMismatch = 1
	if got := Decide(s); got != Block {
		t.Errorf("dm==1: Decide = %s, want %s", got, Block)
	}
}

func TestHardBlockNonceReplayed(t *testing.T) {
	s := cleanSensitive()
	s.NonceReplayed = 1
	if got := Decide(s); got != Block {
		t.Errorf("nr==1: Decide = %s, want %s", got, Block)
	}
}

func TestHardBlockSessionKeyInvalid(t *testing.T) {
	s := cleanSensitive()
	s.SessionKey = 0
	if got := Decide(s); got != Block {
		t.Errorf("sk==0: Decide = %s, want %s", got, Block)
	}
}

func TestSensitiveFullProofAllow(t *testing.T) {
	s := cleanSensitive()
	if got := Score(s); got != 0 {
		t.Errorf("clean sensitive: Score = %d, want 0", got)
	}
	if got := Decide(s); got != Allow {
		t.Errorf("sensitive full proof with low score: Decide = %s, want %s", got, Allow)
	}
}
