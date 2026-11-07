// Package gate implements the shared BankShield HumanGate gate specification.
//
// This is a demo implementation operating on synthetic signals only.
// It must not be used with real bank data or as a production security control.
package gate

// Signals holds the synthetic signals for a single gate evaluation.
//
// Boolean-like fields are encoded as ints with values 0 or 1, matching the
// shared test vector format. The Amount field is informational only and is
// never scored.
type Signals struct {
	Route          string  `json:"r"`
	Passkey        int     `json:"pk"`
	DeviceProof    int     `json:"dp"`
	DeviceToken    int     `json:"dt"`
	SessionKey     int     `json:"sk"`
	NonceReplayed  int     `json:"nr"`
	DeviceMismatch int     `json:"dm"`
	Headless       int     `json:"hl"`
	MissingBrowser int     `json:"mb"`
	Datacenter     int     `json:"dc"`
	RPM            int     `json:"rpm"`
	Coverage       int     `json:"cov"`
	TimingVariance float64 `json:"tv"`
	Overlay        int     `json:"ov"`
	NewPayee       int     `json:"np"`
	Amount         float64 `json:"amt"`
}

// Decision values returned by Decide.
const (
	Allow     = "ALLOW"
	Challenge = "CHALLENGE"
	Block     = "BLOCK"
)

// IsSensitive reports whether a route is sensitive under the shared spec.
// Sensitive routes are: pay, trf, ben, exp, sec.
// Non-sensitive routes include: view, login, prof.
func IsSensitive(route string) bool {
	switch route {
	case "pay", "trf", "ben", "exp", "sec":
		return true
	default:
		return false
	}
}

// Score computes the risk score for the given signals.
//
// Scoring rules from the shared specification:
//
//	hl == 1              adds 40
//	mb == 1              adds 15
//	dc == 1              adds 10
//	rpm > 60             adds 20
//	rpm > 150            adds another 20
//	cov > 70             adds 30
//	tv < 0.2 && rpm > 20 adds 25
//	ov == 1              adds 20
//	np == 1              adds 15
//	dp == 0              adds 30
//	dt == 0              adds 20
//
// The amount (amt) is never scored.
func Score(s Signals) int {
	score := 0
	if s.Headless == 1 {
		score += 40
	}
	if s.MissingBrowser == 1 {
		score += 15
	}
	if s.Datacenter == 1 {
		score += 10
	}
	if s.RPM > 60 {
		score += 20
	}
	if s.RPM > 150 {
		score += 20
	}
	if s.Coverage > 70 {
		score += 30
	}
	if s.TimingVariance < 0.2 && s.RPM > 20 {
		score += 25
	}
	if s.Overlay == 1 {
		score += 20
	}
	if s.NewPayee == 1 {
		score += 15
	}
	if s.DeviceProof == 0 {
		score += 30
	}
	if s.DeviceToken == 0 {
		score += 20
	}
	return score
}

// Decide returns ALLOW, CHALLENGE, or BLOCK for the given signals.
//
// Decision order is exactly as specified and must not be reordered:
//
//  1. dm == 1 -> BLOCK
//  2. nr == 1 -> BLOCK
//  3. sk == 0 -> BLOCK
//  4. Sensitive route: full proof means pk == 1 && dp == 1 && dt == 1.
//     If full proof and score < 50 -> ALLOW;
//     else if score >= 80 -> BLOCK;
//     else -> CHALLENGE.
//  5. Non-sensitive route: score >= 80 -> BLOCK, else -> ALLOW.
func Decide(s Signals) string {
	if s.DeviceMismatch == 1 {
		return Block
	}
	if s.NonceReplayed == 1 {
		return Block
	}
	if s.SessionKey == 0 {
		return Block
	}

	score := Score(s)

	if IsSensitive(s.Route) {
		fullProof := s.Passkey == 1 && s.DeviceProof == 1 && s.DeviceToken == 1
		if fullProof && score < 50 {
			return Allow
		}
		if score >= 80 {
			return Block
		}
		return Challenge
	}

	if score >= 80 {
		return Block
	}
	return Allow
}
