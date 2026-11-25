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
	// Spec v2 signals (default 0 when absent from a vector).
	ApprovalChanged int `json:"ac"`
	DestChanged     int `json:"dd"`
	AgentScope      int `json:"ag"`
	PromptInjection int `json:"pi"`
	MuleChain       int `json:"mc"`
	RecordDeletion  int `json:"rd"`
}

// Decision values returned by Decide.
const (
	Allow     = "ALLOW"
	Challenge = "CHALLENGE"
	Block     = "BLOCK"
)

// Risk weights (spec v2) as compile-time constants.
//
// Performance note: the gate decision is O(1) per request. All risk
// weights are compile-time constants, the sensitive-route check below
// is a constant switch table, and Decide/Score do fixed straight-line
// arithmetic over the signal fields only: no loops, no I/O, no regular
// expressions, and no per-request allocation in the hot path. Nothing
// is computed per request that could be precomputed. The runtime gate
// never loads the shared test vector file; vectors are test data only.
const (
	weightHeadless        = 40
	weightMissingBrowser  = 15
	weightDatacenter      = 10
	weightRPMOver60       = 20
	weightRPMOver150      = 20
	weightCoverageOver70  = 30
	weightLowTimingVar    = 25
	weightOverlay         = 20
	weightNewPayee        = 15
	weightNoDeviceProof   = 30
	weightNoDeviceToken   = 20
	weightApprovalChanged = 25
	weightDestChanged     = 50
	weightAgentScope      = 35
	weightPromptInjection = 45
	weightMuleChain       = 40
	weightRecordDeletion  = 40
)

// IsSensitive reports whether a route is sensitive under the shared spec.
// Sensitive routes are: pay, trf, ben, exp, sec.
// Non-sensitive routes include: view, login, prof.
// The route set is a constant switch table, evaluated per request with
// no allocation, no I/O, and no lookup over any runtime data.
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
// Spec v2 additions:
//
//	ac == 1              adds 25
//	dd == 1              adds 50
//	ag == 1              adds 35
//	pi == 1              adds 45
//	mc == 1              adds 40
//	rd == 1              adds 40
//
// The amount (amt) is never scored.
func Score(s Signals) int {
	score := 0
	if s.Headless == 1 {
		score += weightHeadless
	}
	if s.MissingBrowser == 1 {
		score += weightMissingBrowser
	}
	if s.Datacenter == 1 {
		score += weightDatacenter
	}
	if s.RPM > 60 {
		score += weightRPMOver60
	}
	if s.RPM > 150 {
		score += weightRPMOver150
	}
	if s.Coverage > 70 {
		score += weightCoverageOver70
	}
	if s.TimingVariance < 0.2 && s.RPM > 20 {
		score += weightLowTimingVar
	}
	if s.Overlay == 1 {
		score += weightOverlay
	}
	if s.NewPayee == 1 {
		score += weightNewPayee
	}
	if s.DeviceProof == 0 {
		score += weightNoDeviceProof
	}
	if s.DeviceToken == 0 {
		score += weightNoDeviceToken
	}
	if s.ApprovalChanged == 1 {
		score += weightApprovalChanged
	}
	if s.DestChanged == 1 {
		score += weightDestChanged
	}
	if s.AgentScope == 1 {
		score += weightAgentScope
	}
	if s.PromptInjection == 1 {
		score += weightPromptInjection
	}
	if s.MuleChain == 1 {
		score += weightMuleChain
	}
	if s.RecordDeletion == 1 {
		score += weightRecordDeletion
	}
	return score
}

// Decide returns ALLOW, CHALLENGE, or BLOCK for the given signals.
//
// Decide is O(1) per request: fixed straight-line checks, no loops,
// no I/O, no regular expressions, and no per-request allocation; the
// score is computed once by Score and reused for the threshold checks.
//
// Decision order is exactly as specified and must not be reordered:
//
//  1. dm == 1 -> BLOCK
//  2. nr == 1 -> BLOCK
//  3. sk == 0 -> BLOCK
//  4. Sensitive route: dd == 1 -> BLOCK; mc == 1 -> BLOCK; rd == 1 -> BLOCK;
//     pi == 1 -> BLOCK; ag == 1 -> BLOCK; ac == 1 -> never ALLOW (CHALLENGE
//     at minimum; BLOCK if score >= 80).
//  5. Sensitive route: full proof means pk == 1 && dp == 1 && dt == 1.
//     If full proof and score < 50 -> ALLOW;
//     else if score >= 80 -> BLOCK;
//     else -> CHALLENGE.
//  6. Non-sensitive route: score >= 80 -> BLOCK, else -> ALLOW.
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
		if s.DestChanged == 1 {
			return Block
		}
		if s.MuleChain == 1 {
			return Block
		}
		if s.RecordDeletion == 1 {
			return Block
		}
		if s.PromptInjection == 1 {
			return Block
		}
		if s.AgentScope == 1 {
			return Block
		}
		if s.ApprovalChanged == 1 {
			if score >= 80 {
				return Block
			}
			return Challenge
		}
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
