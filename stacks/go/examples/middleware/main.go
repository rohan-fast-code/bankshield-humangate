// Command middleware is a demo net/http middleware for the BankShield
// HumanGate Go gate implementation.
//
// Demo only: it builds synthetic Signals from simple request headers and
// calls gate.Decide. It is not a production security control and must not
// be used with real bank data. Header names are a simple demo convention,
// not a real attestation protocol; a real system would need proper
// cryptographic proofs verified server side.
//
// Headers read (all optional, booleans and ints as decimal strings):
//
//	X-Route            route code, e.g. pay, trf, ben, exp, sec, view, login, prof
//	X-Passkey          pk  (0/1)
//	X-Device-Proof     dp  (0/1)
//	X-Device-Token     dt  (0/1)
//	X-Session-Key      sk  (0/1)
//	X-Nonce-Replayed   nr  (0/1)
//	X-Device-Mismatch  dm  (0/1)
//	X-Headless         hl  (0/1)
//	X-Missing-Browser  mb  (0/1)
//	X-Datacenter       dc  (0/1)
//	X-RPM              rpm (int, requests per minute)
//	X-Coverage         cov (int, API coverage percent)
//	X-Timing-Variance  tv  (float, seconds)
//	X-Overlay          ov  (0/1)
//	X-New-Payee        np  (0/1)
//	X-Amount           amt (float, rupees, informational only)
package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"

	"bankshield/stacks/go/gate"
)

func parseIntHeader(r *http.Request, name string) int {
	v := r.Header.Get(name)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}

func parseFloatHeader(r *http.Request, name string) float64 {
	v := r.Header.Get(name)
	if v == "" {
		return 0
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0
	}
	return f
}

// SignalsFromRequest builds gate.Signals from the demo headers.
func SignalsFromRequest(r *http.Request) gate.Signals {
	route := r.Header.Get("X-Route")
	if route == "" {
		route = "view"
	}
	return gate.Signals{
		Route:          route,
		Passkey:        parseIntHeader(r, "X-Passkey"),
		DeviceProof:    parseIntHeader(r, "X-Device-Proof"),
		DeviceToken:    parseIntHeader(r, "X-Device-Token"),
		SessionKey:     parseIntHeader(r, "X-Session-Key"),
		NonceReplayed:  parseIntHeader(r, "X-Nonce-Replayed"),
		DeviceMismatch: parseIntHeader(r, "X-Device-Mismatch"),
		Headless:       parseIntHeader(r, "X-Headless"),
		MissingBrowser: parseIntHeader(r, "X-Missing-Browser"),
		Datacenter:     parseIntHeader(r, "X-Datacenter"),
		RPM:            parseIntHeader(r, "X-RPM"),
		Coverage:       parseIntHeader(r, "X-Coverage"),
		TimingVariance: parseFloatHeader(r, "X-Timing-Variance"),
		Overlay:        parseIntHeader(r, "X-Overlay"),
		NewPayee:       parseIntHeader(r, "X-New-Payee"),
		Amount:         parseFloatHeader(r, "X-Amount"),
	}
}

// Middleware wraps a handler with the gate decision.
//
//	BLOCK     -> 403 Forbidden
//	CHALLENGE -> 401 with a challenge body
//	ALLOW     -> passes through to the next handler
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := SignalsFromRequest(r)
		switch gate.Decide(s) {
		case gate.Block:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, `{"decision":"BLOCK"}`)
			return
		case gate.Challenge:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, `{"decision":"CHALLENGE","challenge":"additional verification required"}`)
			return
		default: // ALLOW
			next.ServeHTTP(w, r)
			return
		}
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"decision":"ALLOW","message":"ok"}`)
	})

	addr := ":8080"
	log.Printf("BankShield HumanGate Go demo middleware listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, Middleware(mux)))
}
