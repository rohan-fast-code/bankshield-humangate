/**
 * BankShield HumanGate: TypeScript implementation of the shared gate
 * specification v2 (docs/GATE_SPEC.md).
 *
 * This is a demo implementation operating on synthetic signals only.
 * It must not be used with real bank data or as a production security
 * control.
 *
 * Mirrors the Python reference (stacks/shared/gate_reference.py), the Go
 * implementation (stacks/go/gate/gate.go), and the Rust implementation
 * (stacks/rust/src/lib.rs). All four must agree on every shared test
 * vector.
 *
 * Performance: decide() is constant time per request: fixed straight-line
 * arithmetic over the signal fields, with no loops, no input/output, no
 * regular expressions, and no per-request allocation in the hot path (it
 * returns a string literal and reads only the caller's signals object).
 * All risk weights and decision thresholds below are constants built once
 * at module load, and SENSITIVE_ROUTES is a Set built once at module
 * load, so nothing is recomputed or rebuilt per request. The runtime gate
 * never loads the shared test vector file; vectors are test data only.
 *
 * Uses only erasable TypeScript syntax (interfaces and type annotations;
 * no enums, namespaces, or parameter properties) so it runs directly
 * under Node 24 native TypeScript support with no build step.
 */

/** Signals for a single gate evaluation, using the short field names from the spec. */
export interface Signals {
  /** Route code: pay, trf, ben, exp, sec are sensitive; view, login, prof are not. */
  r: string;
  /** Passkey proof present and valid (0 or 1). */
  pk: number;
  /** Device proof (attestation) valid (0 or 1). */
  dp: number;
  /** Device bound token valid (0 or 1). */
  dt: number;
  /** Session key signature valid for this exact request (0 or 1). */
  sk: number;
  /** Nonce replayed (0 or 1). */
  nr: number;
  /** Token device mismatch (0 or 1). */
  dm: number;
  /** Headless or automated browser signal (0 or 1). */
  hl: number;
  /** Missing browser signals (0 or 1). */
  mb: number;
  /** Datacenter IP (0 or 1). */
  dc: number;
  /** Requests per minute from this session. */
  rpm: number;
  /** API coverage percent in the current window. */
  cov: number;
  /** Timing variance in seconds. */
  tv: number;
  /** Overlay or accessibility abuse detected (0 or 1). */
  ov: number;
  /** New payee (0 or 1). */
  np: number;
  /** Approval relationship or beneficiary changed recently (0 or 1). Optional, defaults to 0. */
  ac?: number;
  /** Disbursement destination changed from the approved destination (0 or 1). Optional, defaults to 0. */
  dd?: number;
  /** Agent acting beyond its authorized task scope (0 or 1). Optional, defaults to 0. */
  ag?: number;
  /** Inbound content contains embedded instructions (0 or 1). Optional, defaults to 0. */
  pi?: number;
  /** Mule chain pattern, rapid hops across accounts (0 or 1). Optional, defaults to 0. */
  mc?: number;
  /** Record deletion or tampering attempt (0 or 1). Optional, defaults to 0. */
  rd?: number;
  /** Amount in rupees. Informational only, never scored. */
  amt: number;
}

export type Decision = "ALLOW" | "CHALLENGE" | "BLOCK";

/** Sensitive routes under the shared spec: pay, trf, ben, exp, sec. Built once at module load; never rebuilt per request. */
const SENSITIVE_ROUTES: ReadonlySet<string> = new Set([
  "pay",
  "trf",
  "ben",
  "exp",
  "sec",
]);

// Risk weights and decision thresholds from the shared spec, as constants
// precomputed at module load (see file header). Values and decision order
// are fixed by the spec and must not change.
const WEIGHTS = {
  HEADLESS: 40,
  MISSING_BROWSER: 15,
  DATACENTER: 10,
  RPM_OVER_60: 20,
  RPM_OVER_150: 20,
  COVERAGE_OVER_70: 30,
  LOW_TIMING_VARIANCE: 25,
  OVERLAY: 20,
  NEW_PAYEE: 15,
  NO_DEVICE_PROOF: 30,
  NO_DEVICE_TOKEN: 20,
  APPROVAL_CHANGED: 25,
  DISBURSEMENT_CHANGED: 50,
  AGENT_BEYOND_SCOPE: 35,
  PROMPT_INJECTION: 45,
  MULE_CHAIN: 40,
  RECORD_DELETION: 40,
};
/** Full proof on a sensitive route ALLOWs only when score is below this. */
const ALLOW_SCORE_LIMIT = 50;
/** Score at or above this BLOCKs (sensitive route, or any non-sensitive route). */
const BLOCK_SCORE = 80;

export function isSensitive(route: string): boolean {
  return SENSITIVE_ROUTES.has(route);
}

/**
 * Compute the risk score exactly as specified.
 *
 * hl=1 adds 40; mb=1 adds 15; dc=1 adds 10; rpm>60 adds 20;
 * rpm>150 adds 20 more; cov>70 adds 30; tv<0.2 and rpm>20 adds 25;
 * ov=1 adds 20; np=1 adds 15; dp=0 adds 30; dt=0 adds 20;
 * ac=1 adds 25; dd=1 adds 50; ag=1 adds 35; pi=1 adds 45;
 * mc=1 adds 40; rd=1 adds 40.
 * amt is never scored.
 */
export function score(s: Signals): number {
  let total = 0;
  if (s.hl === 1) total += WEIGHTS.HEADLESS;
  if (s.mb === 1) total += WEIGHTS.MISSING_BROWSER;
  if (s.dc === 1) total += WEIGHTS.DATACENTER;
  if (s.rpm > 60) total += WEIGHTS.RPM_OVER_60;
  if (s.rpm > 150) total += WEIGHTS.RPM_OVER_150;
  if (s.cov > 70) total += WEIGHTS.COVERAGE_OVER_70;
  if (s.tv < 0.2 && s.rpm > 20) total += WEIGHTS.LOW_TIMING_VARIANCE;
  if (s.ov === 1) total += WEIGHTS.OVERLAY;
  if (s.np === 1) total += WEIGHTS.NEW_PAYEE;
  if (s.dp === 0) total += WEIGHTS.NO_DEVICE_PROOF;
  if (s.dt === 0) total += WEIGHTS.NO_DEVICE_TOKEN;
  if ((s.ac ?? 0) === 1) total += WEIGHTS.APPROVAL_CHANGED;
  if ((s.dd ?? 0) === 1) total += WEIGHTS.DISBURSEMENT_CHANGED;
  if ((s.ag ?? 0) === 1) total += WEIGHTS.AGENT_BEYOND_SCOPE;
  if ((s.pi ?? 0) === 1) total += WEIGHTS.PROMPT_INJECTION;
  if ((s.mc ?? 0) === 1) total += WEIGHTS.MULE_CHAIN;
  if ((s.rd ?? 0) === 1) total += WEIGHTS.RECORD_DELETION;
  return total;
}

/**
 * Decide ALLOW, CHALLENGE, or BLOCK for the given signals.
 *
 * Decision order is exactly as specified and must not be reordered:
 *
 * 1. dm=1 -> BLOCK on any route.
 * 2. nr=1 -> BLOCK on any route.
 * 3. sk=0 -> BLOCK on any route.
 * 4. Sensitive route: dd=1 -> BLOCK; mc=1 -> BLOCK; rd=1 -> BLOCK;
 *    pi=1 -> BLOCK; ag=1 -> BLOCK; ac=1 -> never ALLOW (CHALLENGE at
 *    minimum; BLOCK if the score reaches 80).
 * 5. Sensitive route: full proof means pk=1 and dp=1 and dt=1.
 *    Full proof and score<50 -> ALLOW; score>=80 -> BLOCK;
 *    anything else -> CHALLENGE.
 * 6. Non-sensitive route: score>=80 -> BLOCK, anything else -> ALLOW.
 */
export function decide(s: Signals): Decision {
  if (s.dm === 1) return "BLOCK";
  if (s.nr === 1) return "BLOCK";
  if (s.sk === 0) return "BLOCK";

  const value = score(s);

  if (isSensitive(s.r)) {
    if ((s.dd ?? 0) === 1) return "BLOCK";
    if ((s.mc ?? 0) === 1) return "BLOCK";
    if ((s.rd ?? 0) === 1) return "BLOCK";
    if ((s.pi ?? 0) === 1) return "BLOCK";
    if ((s.ag ?? 0) === 1) return "BLOCK";
    if ((s.ac ?? 0) === 1) {
      if (value >= BLOCK_SCORE) return "BLOCK";
      return "CHALLENGE";
    }
    const fullProof = s.pk === 1 && s.dp === 1 && s.dt === 1;
    if (fullProof && value < ALLOW_SCORE_LIMIT) return "ALLOW";
    if (value >= BLOCK_SCORE) return "BLOCK";
    return "CHALLENGE";
  }

  if (value >= BLOCK_SCORE) return "BLOCK";
  return "ALLOW";
}
