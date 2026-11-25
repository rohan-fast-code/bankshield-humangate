package com.bankshield.gate;

import java.util.Set;

/**
 * Java implementation of the shared BankShield HumanGate gate specification v2
 * (see {@code docs/GATE_SPEC.md}).
 *
 * <p>Mirrors the Go implementation in {@code stacks/go/gate/gate.go} and the
 * Python reference in {@code stacks/shared/gate_reference.py}: the same
 * signals, the same risk score, and the same decision order, verified
 * against the same shared test vectors.
 *
 * <p>Performance (see {@code docs/GATE_SPEC.md} for the fixed rules):
 * {@link #decide(Signals)} is constant time per request: fixed straight-line
 * arithmetic over the signal fields, with no loops, no input/output, no
 * regular expressions, and no per-request allocation in the hot path (it
 * returns a pre-existing enum value and reads only the caller's record).
 * All risk weights and decision thresholds below are compile-time
 * {@code static final} constants, and {@link #SENSITIVE_ROUTES} is an
 * immutable set built once at class load, so nothing is recomputed or
 * rebuilt per request. The runtime gate never loads the shared test
 * vector file; vectors are test data only.
 *
 * <p>Demo only: this operates on synthetic signals only. It must not be used
 * with real bank data or as a production security control.
 */
public final class Gate {

    /** Sensitive routes: pay, trf, ben, exp, sec. Built once at class load; never rebuilt per request. */
    public static final Set<String> SENSITIVE_ROUTES = Set.of("pay", "trf", "ben", "exp", "sec");

    // Risk weights and decision thresholds from the shared spec, as
    // compile-time constants precomputed at class load (see class javadoc).
    // Values and decision order are fixed by the spec and must not change.
    private static final int W_HEADLESS = 40;
    private static final int W_MISSING_BROWSER = 15;
    private static final int W_DATACENTER = 10;
    private static final int W_RPM_OVER_60 = 20;
    private static final int W_RPM_OVER_150 = 20;
    private static final int W_COVERAGE_OVER_70 = 30;
    private static final int W_LOW_TIMING_VARIANCE = 25;
    private static final int W_OVERLAY = 20;
    private static final int W_NEW_PAYEE = 15;
    private static final int W_NO_DEVICE_PROOF = 30;
    private static final int W_NO_DEVICE_TOKEN = 20;
    private static final int W_APPROVAL_CHANGED = 25;
    private static final int W_DISBURSEMENT_CHANGED = 50;
    private static final int W_AGENT_BEYOND_SCOPE = 35;
    private static final int W_PROMPT_INJECTION = 45;
    private static final int W_MULE_CHAIN = 40;
    private static final int W_RECORD_DELETION = 40;
    /** Full proof on a sensitive route ALLOWs only when score is below this. */
    private static final int ALLOW_SCORE_LIMIT = 50;
    /** Score at or above this BLOCKs (sensitive route, or any non-sensitive route). */
    private static final int BLOCK_SCORE = 80;

    private Gate() {
        // Utility class; no instances.
    }

    /** Decisions returned by {@link #decide(Signals)}. */
    public enum Decision {
        ALLOW,
        CHALLENGE,
        BLOCK;

        /** The single-letter code used in the shared vector file: A, C, B. */
        public String code() {
            return switch (this) {
                case ALLOW -> "A";
                case CHALLENGE -> "C";
                case BLOCK -> "B";
            };
        }

        /** Parse a vector-file code ("A", "C", or "B") into a decision. */
        public static Decision fromCode(String code) {
            return switch (code) {
                case "A" -> ALLOW;
                case "C" -> CHALLENGE;
                case "B" -> BLOCK;
                default -> throw new IllegalArgumentException("unknown decision code: " + code);
            };
        }
    }

    /**
     * The synthetic signals for a single gate evaluation.
     *
     * <p>Boolean-like fields are encoded as ints with values 0 or 1, matching
     * the shared test vector format. {@code amount} is informational only and
     * is never scored.
     *
     * @param route          route code, e.g. "pay", "view", "login"
     * @param passkey        pk: passkey proof present and valid
     * @param deviceProof    dp: device proof (attestation) valid
     * @param deviceToken    dt: device bound token valid
     * @param sessionKey     sk: session key signature valid for this exact request
     * @param nonceReplayed  nr: nonce replayed (this nonce was already used)
     * @param deviceMismatch dm: token device mismatch (token used on a different device)
     * @param headless       hl: headless or automated browser signal
     * @param missingBrowser mb: missing browser signals
     * @param datacenter     dc: datacenter IP
     * @param rpm            requests per minute from this session
     * @param coverage       cov: API coverage percent in the current window
     * @param timingVariance tv: timing variance in seconds (low values mean machine-regular timing)
     * @param overlay        ov: overlay or accessibility abuse detected during entry
     * @param newPayee       np: new payee (payee was added recently, money routes)
     * @param approvalChanged ac: an approval relationship or beneficiary was changed recently
     * @param disbursementDestinationChanged dd: the disbursement destination was changed
     *                       from the approved destination
     * @param agentBeyondScope ag: an agent is acting beyond its authorized task scope
     * @param promptInjection pi: inbound content contains embedded instructions
     * @param muleChain      mc: a mule chain pattern, rapid hops across accounts
     * @param recordDeletion rd: a record deletion or tampering attempt
     * @param amount         amt: amount in rupees, informational only, never scored
     */
    public record Signals(
            String route,
            int passkey,
            int deviceProof,
            int deviceToken,
            int sessionKey,
            int nonceReplayed,
            int deviceMismatch,
            int headless,
            int missingBrowser,
            int datacenter,
            int rpm,
            int coverage,
            double timingVariance,
            int overlay,
            int newPayee,
            int approvalChanged,
            int disbursementDestinationChanged,
            int agentBeyondScope,
            int promptInjection,
            int muleChain,
            int recordDeletion,
            double amount) {

        /** A clean, fully proved payment: full proof, low risk, score 0. */
        public static Signals cleanPayment() {
            return new Signals("pay", 1, 1, 1, 1, 0, 0, 0, 0, 0, 10, 10, 1.0, 0, 0,
                    0, 0, 0, 0, 0, 0, 1000);
        }
    }

    /** Reports whether a route is sensitive under the shared spec. */
    public static boolean isSensitive(String route) {
        return SENSITIVE_ROUTES.contains(route);
    }

    /**
     * Computes the risk score for the given signals.
     *
     * <p>Scoring rules from the shared specification:
     * <ul>
     *   <li>hl == 1 adds 40</li>
     *   <li>mb == 1 adds 15</li>
     *   <li>dc == 1 adds 10</li>
     *   <li>rpm &gt; 60 adds 20</li>
     *   <li>rpm &gt; 150 adds another 20</li>
     *   <li>cov &gt; 70 adds 30</li>
     *   <li>tv &lt; 0.2 and rpm &gt; 20 adds 25</li>
     *   <li>ov == 1 adds 20</li>
     *   <li>np == 1 adds 15</li>
     *   <li>dp == 0 adds 30</li>
     *   <li>dt == 0 adds 20</li>
     *   <li>ac == 1 adds 25</li>
     *   <li>dd == 1 adds 50</li>
     *   <li>ag == 1 adds 35</li>
     *   <li>pi == 1 adds 45</li>
     *   <li>mc == 1 adds 40</li>
     *   <li>rd == 1 adds 40</li>
     * </ul>
     * The amount (amt) is never scored.
     */
    public static int score(Signals s) {
        int total = 0;
        if (s.headless() == 1) {
            total += W_HEADLESS;
        }
        if (s.missingBrowser() == 1) {
            total += W_MISSING_BROWSER;
        }
        if (s.datacenter() == 1) {
            total += W_DATACENTER;
        }
        if (s.rpm() > 60) {
            total += W_RPM_OVER_60;
        }
        if (s.rpm() > 150) {
            total += W_RPM_OVER_150;
        }
        if (s.coverage() > 70) {
            total += W_COVERAGE_OVER_70;
        }
        if (s.timingVariance() < 0.2 && s.rpm() > 20) {
            total += W_LOW_TIMING_VARIANCE;
        }
        if (s.overlay() == 1) {
            total += W_OVERLAY;
        }
        if (s.newPayee() == 1) {
            total += W_NEW_PAYEE;
        }
        if (s.deviceProof() == 0) {
            total += W_NO_DEVICE_PROOF;
        }
        if (s.deviceToken() == 0) {
            total += W_NO_DEVICE_TOKEN;
        }
        if (s.approvalChanged() == 1) {
            total += W_APPROVAL_CHANGED;
        }
        if (s.disbursementDestinationChanged() == 1) {
            total += W_DISBURSEMENT_CHANGED;
        }
        if (s.agentBeyondScope() == 1) {
            total += W_AGENT_BEYOND_SCOPE;
        }
        if (s.promptInjection() == 1) {
            total += W_PROMPT_INJECTION;
        }
        if (s.muleChain() == 1) {
            total += W_MULE_CHAIN;
        }
        if (s.recordDeletion() == 1) {
            total += W_RECORD_DELETION;
        }
        return total;
    }

    /**
     * Returns ALLOW, CHALLENGE, or BLOCK for the given signals.
     *
     * <p>Decision order is exactly as specified and must not be reordered:
     * <ol>
     *   <li>dm == 1 -&gt; BLOCK on any route</li>
     *   <li>nr == 1 -&gt; BLOCK on any route</li>
     *   <li>sk == 0 -&gt; BLOCK on any route</li>
     *   <li>Sensitive route: dd == 1 -&gt; BLOCK; mc == 1 -&gt; BLOCK;
     *       rd == 1 -&gt; BLOCK; pi == 1 -&gt; BLOCK; ag == 1 -&gt; BLOCK;
     *       ac == 1 -&gt; never ALLOW (CHALLENGE at minimum; BLOCK if the
     *       score reaches 80).</li>
     *   <li>Sensitive route: full proof means pk == 1 and dp == 1 and dt == 1.
     *       Full proof and score &lt; 50 -&gt; ALLOW; score &gt;= 80 -&gt; BLOCK;
     *       anything else -&gt; CHALLENGE.</li>
     *   <li>Non-sensitive route: score &gt;= 80 -&gt; BLOCK, anything else -&gt; ALLOW.</li>
     * </ol>
     */
    public static Decision decide(Signals s) {
        if (s.deviceMismatch() == 1) {
            return Decision.BLOCK;
        }
        if (s.nonceReplayed() == 1) {
            return Decision.BLOCK;
        }
        if (s.sessionKey() == 0) {
            return Decision.BLOCK;
        }

        int value = score(s);

        if (isSensitive(s.route())) {
            if (s.disbursementDestinationChanged() == 1) {
                return Decision.BLOCK;
            }
            if (s.muleChain() == 1) {
                return Decision.BLOCK;
            }
            if (s.recordDeletion() == 1) {
                return Decision.BLOCK;
            }
            if (s.promptInjection() == 1) {
                return Decision.BLOCK;
            }
            if (s.agentBeyondScope() == 1) {
                return Decision.BLOCK;
            }
            if (s.approvalChanged() == 1) {
                if (value >= BLOCK_SCORE) {
                    return Decision.BLOCK;
                }
                return Decision.CHALLENGE;
            }
            boolean fullProof = s.passkey() == 1 && s.deviceProof() == 1 && s.deviceToken() == 1;
            if (fullProof && value < ALLOW_SCORE_LIMIT) {
                return Decision.ALLOW;
            }
            if (value >= BLOCK_SCORE) {
                return Decision.BLOCK;
            }
            return Decision.CHALLENGE;
        }

        if (value >= BLOCK_SCORE) {
            return Decision.BLOCK;
        }
        return Decision.ALLOW;
    }
}
