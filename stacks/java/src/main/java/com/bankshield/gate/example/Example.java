package com.bankshield.gate.example;

import com.bankshield.gate.Gate;

/**
 * Small demo of {@link Gate#decide(Gate.Signals)} on three cases.
 *
 * <p>Demo only: all signals are synthetic, no real bank data.
 *
 * <p>Run with: {@code mvn exec:java} is not configured; use the compiled
 * classes directly, or run {@code mvn test} for the full shared-vector
 * verification. Example:
 * <pre>
 *   mvn compile
 *   java -cp target/classes com.bankshield.gate.example.Example
 * </pre>
 */
public final class Example {

    private Example() {
    }

    public static void main(String[] args) {
        // 1. Full proof payment: passkey, device proof and device token all
        // valid, low risk (score 0) -> ALLOW.
        Gate.Signals fullProofPayment = Gate.Signals.cleanPayment();
        System.out.println("full proof payment -> " + Gate.decide(fullProofPayment)
                + " (score " + Gate.score(fullProofPayment) + ")");

        // 2. Replayed nonce: same clean payment, but the nonce was already
        // used -> BLOCK on any route (hard block, rule 2).
        Gate.Signals replayedNonce = new Gate.Signals(
                "pay", 1, 1, 1, 1, 1, 0, 0, 0, 0, 10, 10, 1.0, 0, 0, 0, 0, 0, 0, 0, 0, 1000);
        System.out.println("replayed nonce payment -> " + Gate.decide(replayedNonce)
                + " (score " + Gate.score(replayedNonce) + ")");

        // 3. Missing passkey: device proof and token valid, but no passkey
        // proof, so no full proof on a sensitive route -> CHALLENGE.
        Gate.Signals missingPasskey = new Gate.Signals(
                "pay", 0, 1, 1, 1, 0, 0, 0, 0, 0, 10, 10, 1.0, 0, 0, 0, 0, 0, 0, 0, 0, 1000);
        System.out.println("missing passkey payment -> " + Gate.decide(missingPasskey)
                + " (score " + Gate.score(missingPasskey) + ")");
    }
}
