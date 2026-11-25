/**
 * BankShield HumanGate TypeScript example.
 *
 * Runs three cases against decide() and prints each decision:
 * a full-proof payment that ALLOWs, a replayed nonce that BLOCKs,
 * and a missing passkey case that CHALLENGEs.
 *
 * All signals are synthetic. Demo only, no real bank data.
 */
import { decide } from "../src/gate.ts";
import type { Signals } from "../src/gate.ts";

function cleanPayment(): Signals {
  return {
    r: "pay",
    pk: 1,
    dp: 1,
    dt: 1,
    sk: 1,
    nr: 0,
    dm: 0,
    hl: 0,
    mb: 0,
    dc: 0,
    rpm: 12,
    cov: 8,
    tv: 1.4,
    ov: 0,
    np: 0,
    amt: 45000,
  };
}

// 1. Full proof payment: passkey, device proof and device token all valid,
//    low risk score -> ALLOW.
const fullProofPayment = cleanPayment();
console.log("full proof payment:", decide(fullProofPayment));

// 2. Replayed nonce: the same nonce was already used -> BLOCK on any route.
const replayedNonce = cleanPayment();
replayedNonce.nr = 1;
console.log("replayed nonce payment:", decide(replayedNonce));

// 3. Missing passkey: no full proof on a sensitive route, low score -> CHALLENGE.
const missingPasskey = cleanPayment();
missingPasskey.pk = 0;
console.log("missing passkey payment:", decide(missingPasskey));
