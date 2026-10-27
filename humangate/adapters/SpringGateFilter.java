// Spring Boot filter sketch for Java financial apps.
// This file shows the integration pattern. It mirrors the Python
// gate decision in Java, so a Spring team can port the same rules
// without rewriting finance logic. Verify passkey, attestation,
// and request signatures with real platform libraries in production.
// Do not trust a header value as proof by itself.
//
// Pattern:
//   1. Read route from the request path.
//   2. Build signals from verified passkey, attestation, token, and signature services.
//   3. If route is sensitive and any proof is missing, return 403 or 401 challenge.
//   4. If risk score is high, block and log.
//   5. Only then call the finance handler.
//
// Sensitive routes in this sketch: payment, transfer, change beneficiary,
// export data, change security settings.
// View routes: allow low risk traffic, block obvious automation.
//
// In production, put this filter before every finance controller,
// keep finance logic behind it, and log every decision with session,
// route, score, and reason, just like the Python gate audit log.
public class SpringGateFilter {
    public String decide(boolean hasPasskeyProof, boolean attestationValid,
                         boolean tokenValid, boolean deviceMatches,
                         boolean signatureValid, int riskScore, String route) {
        if (!deviceMatches) return "BLOCK";
        if (!signatureValid) return "BLOCK";
        boolean sensitive = route.equals("payment") || route.equals("transfer")
                || route.equals("change_beneficiary") || route.equals("export_data");
        if (sensitive) {
            if (hasPasskeyProof && attestationValid && tokenValid && riskScore < 50) return "ALLOW";
            if (riskScore >= 80) return "BLOCK";
            return "CHALLENGE";
        }
        if (riskScore >= 80) return "BLOCK";
        return "ALLOW";
    }
}
