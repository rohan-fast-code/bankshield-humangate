package com.bankshield.gate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.bankshield.gate.Gate.Decision;
import com.bankshield.gate.Gate.Signals;

/**
 * Verifies the Java gate against the shared test vectors in
 * {@code stacks/shared/test_vectors.json}.
 *
 * <p>The vector file is loaded from the repository, never copied: it is
 * resolved relative to the project directory
 * ({@code stacks/java/../shared/test_vectors.json}), or from the
 * {@code BSG_VECTORS} environment variable when set, matching the Go and
 * Rust stacks.
 *
 * <p>Java has no built-in JSON parser, so this test includes a small
 * hand-written JSON parser ({@link JsonParser} below, test sources only).
 * It parses objects, arrays, strings (including escapes), numbers,
 * booleans and null, which is all the vector file needs. No JSON library
 * dependency is added.
 */
class VectorsTest {

    // ------------------------------------------------------------------
    // Shared vector test
    // ------------------------------------------------------------------

    @Test
    void sharedVectors() throws IOException {
        Path path = vectorsPath();
        String text = Files.readString(path);
        Object parsed = new JsonParser(text).parseValue();
        @SuppressWarnings("unchecked")
        List<Object> cases = (List<Object>) parsed;
        if (cases.isEmpty()) {
            fail("no test vectors found in " + path);
        }

        int allow = 0;
        int challenge = 0;
        int block = 0;
        int attackAllowOnSensitive = 0;
        int legitFalsePositives = 0;
        List<String> failures = new ArrayList<>();

        for (Object rawCase : cases) {
            @SuppressWarnings("unchecked")
            Map<String, Object> c = (Map<String, Object>) rawCase;
            int id = number(c.get("i")).intValue();
            String group = (String) c.get("g");
            String kind = (String) c.get("k");
            String template = (String) c.get("t");
            @SuppressWarnings("unchecked")
            Map<String, Object> s = (Map<String, Object>) c.get("s");
            String expectedCode = (String) c.get("e");

            Signals signals = signalsFrom(s);
            Decision got = Gate.decide(signals);
            Decision expected = Decision.fromCode(expectedCode);

            switch (got) {
                case ALLOW -> allow++;
                case CHALLENGE -> challenge++;
                case BLOCK -> block++;
            }
            if (got != expected) {
                failures.add("case " + id + " (g=" + group + " k=" + kind + " t=" + template
                        + "): decide=" + got + " (score=" + Gate.score(signals)
                        + "), want " + expected + " (code " + expectedCode + ")");
            }
            // Hard pass rule 1: zero attack cases allowed on a sensitive route.
            if ("a".equals(kind) && Gate.isSensitive(signals.route()) && got == Decision.ALLOW) {
                attackAllowOnSensitive++;
            }
            // Hard pass rule 2: zero legitimate cases that do not ALLOW.
            if ("l".equals(kind) && got != Decision.ALLOW) {
                legitFalsePositives++;
            }
        }

        System.out.println("verified " + cases.size() + " cases: ALLOW=" + allow
                + " CHALLENGE=" + challenge + " BLOCK=" + block);
        System.out.println("attack_allow_on_sensitive=" + attackAllowOnSensitive);
        System.out.println("legit_false_positives=" + legitFalsePositives);

        if (!failures.isEmpty()) {
            fail("FAILURES=" + failures.size() + " first=" + failures.subList(0, Math.min(5, failures.size())));
        }
        assertEquals(0, attackAllowOnSensitive,
                "attack cases allowed on a sensitive route must be zero");
        assertEquals(0, legitFalsePositives,
                "legitimate cases that do not ALLOW must be zero");
    }

    private static Signals signalsFrom(Map<String, Object> s) {
        // The six v2 signals default to 0 when the key is absent from a vector.
        return new Signals(
                (String) s.get("r"),
                number(s.get("pk")).intValue(),
                number(s.get("dp")).intValue(),
                number(s.get("dt")).intValue(),
                number(s.get("sk")).intValue(),
                number(s.get("nr")).intValue(),
                number(s.get("dm")).intValue(),
                number(s.get("hl")).intValue(),
                number(s.get("mb")).intValue(),
                number(s.get("dc")).intValue(),
                number(s.get("rpm")).intValue(),
                number(s.get("cov")).intValue(),
                number(s.get("tv")).doubleValue(),
                number(s.get("ov")).intValue(),
                number(s.get("np")).intValue(),
                intOrZero(s.get("ac")),
                intOrZero(s.get("dd")),
                intOrZero(s.get("ag")),
                intOrZero(s.get("pi")),
                intOrZero(s.get("mc")),
                intOrZero(s.get("rd")),
                number(s.get("amt")).doubleValue());
    }

    private static int intOrZero(Object value) {
        return value == null ? 0 : ((Number) value).intValue();
    }

    private static Number number(Object value) {
        return (Number) value;
    }

    private static Path vectorsPath() {
        String env = System.getenv("BSG_VECTORS");
        if (env != null && !env.isBlank()) {
            return Path.of(env);
        }
        // Maven runs tests with user.dir = stacks/java, so the shared file is
        // ../shared/test_vectors.json. Fall back to a couple of nearby
        // locations so the test also works from other working directories.
        Path base = Path.of(System.getProperty("user.dir"));
        for (String candidate : List.of(
                "../shared/test_vectors.json",
                "../../shared/test_vectors.json",
                "stacks/shared/test_vectors.json")) {
            Path p = base.resolve(candidate).normalize();
            if (Files.isRegularFile(p)) {
                return p;
            }
        }
        return base.resolve("../shared/test_vectors.json").normalize();
    }

    // ------------------------------------------------------------------
    // Unit tests for the hard blocks and the clean full-proof case
    // ------------------------------------------------------------------

    @Test
    void hardBlockDeviceMismatch() {
        Signals s = new Signals("pay", 1, 1, 1, 1, 0, 1, 0, 0, 0, 10, 10, 1.0, 0, 0, 0, 0, 0, 0, 0, 0, 1000);
        assertEquals(Decision.BLOCK, Gate.decide(s), "dm==1 must BLOCK");
    }

    @Test
    void hardBlockNonceReplayed() {
        Signals s = new Signals("pay", 1, 1, 1, 1, 1, 0, 0, 0, 0, 10, 10, 1.0, 0, 0, 0, 0, 0, 0, 0, 0, 1000);
        assertEquals(Decision.BLOCK, Gate.decide(s), "nr==1 must BLOCK");
    }

    @Test
    void hardBlockSessionKeyInvalid() {
        Signals s = new Signals("pay", 1, 1, 1, 0, 0, 0, 0, 0, 0, 10, 10, 1.0, 0, 0, 0, 0, 0, 0, 0, 0, 1000);
        assertEquals(Decision.BLOCK, Gate.decide(s), "sk==0 must BLOCK");
    }

    @Test
    void sensitiveFullProofAllow() {
        Signals s = Signals.cleanPayment();
        assertEquals(0, Gate.score(s), "clean payment score must be 0");
        assertEquals(Decision.ALLOW, Gate.decide(s),
                "sensitive full proof with low score must ALLOW");
    }

    @Test
    void sensitiveMissingPasskeyChallenge() {
        Signals s = new Signals("pay", 0, 1, 1, 1, 0, 0, 0, 0, 0, 10, 10, 1.0, 0, 0, 0, 0, 0, 0, 0, 0, 1000);
        assertEquals(Decision.CHALLENGE, Gate.decide(s),
                "sensitive route without full proof must not ALLOW");
    }

    // ------------------------------------------------------------------
    // Unit tests for the v2 signals (ac, dd, ag, pi, mc, rd)
    // ------------------------------------------------------------------

    @Test
    void v2SensitiveDestinationChangedBlocks() {
        // dd=1 on a sensitive route BLOCKs even with full proof and score 50.
        Signals s = new Signals("pay", 1, 1, 1, 1, 0, 0, 0, 0, 0, 10, 10, 1.0, 0, 0, 0, 1, 0, 0, 0, 0, 1000);
        assertEquals(50, Gate.score(s), "dd=1 must add 50");
        assertEquals(Decision.BLOCK, Gate.decide(s), "dd==1 on a sensitive route must BLOCK");
    }

    @Test
    void v2SensitivePromptInjectionBlocks() {
        Signals s = new Signals("pay", 1, 1, 1, 1, 0, 0, 0, 0, 0, 10, 10, 1.0, 0, 0, 0, 0, 0, 1, 0, 0, 1000);
        assertEquals(45, Gate.score(s), "pi=1 must add 45");
        assertEquals(Decision.BLOCK, Gate.decide(s), "pi==1 on a sensitive route must BLOCK");
    }

    @Test
    void v2SensitiveApprovalChangedChallenges() {
        // ac=1 on a sensitive route never ALLOWs, even with full proof and score 25.
        Signals s = new Signals("pay", 1, 1, 1, 1, 0, 0, 0, 0, 0, 10, 10, 1.0, 0, 0, 1, 0, 0, 0, 0, 0, 1000);
        assertEquals(25, Gate.score(s), "ac=1 must add 25");
        assertEquals(Decision.CHALLENGE, Gate.decide(s),
                "ac==1 on a sensitive route must CHALLENGE at minimum");
    }

    @Test
    void v2SensitiveApprovalChangedBlocksAtScore80() {
        // ac=1 plus headless (40) plus missing browser (15) = 80 -> BLOCK.
        Signals s = new Signals("pay", 1, 1, 1, 1, 0, 0, 1, 1, 0, 10, 10, 1.0, 0, 0, 1, 0, 0, 0, 0, 0, 1000);
        assertEquals(80, Gate.score(s), "ac + hl + mb must total 80");
        assertEquals(Decision.BLOCK, Gate.decide(s), "ac==1 with score>=80 must BLOCK");
    }

    @Test
    void v2NonSensitiveNewSignalsOnlyScore() {
        // On a non-sensitive route the v2 signals only add to the score:
        // pi=1 adds 45, score 45 < 80 -> ALLOW.
        Signals s = new Signals("view", 1, 1, 1, 1, 0, 0, 0, 0, 0, 10, 10, 1.0, 0, 0, 0, 0, 0, 1, 0, 0, 1000);
        assertEquals(45, Gate.score(s), "pi=1 must add 45");
        assertEquals(Decision.ALLOW, Gate.decide(s),
                "pi==1 on a non-sensitive route with score<80 must ALLOW");
    }

    // ------------------------------------------------------------------
    // Minimal hand-written JSON parser (test sources only).
    //
    // Parses the full JSON grammar needed here: objects, arrays, strings
    // with escapes, numbers, true/false/null. Returns LinkedHashMap for
    // objects, List for arrays, String for strings, Double for numbers,
    // Boolean for booleans, and null for null. No external dependency.
    // ------------------------------------------------------------------

    static final class JsonParser {
        private final String text;
        private int pos;

        JsonParser(String text) {
            this.text = text;
        }

        Object parseValue() {
            skipWhitespace();
            if (pos >= text.length()) {
                throw error("unexpected end of input");
            }
            char c = text.charAt(pos);
            return switch (c) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> parseString();
                case 't' -> parseLiteral("true", Boolean.TRUE);
                case 'f' -> parseLiteral("false", Boolean.FALSE);
                case 'n' -> parseLiteral("null", null);
                default -> parseNumber();
            };
        }

        private Map<String, Object> parseObject() {
            Map<String, Object> map = new LinkedHashMap<>();
            pos++; // '{'
            skipWhitespace();
            if (peek() == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                expect(':');
                Object value = parseValue();
                map.put(key, value);
                skipWhitespace();
                char c = peek();
                if (c == ',') {
                    pos++;
                } else if (c == '}') {
                    pos++;
                    return map;
                } else {
                    throw error("expected ',' or '}' in object");
                }
            }
        }

        private List<Object> parseArray() {
            List<Object> list = new ArrayList<>();
            pos++; // '['
            skipWhitespace();
            if (peek() == ']') {
                pos++;
                return list;
            }
            while (true) {
                list.add(parseValue());
                skipWhitespace();
                char c = peek();
                if (c == ',') {
                    pos++;
                } else if (c == ']') {
                    pos++;
                    return list;
                } else {
                    throw error("expected ',' or ']' in array");
                }
            }
        }

        private String parseString() {
            expect('"');
            StringBuilder out = new StringBuilder();
            while (pos < text.length()) {
                char c = text.charAt(pos++);
                if (c == '"') {
                    return out.toString();
                }
                if (c == '\\') {
                    if (pos >= text.length()) {
                        break;
                    }
                    char esc = text.charAt(pos++);
                    switch (esc) {
                        case '"' -> out.append('"');
                        case '\\' -> out.append('\\');
                        case '/' -> out.append('/');
                        case 'b' -> out.append('\b');
                        case 'f' -> out.append('\f');
                        case 'n' -> out.append('\n');
                        case 'r' -> out.append('\r');
                        case 't' -> out.append('\t');
                        case 'u' -> {
                            if (pos + 4 > text.length()) {
                                throw error("bad unicode escape");
                            }
                            out.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
                            pos += 4;
                        }
                        default -> throw error("bad escape \\" + esc);
                    }
                } else {
                    out.append(c);
                }
            }
            throw error("unterminated string");
        }

        private Object parseLiteral(String literal, Object value) {
            if (!text.startsWith(literal, pos)) {
                throw error("expected '" + literal + "'");
            }
            pos += literal.length();
            return value;
        }

        private Double parseNumber() {
            int start = pos;
            if (peek() == '-') {
                pos++;
            }
            while (pos < text.length() && isNumberChar(text.charAt(pos))) {
                pos++;
            }
            if (pos == start) {
                throw error("expected number");
            }
            try {
                return Double.valueOf(text.substring(start, pos));
            } catch (NumberFormatException e) {
                throw error("bad number: " + text.substring(start, pos));
            }
        }

        private static boolean isNumberChar(char c) {
            return (c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-';
        }

        private void skipWhitespace() {
            while (pos < text.length()) {
                char c = text.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        private char peek() {
            if (pos >= text.length()) {
                throw error("unexpected end of input");
            }
            return text.charAt(pos);
        }

        private void expect(char wanted) {
            if (peek() != wanted) {
                throw error("expected '" + wanted + "' but found '" + peek() + "'");
            }
            pos++;
        }

        private IllegalArgumentException error(String message) {
            return new IllegalArgumentException("JSON parse error at offset " + pos + ": " + message);
        }
    }
}
