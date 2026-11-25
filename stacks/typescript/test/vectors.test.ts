/**
 * BankShield HumanGate TypeScript vector test.
 *
 * Loads the shared test vectors from stacks/shared/test_vectors.json
 * (resolved relative to this project directory; the file is not copied),
 * runs decide() on every case, and asserts the decision equals the
 * expected code in "e" (A = ALLOW, C = CHALLENGE, B = BLOCK).
 *
 * Also asserts the hard pass rules: zero attack cases ("k" == "a")
 * allowed (ALLOW) on a sensitive route, and zero legitimate cases
 * ("k" == "l") that do not ALLOW.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { decide, isSensitive } from "../src/gate.ts";
import type { Decision, Signals } from "../src/gate.ts";

interface VectorCase {
  i: number;
  g: string;
  k: string;
  t: string;
  s: Signals;
  e: string;
}

const EXPECTED: Record<string, Decision> = {
  A: "ALLOW",
  C: "CHALLENGE",
  B: "BLOCK",
};

test("shared test vectors", () => {
  // test/ is one level below the project root; shared vectors live at
  // ../../shared/test_vectors.json relative to the project root.
  const projectDir = join(dirname(fileURLToPath(import.meta.url)), "..");
  const vectorsPath = join(projectDir, "..", "shared", "test_vectors.json");
  const raw = readFileSync(vectorsPath, "utf8");
  const cases = JSON.parse(raw) as VectorCase[];

  assert.ok(cases.length > 0, `no test vectors found in ${vectorsPath}`);

  const counts: Record<Decision, number> = {
    ALLOW: 0,
    CHALLENGE: 0,
    BLOCK: 0,
  };
  let attackAllowOnSensitive = 0;
  let legitFalsePositives = 0;
  const failures: string[] = [];

  for (const c of cases) {
    const want = EXPECTED[c.e];
    assert.ok(want !== undefined, `case ${c.i}: unknown expected code ${JSON.stringify(c.e)}`);
    const got = decide(c.s);
    counts[got] += 1;
    if (got !== want) {
      failures.push(`case ${c.i} (g=${c.g} k=${c.k} t=${c.t}): got ${got}, want ${want} (code ${c.e})`);
    }
    if (c.k === "a" && isSensitive(c.s.r) && got === "ALLOW") {
      attackAllowOnSensitive += 1;
    }
    if (c.k === "l" && got !== "ALLOW") {
      legitFalsePositives += 1;
    }
  }

  console.log(
    `cases=${cases.length} allow=${counts.ALLOW} challenge=${counts.CHALLENGE} block=${counts.BLOCK}`,
  );
  console.log(`attack_allow_on_sensitive=${attackAllowOnSensitive}`);
  console.log(`legit_false_positives=${legitFalsePositives}`);
  if (failures.length > 0) {
    console.log(`FAILURES=${failures.length} first=${failures.slice(0, 5).join(" | ")}`);
  }

  assert.deepEqual(failures, [], `${failures.length} vector(s) failed`);
  assert.equal(attackAllowOnSensitive, 0, "attack cases allowed on a sensitive route");
  assert.equal(legitFalsePositives, 0, "legitimate cases that did not ALLOW");
});
