"""CI scan: fail if finance logic leaks into the agent repo.

Run in CI on every pull request. A human cannot reliably catch
a logic leak in a large agent diff. This scan can.
Banned patterns are a safety net, not a proof. The real proof is
that finance code lives in a separate private repo.
"""
import sys
from pathlib import Path

BANNED = [
    "fraud_threshold",
    "fee_calculation",
    "interest_rate_logic",
    "ledger_write",
    "private_key",
    "api_key =",
    "secret =",
]

ROOT = Path(__file__).resolve().parent.parent


def main():
    found = []
    # Scan only app code, where a leak would actually matter.
    # Gateway policy and this scan itself legitimately name banned
    # patterns as strings, so scanning them would give false positives.
    if (ROOT / "finance_core").exists():
        found.append((str(ROOT / "finance_core"), "finance_core path must not exist in this repo"))
    for path in (ROOT / "app").rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in BANNED:
            if pattern in text:
                found.append((str(path), pattern))
    if found:
        print("FINANCE LEAK DETECTED. Build failed.")
        for path, pattern in found:
            print(path, pattern)
        return 1
    print("Scan passed. No banned finance pattern found in this repo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
