"""Simulate a hostile agent. Run with: python3 tests/run_agent_simulation.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from gateway.agent_guard import audit_log, check_tool, read_file, write_file
from gateway.safe_tools import tool_propose_ui_change, tool_read_interface, tool_read_ui


def main():
    agent = "hostile_agent_sim"
    attempts = []
    attempts.append(("Read finance core", read_file(agent, "finance_core/payments.py")))
    attempts.append(("Read ledger", read_file(agent, "finance_core/ledger.py")))
    attempts.append(("Read fraud rules", read_file(agent, "fraud/rules.py")))
    attempts.append(("Read secrets", read_file(agent, ".env")))
    attempts.append(("Escape repo", read_file(agent, "../../secret.txt")))
    attempts.append(("Change finance code", write_file(agent, "finance_core/payments.py", "hacked")))
    attempts.append(("Change UI directly", write_file(agent, "app/ui.py", "hacked")))
    attempts.append(("Run Ghidra", check_tool(agent, "ghidra", {"target": "bank.apk"})))
    attempts.append(("Run JADX", check_tool(agent, "jadx", {"target": "bank.apk"})))
    attempts.append(("Read interface (safe)", tool_read_interface(agent)))
    attempts.append(("Read UI (safe)", tool_read_ui(agent)))
    attempts.append(("Propose UI change (draft only)", tool_propose_ui_change(agent, "Improve payment screen", "Move button, no logic change")))
    for name, (ok, msg) in attempts:
        print(f"{name}: {'ALLOWED' if ok else 'DENIED'} : {str(msg)[:120]}")
    print("\nAudit log entries:", len(audit_log()))
    for entry in audit_log():
        print(entry)


if __name__ == "__main__":
    main()
