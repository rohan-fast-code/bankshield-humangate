"""Gateway tests. Run with: python3 tests/test_agent_guard.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from gateway.agent_guard import check_tool, read_file, write_file


def main():
    agent = "test_agent_1"
    ok, _ = read_file(agent, "app/finance_interface.py")
    assert ok, "Interface read should be allowed"
    ok, _ = read_file(agent, "finance_core/payments.py")
    assert not ok, "Finance core read should be denied"
    ok, _ = read_file(agent, "app/../.env")
    assert not ok, "Secret path should be denied"
    ok, _ = read_file(agent, "../../etc/passwd")
    assert not ok, "Path escape should be denied"
    ok, _ = write_file(agent, "app/ui.py", "new code")
    assert not ok, "Direct writes should be denied"
    ok, _ = check_tool(agent, "ghidra", {"target": "bank.apk"})
    assert not ok, "Reverse tool should be denied"
    ok, _ = check_tool(agent, "jadx", {"target": "bank.apk"})
    assert not ok, "Reverse tool should be denied"
    print("All gateway tests passed.")


if __name__ == "__main__":
    main()
