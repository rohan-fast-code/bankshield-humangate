"""Safe tools only. This is the entire tool surface an agent gets.

No shell tool. No raw file tool. No decompiler tool.
An agent that needs a new tool must get it approved, added here,
and reviewed, like any other code change.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from gateway.agent_guard import check_tool, propose_ui_change, read_file


def tool_read_interface(agent_id):
    return read_file(agent_id, "app/finance_interface.py")


def tool_read_ui(agent_id):
    return read_file(agent_id, "app/ui.py")


def tool_run_ui_tests(agent_id):
    ok, msg = check_tool(agent_id, "run_ui_tests", {})
    if not ok:
        return False, msg
    return True, "UI tests are run in a sandbox by the gateway, not by the agent shell."


def tool_call_sandbox_api(agent_id, intent_summary):
    ok, msg = check_tool(agent_id, "call_sandbox_api", intent_summary)
    if not ok:
        return False, msg
    return True, "Sandbox API call accepted with fake test data only. No real customer data, no real money."


def tool_propose_ui_change(agent_id, title, description):
    return propose_ui_change(agent_id, title, description)
