"""AgentGuard: policy in code, not in a prompt.

An agent must call these functions. It must never be given raw
filesystem or shell access to this repo. If it has raw access,
this file is bypassed, and that is a deployment failure, not a
bug in this file.
"""
import json
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = REPO_ROOT / "agent_policy.json"
AUDIT_LOG = []


def load_policy():
    with open(POLICY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def log(agent_id, tool, target, decision, reason):
    entry = {
        "agent": agent_id,
        "tool": tool,
        "target": str(target),
        "decision": decision,
        "reason": reason,
    }
    AUDIT_LOG.append(entry)
    return entry


def canonical_path(requested):
    """Resolve a requested path inside the repo root, or return None."""
    try:
        candidate = (REPO_ROOT / requested).resolve()
        candidate.relative_to(REPO_ROOT.resolve())
        return candidate
    except Exception:
        return None


def is_protected(path_text, policy):
    lowered = str(path_text).lower()
    for pattern in policy["protected_patterns"]:
        if pattern.lower() in lowered:
            return True
    return False


def check_tool(agent_id, tool_name, arguments=None):
    policy = load_policy()
    lowered_tool = str(tool_name).lower()
    if lowered_tool in policy["blocked_tools"]:
        log(agent_id, tool_name, arguments or "", "DENIED", "Tool is blocked by policy")
        return False, "DENIED: tool is blocked by policy"
    if arguments and any(
        word in str(arguments).lower()
        for word in ["secret", "private_key", ".pem", "api_key="]
    ):
        log(agent_id, tool_name, arguments, "DENIED", "Arguments contain a secret pattern")
        return False, "DENIED: arguments contain a secret pattern"
    log(agent_id, tool_name, arguments or "", "ALLOWED", "Tool is allowed")
    return True, "ALLOWED"


def read_file(agent_id, requested_path):
    """Read a file only if policy allows it. Returns (ok, text_or_reason)."""
    policy = load_policy()
    if is_protected(requested_path, policy):
        log(agent_id, "read_file", requested_path, "DENIED", "Path matches a protected finance or secret pattern")
        return False, "DENIED: finance code and secrets are not in this repo and are not readable by an agent"
    resolved = canonical_path(requested_path)
    if resolved is None:
        log(agent_id, "read_file", requested_path, "DENIED", "Path escapes the repo root")
        return False, "DENIED: path escapes the repo root"
    if not resolved.exists():
        # In production this is the normal case for finance code:
        # it simply does not exist in this repo.
        log(agent_id, "read_file", requested_path, "DENIED", "File does not exist in the agent repo")
        return False, "DENIED: file does not exist in the agent repo. Finance code lives only in the private finance service."
    if str(resolved.relative_to(REPO_ROOT)) not in policy["allowed_read_paths"]:
        log(agent_id, "read_file", requested_path, "DENIED", "Path is not on the allowed read list")
        return False, "DENIED: path is not on the allowed read list"
    with open(resolved, "r", encoding="utf-8") as f:
        content = f.read()
    log(agent_id, "read_file", requested_path, "ALLOWED", "Allowed interface or UI file")
    return True, content


def write_file(agent_id, requested_path, content):
    """Deny direct writes. Agents propose, humans merge."""
    policy = load_policy()
    if is_protected(requested_path, policy):
        log(agent_id, "write_file", requested_path, "DENIED", "Protected finance path")
        return False, "DENIED: finance paths cannot be written by an agent"
    log(agent_id, "write_file", requested_path, "DENIED", "Direct writes are disabled. Use propose_ui_change instead.")
    return False, "DENIED: direct writes are disabled. Use propose_ui_change to create a draft for human review."


def propose_ui_change(agent_id, title, description):
    """Safe write path: a proposal, not a merge. Returns a draft record."""
    draft = {
        "agent": agent_id,
        "title": title,
        "description": description,
        "status": "DRAFT_FOR_HUMAN_REVIEW",
        "merged": False,
    }
    log(agent_id, "propose_ui_change", title, "ALLOWED_AS_DRAFT", "Draft only, human review required")
    return True, draft


def audit_log():
    return list(AUDIT_LOG)
