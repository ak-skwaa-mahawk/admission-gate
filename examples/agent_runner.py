#!/usr/bin/env python3
"""
Example: Safe agent tool runner using admission-gate.
Demonstrates gating an LLM command tool execution before it hits the OS.
"""

import sys
from admission_gate import ActionProposal, gated_shell


def run_agent_tool(tool_call_id: str, command: str, target: str) -> str:
    """Simulated LLM tool call dispatcher."""
    print(f"\n[Agent Tool] Dispatching: '{command}' on '{target}'...")

    proposal = ActionProposal(
        action_id=tool_call_id,
        command=command,
        target_path=target,
        risk_tier=2,
    )

    # Hard sandbox boundaries: restricted strictly to ./workspace
    executed, output, exit_code = gated_shell(
        proposal,
        allowed_roots=["./workspace"],
        log_path="audit_log.jsonl",
        require_confirm=True,
    )

    if not executed:
        return f"TOOL ERROR (Gate Denied): {output}"

    return f"TOOL SUCCESS (Code {exit_code}):\n{output}"


if __name__ == "__main__":
    # Test 1: Benign workspace command
    res1 = run_agent_tool("call_1", "ls -la", "./workspace")
    print(res1)

    # Test 2: Attempted sandbox escape (blocked deterministically)
    res2 = run_agent_tool("call_2", "cat /etc/passwd", "/etc/passwd")
    print(res2)
