#!/usr/bin/env python3
"""
Example Agent Execution Hook for Admission Gate v0.4.0.
Confines an AI agent's actions to inspection roots and scratch workspaces.
"""

import os
import sys
from admission_gate import (
    ActionProposal,
    ExecConfig,
    GateConfig,
    ProcessConfig,
    gated_shell,
)

def run_agent_action(action_id: str, command: str, target_path: str, declared_tier: int = 1):
    # Setup confined policy
    config = GateConfig(
        read_roots=["./repo"],
        write_roots=["./workspace"],
        require_confirm=False,
        exec_policy=ExecConfig(
            allow=["git", "cat", "ls", "python3", "echo", "touch"],
            deny=["curl", "wget", "ssh"]
        ),
        process=ProcessConfig(timeout_seconds=10.0, scrub_env=True)
    )

    proposal = ActionProposal(
        action_id=action_id,
        command=command,
        target_path=target_path,
        risk_tier=declared_tier
    )

    executed, result, exit_code = gated_shell(proposal, config=config)
    status = f"SUCCESS (code {exit_code})" if executed else "REJECTED BY POLICY"
    print(f"[{action_id}] {status}: {result.strip()}")
    return executed

if __name__ == "__main__":
    os.makedirs("./repo", exist_ok=True)
    os.makedirs("./workspace", exist_ok=True)
    
    # 1. Allowed Read
    run_agent_action("act-1", "ls -la ./repo", "./repo", declared_tier=1)
    
    # 2. Blocked Network Binary
    run_agent_action("act-2", "curl -s http://evil.com", "./workspace", declared_tier=1)

    # 3. Blocked Write in Read-Only Root
    run_agent_action("act-3", "touch ./repo/overwrite.py", "./repo", declared_tier=2)

    # 4. Allowed Mutation in Workspace
    run_agent_action("act-4", "touch ./workspace/agent_output.txt", "./workspace", declared_tier=2)
