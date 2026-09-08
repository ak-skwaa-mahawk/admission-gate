# admission-gate

[![CI](https://github.com/ak-skwaa-mahawk/admission-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/ak-skwaa-mahawk/admission-gate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI](https://img.shields.io/pypi/v/admission-gate)](https://pypi.org/project/admission-gate/)

A deterministic admission gatekeeper, feedback regulator, and cryptographic audit logger for autonomous shell environments and agent tooling.

## Architectural Layers

1. **The Map (`admission-gate`)**: Static verification kernel executing strict path canonicalization, command jail confinement, and invariant enforcement.
2. **The Territory (`kpt_kernel` / `fpt_daemon`)**: Adaptive PID damping controller adjusting burst allowance, cooldown intervals, and path quarantines based on real-time fault telemetry.
3. **The Witness (`Human_inthe_loop`)**: Out-of-band sovereign attractor handshake preventing automated execution bypasses when damping escalates ($\sigma > 0.85$).
4. **Agent Integration (`fpt_mcp_server.py`)**: Zero-dependency Model Context Protocol server exposing gated shell execution over JSON-RPC stdio.

## Installation

```bash
pip install admission-gate kpt_kernel
Formal Verification
​State Space Model Checking: Verified via discrete state exploration (spec/verify_model.py) across 697 states, 1,020 transitions, and 0 bypasses.
​Control Stability: Discrete Lyapunov stability with anti-windup accumulator bounds (\sup \vert{}I_k\vert{} \le I_{\max}) documented in ARCHITECTURE.md.
​Adversarial Fuzzing: 500+ path-traversal mutations verified against root confinement invariants (tests/test_properties_adversarial.py).
​Quick Start
from admission_gate import evaluate, GateConfig, ActionProposal

config = GateConfig(
    write_roots=["./workspace", "./scratch"],
    read_roots=["./workspace", "./scratch"],
    blocked_patterns=["rm -rf /", ":(){ :|:& };:", "/dev/sd", "> /dev/null"]
)

proposal = ActionProposal(
    action_id="task-01",
    command="echo 'build complete' > ./workspace/status.txt",
    target_path="./workspace/status.txt",
    risk_tier=1
)

passed, reason = evaluate(proposal, config=config)
print(f"Policy Decision: {passed} ({reason})")

License
​MIT
