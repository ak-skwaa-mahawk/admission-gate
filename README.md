python3 -c '
content = """# admission-gate

[![CI](https://github.com/ak-skwaa-mahawk/admission-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/ak-skwaa-mahawk/admission-gate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI](https://img.shields.io/pypi/v/admission-gate)](https://pypi.org/project/admission-gate/)

A zero-dependency, deterministic admission security kernel and cryptographic audit logging engine for autonomous CLI agents.

When autonomous scripts or LLMs execute commands in a subshell, developers face two extremes: fully autonomous execution that risks destructive operations, or prompt fatigue from micro-approving benign steps. `admission-gate` sits directly between the agent and your shell:

1. **Deterministic Security Kernel**: Enforces sandbox jails, blocks hazardous tokens, and canonicalizes paths (`os.path.realpath`) across all command arguments.
2. **Metacharacter & Environment Variable Hardening**: Neutralizes command chaining evasions, redirection breakouts, indirect subshells (`$(...)`, backticks, `<(...)`), and unexpanded environment variable injection (`$VAR`, `${VAR}`, `%VAR%`).
3. **Risk-Tier Auto-Classification**: Automatically infers risk based on command binaries, flags (e.g. `sed -i`), and redirection operators, ratcheting upward if an agent attempts to under-report risk.
4. **Sliding-Window Rate Limiting & Burst Control**: Enforces maximum requests per minute, mandatory quiescent cooldown periods after destructive actions (Tier 3), and burst escalation.
5. **Interactive & Non-Interactive (`--verify-only`) Modes**: Halts for operator authorization (`[y/N]`) on interactive terminals or runs headless with structured outputs in CI/automation.
6. **Cryptographic Audit Trail & Forensic Tools**: Appends SHA-256 hash-chained JSONL logs, verifiable via `verify-audit` and queryable via `query-audit`.
7. **Native Model Context Protocol (MCP)**: Exposes `admission-gate-mcp` for direct integration into Claude Desktop, Cursor, and Cline.

Requires Python 3.8+ with zero third-party dependencies.

---

## Installation

```bash
pip install --upgrade admission-gate
