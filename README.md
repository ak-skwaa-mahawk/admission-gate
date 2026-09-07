# admission-gate

[![CI](https://github.com/ak-skwaa-mahawk/admission-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/ak-skwaa-mahawk/admission-gate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/github/v/release/ak-skwaa-mahawk/admission-gate)](https://github.com/ak-skwaa-mahawk/admission-gate/releases)

A lightweight admission gatekeeper and cryptographic audit logger for autonomous CLI agents.

cat << 'EOF' > README.md
# admission-gate

[![CI](https://github.com/ak-skwaa-mahawk/admission-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/ak-skwaa-mahawk/admission-gate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI](https://img.shields.io/pypi/v/admission-gate)](https://pypi.org/project/admission-gate/)

A lightweight, deterministic admission gatekeeper and cryptographic audit logger for autonomous CLI agents.

When autonomous scripts or LLMs execute commands in a subshell, developers are forced between two extremes: fully autonomous execution that risks destructive operations, or prompt fatigue from micro-approving dozens of benign commands. `admission-gate` sits between the agent and your shell:

1. **Deterministic Security Kernel**: Enforces sandbox jails, blocks dangerous tokens, and runs multi-path inspection across all command arguments using strict path canonicalization.
2. **Metacharacter & Subshell Hardening**: Disallows command chaining evasions, redirection breakouts, and indirect subshell expansions (`$(...)`, backticks, `<(...)`).
3. **Interactive TTY Escalation**: Halts for operator authorization (`[y/N]`) only on proposals that pass static policy checks.
4. **Cryptographic Audit Trail**: Commits all proposals, policy outcomes, and approval decisions to an append-only, SHA-256 hash-chained JSONL log.
5. **Native MCP Support**: Provides a zero-dependency Model Context Protocol server (`admission-gate-mcp`) for tools like Claude Desktop, Cursor, and Cline.

Requires Python 3.8+ with zero third-party dependencies.

---

## Installation

```bash
pip install admission-gate
