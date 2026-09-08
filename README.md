# admission-gate

[![CI](https://github.com/ak-skwaa-mahawk/admission-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/ak-skwaa-mahawk/admission-gate)
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
```

---

## Configuration (`admission_gate.toml`)

Place `admission_gate.toml` in your working directory or provide `--config <path>`:

```toml
[policy]
blocked_patterns = [
    "rm -rf /",
    ":(){ :|:f };:",
    "/dev/sd",
    "> /dev/null",
    "mkfs",
]
require_confirm = true

[filesystem]
allowed_roots = [
    "./workspace",
    "./scratch",
]
protected_paths = [
    "/etc",
    "/boot",
    "/sys",
    "/dev",
    "/proc",
    "C:\\Windows",
    "C:\\Windows\\System32",
]
logging]
log_file = "audit_log.jsonl"

[rate_limit]
enabled = true
max_requests_per_minute = 30
burst_threshold = 10
tier3_cooldown_seconds = 3.0
```

---

## Risk-Tier Auto-Classification

The gate calculates an effective risk tier for every proposal. The engine only ratchets upward:

**Tier 1 (Read-Only / Inspection)**: `ls`, `cat`, `head`, `tail`, `grep`, `find`, `stat`, `diff`, `wc`, `file`.
**Tier 2 (Mutating / State Modification)**: `touch`, `mkdir`, `cp`, ggit add`, `python`, `node`, or any command containing redirection (`>`, `>>`).
**Tier 3 (Destructive / Administrative)**: `rm`, `mv`, `chmod`, `chown`, `dd`, `truncate`, `kill`, `sed -i`, `mkfs`, `shred`.

---

## Command Line Tools

### 1. `admission-gate` (Core Gatekeeper)

```bash
# Interactive execution
some_proposal_stream | admission-gate

# Headless / Dry-Run verification in CI
some_proposal_stream | admission-gate --verify-only
```

### 2. `verify-audit` (Cryptographic Verification)

Matches all prev-hash chains and validates tamper-resistance:

```bash
verify-audit audit_log.jsonl
```

### 3. `query-audit` (Forensic Query & Replay)

Filter historical records or simulate past proposals against updated policies:

```bash
# Filter by risk tier or status
query-audit --tier 3
query-audit --status blocked

# Filter by time window
query-audit --since 15mquery-audit --until 5m

# Replay past actions against current admission_gate.toml rules
query-audit --action-id step_1 --replay
```

### 4. `admission-gate-mcp` (MCP Adapter)

```json
{
  "mcpServers": {
    "admission_gate": {
      "command": "admission-gate-mcp",
      "args": []
    }
  }
}
```

---

## Running the Test Suite

```bash
PYTHONPATG=src python3 -m unittest discover -s tests
```

---

## License

[MIT)(LICENSE)
