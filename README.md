# admission-gate

[![CI](https://github.com/ak-skwaa-mahawk/admission-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/ak-skwaa-mahawk/admission-gate)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI](https://img.shields.io/pypi/v/admission-gate)](https://pypi.org/project/admission-gate/)

Follow the exact steps below in sequence.
Step 1: Wire --verify into src/admission_gate/query.py
Run this script to add --verify argument handling and the SHA-256 chain verification routine:
python3 -c '
import sys

with open("src/admission_gate/query.py", "r", encoding="utf-8") as f:
    text = f.read()

verify_fn = """
def verify_hash_chain(log_path: str) -> bool:
    \"\"\"Verifies continuous SHA-256 hash-chain integrity of the audit log.\"\"\"
    import os, json, hashlib
    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}")
        return False

    prev_expected = "0" * 64
    total = 0
    with open(log_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            if not line.strip():
                continue
            entry = json.loads(line)
            actual_hash = entry.get("entry_hash")
            prev_hash = entry.get("prev_hash")
            if prev_hash != prev_expected:
                print(f"[TAMPER DETECTED] Line {idx}: prev_hash {prev_hash[:16]}... does not match expected {prev_expected[:16]}...")
                return False

            payload = {k: v for k, v in entry.items() if k != "entry_hash"}
            serialized = json.dumps(payload, sort_keys=True)
            computed_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            if computed_hash != actual_hash:
                print(f"[TAMPER DETECTED] Line {idx}: entry_hash mismatch. Recorded {actual_hash[:16]}..., computed {computed_hash[:16]}...")
                return False

            prev_expected = actual_hash
            total += 1

    print(f"[Chain OK] Verified {total} audit records. Cryptographic integrity intact.")
    return True
"""

if "def verify_hash_chain" not in text:
    main_idx = text.find("def main():")
    text = text[:main_idx] + verify_fn + "\n\n" + text[main_idx:]

if "--verify" not in text:
    old_parser = "    parser.add_argument(\"--replay\", action=\"store_true\""
    new_parser = "    parser.add_argument(\"--verify\", action=\"store_true\", help=\"Verify cryptographic SHA-256 ledger integrity\")\n" + old_parser
    text = text.replace(old_parser, new_parser, 1)

    old_dispatch = "    if args.replay:\n        run_replay(log_path, args.config)\n        return"
    new_dispatch = """    if args.verify:
        success = verify_hash_chain(log_path)
        sys.exit(0 if success else 1)
    if args.replay:
        run_replay(log_path, args.config)
        return"""
    text = text.replace(old_dispatch, new_dispatch, 1)

with open("src/admission_gate/query.py", "w", encoding="utf-8") as f:
    f.write(text)

import py_compile
py_compile.compile("src/admission_gate/query.py", doraise=True)
print("query.py updated with --verify support.")
'

Reinstall the CLI entry points in editable mode so your shell picks up the new flag:
pip install -e .

Step 2: Write Clean README.md
Replace README.md with the completed specification:
cat << 'EOF' > README.md
# Admission Gate

A deterministic security admission gate for CLI-based AI agents, MCP servers, and autonomous toolchains.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version: 0.4.0](https://img.shields.io/badge/Version-0.4.0-green.svg)](pyproject.toml)

Admission Gate evaluates, confines, and cryptographically audits shell actions before subprocess execution occurs.

---

## What Admission Gate Guarantees (v0.4.0)

1. **Executable Allowlisting / Denylisting (`argv[0]`)**: Resolves binary symlinks and multiplexers (`busybox`, `coreutils`) down to canonical filesystem paths before execution.
2. **Filesystem Partitioning**: Strict separation between `read_roots` (Tier 1 inspection) and `write_roots` (Tier 2/3 mutation and redirection targets). Cross-boundary moves and writes into read roots are rejected.
3. **Process Isolation & Environment Scrubbing**: Subprocesses are isolated into detached process groups (`setsid`), stripped of dangerous environment variables (`LD_PRELOAD`, `PYTHONPATH`, credentials), and terminated via `killpg` upon timeout expiration.
4. **Forensic Audit Hash Ledger**: JSONL audit records form a continuous SHA-256 hash-chain, stamped with schema versions (`0.4.0`) and execution metadata.
5. **Config Precedence**: Strict resolution hierarchy:

CLI Flags > Environment Variables > Config File > Defaults

---

## Security Model & Honest Limitations

* **Same UID / No Network Namespace**: Admission Gate executes with the agent's user privileges. It prevents tools from accidentally or adversarially running unauthorized executables, modifying protected trees, or leaking environment secrets.
* **Network Confinement**: Admission Gate is **not** a network firewall. It blocks egress tools (`curl`, `wget`, `ssh`, `socat`) through executable allowlists/denylists. If strict TCP/UDP packet isolation is required, run the host agent inside a container without network access (`--network none`).

---

## Installation

```bash
git clone [https://github.com/ak-skwaa-mahawk/admission-gate.git](https://github.com/ak-skwaa-mahawk/admission-gate.git)
cd admission-gate
pip install .

CLI Usage & Flags
# Run the gate with explicit boundaries and timeouts
admission-gate \
  --read-root ./repo \
  --write-root ./workspace \
  --allow-bin git --allow-bin python3 --allow-bin ls \
  --deny-bin curl --deny-bin ssh \
  --timeout 15.0 \
  --config admission_gate.toml

Supported Flags
| Flag | Description |
|---|---|
| --read-root <path> | Read-only directory boundary (repeatable) |
| --write-root <path> | Write-capable directory boundary (repeatable) |
| --allow-bin <name> | Explicitly allowed executable basename or path (repeatable) |
| --deny-bin <name> | Explicitly denied executable basename (repeatable) |
| --timeout <sec> | Subprocess timeout in seconds (default: 30.0) |
| --no-scrub-env | Bypass process environment variable scrubbing |
| --verify-only | Audit and verify proposals without spawning subprocesses |
| --no-confirm | Bypass interactive operator TTY prompt |
| --config <file> | Path to TOML configuration file |
Audit Replay & Verification
Verify the cryptographic integrity of the audit chain:
query-audit --verify

Re-evaluate historical proposals against the current v0.4.0 policy:
query-audit --replay --config admission_gate.toml

The replay engine compares historical decisions against active rules and outputs diffs:
 * WOULD STILL ADMIT: Still complies with current policy.
 * WOULD NOW DENY (divergence: argv0 | write-root | timeout | env): Command would be blocked under updated security controls.
 * CANNOT REPLAY (SCHEMA GAP): Distinguishes pre-0.4.0 legacy records lacking binary resolution data.
Python API Integration
from admission_gate import (
    ActionProposal,
    ExecConfig,
    GateConfig,
    ProcessConfig,
    gated_shell,
)

cfg = GateConfig(
    read_roots=["./repo"],
    write_roots=["./workspace"],
    require_confirm=False,
    exec_policy=ExecConfig(allow=["python3", "git", "cat"], deny=["curl"]),
    process=ProcessConfig(timeout_seconds=15.0, scrub_env=True),
)

proposal = ActionProposal("act-1", "cat ./repo/main.py", "./repo", risk_tier=1)
executed, output, exit_code = gated_shell(proposal, config=cfg)

Testing
PYTHONPATH=src python3 -m unittest discover -s tests

License
MIT
EOF

---

### Step 3: Run the Integration Example to Populate `audit_log.jsonl`

Run `examples/agent_runner.py` with `PYTHONPATH=src`:

```bash
PYTHONPATH=src python3 examples/agent_runner.py

Expected output:
[act-1] SUCCESS (code 0): ...
[act-2] REJECTED BY POLICY: Blocked: binary 'curl' is explicitly denied by execution policy
[act-3] REJECTED BY POLICY: Blocked: mutating/destructive action targets read-only root './repo/overwrite.py'
[act-4] SUCCESS (code 0): 

Now test --verify and --replay against the generated log:
query-audit --verify
query-audit --replay --config admission_gate.toml.example

Step 4: Run the Complete Test Suite
PYTHONPATH=src python3 -m unittest discover -s tests

Confirm all unit, hardening, and v0.4.0 integration tests pass.
Step 5: Commit and Tag v0.4.0
git add src/ tests/ examples/ README.md admission_gate.toml.example
git commit -m "release: v0.4.0 - CLI flags, schema-versioned audit ledger, replay diffs, and docs"
git tag v0.4.0
git push origin main --tags

 (`[y/N]`) on interactive terminals or runs headless with structured outputs in CI/automation.
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
printf '%s\n' '{"action_id": "step_1", "command": "ls -la", "target_path": "./workspace", "risk_tier": 1}' | admission-gate

# Headless / Dry-Run verification in CI
printf '%s\n' '{"action_id": "ci_1", "command": "rm file.txt", "target_path": "./workspace", "risk_tier": 1}' | admission-gate --verify-only
```

### 2. @verify-audit` (Cryptographic Verification)

Validates SHA-256 hash chains and checks tamper resistance:

```bash
verify-audit audit_log.jsonl
```

### 3. `query-audit` (Forensic Query & Replay)

Filter historical records or simulate past proposals against updated policies:

```bash
# Filter by risk tier or status
query-audit --tier 3
query-audit --status blocked

# Filter by time window--since 15m
query-audit --since 15m
query-audit --until 5m

# Replay past actions against current admission_gate.toml rules
query-audit --action-id step_1 --replay
```

### 4. `admission-gate-mcp` (MCP Adapter)

Add to your MCP-compliant host config:

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

## Security Model & Known Limitations

1. **Heuristic Parsing vs. Full AST**: `admission-gate` tokenizes via `shlex` and regex checks rather than a complete Bash ASS parser. While metacharacters (`$()`, backticks, redirections) and unexpanded environment variables are proactively rejected, nested subshell combinations should be bounded via strict root policies and binary whitelisting.
2. **Zero-Dependency Wire Protocol**: The MCP server implements standard JSON-RPC 2.0 directly rather than depending on the official MCP SDK.
3. **Execution Isolation**: Policy checks occur prior to subprocess spawning. For hard multi-tenant or untrusted-code isolation, `admission-gate` should be run inside an ephemeral container or unprivileged namespace.

---

## Running the Test Suite

```bash
PYTHONPATG=src python3 -m unittest discover -s tests
```

---

## License

[MIT)(LICENSE)
