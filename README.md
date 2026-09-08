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

