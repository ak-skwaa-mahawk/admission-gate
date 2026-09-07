# admission-gate

A lightweight admission gatekeeper and cryptographic audit logger for autonomous CLI agents.

When local scripts or LLMs execute commands in a subshell, developers are forced between two extremes: fully autonomous execution that risks destructive operations, or prompt fatigue from micro-approving dozens of benign commands. `admission-gate` sits between the agent and your shell:

1. **Deterministic Filter**: Blocks dangerous patterns (`rm -rf /`) and restricts filesystem access to configured `allowed_roots` using strict path canonicalization.
2. **Interactive TTY Confirmation**: Halts for human authorization (`[y/N]`) only on proposals that pass static policy checks.
3. **SHA-256 Audit Trail**: Commits all proposals, policy outcomes, and approval decisions to an append-only, hash-chained log.

Requires Python 3.8+ with zero third-party dependencies.

---

## Quickstart

```bash
git clone [https://github.com/ak-skwaa-mahawk/admission-gate.git](https://github.com/ak-skwaa-mahawk/admission-gate.git)
cd admission-gate
pip install .
```

---

## Library Usage

Wrap your agent's shell execution tool so rejected actions never hit the subshell:

```python
from admission_gate import ActionProposal, gated_shell

proposal = ActionProposal(
    action_id="task_101",
    command="rm scratch.tmp",
    target_path="./workspace/scratch.tmp",
    risk_tier=2,
)

# Returns (executed: bool, output: str, exit_code: int)
executed, output, code = gated_shell(
    proposal,
    allowed_roots=["./workspace"],
    log_path="audit_log.jsonl",
    require_confirm=True,
)

if not executed:
    print(f"Action refused: {output}")
else:
    print(f"Command succeeded:\n{output}")
```

### Standalone Policy Checks

```python
from admission_gate import ActionProposal, evaluate

p = ActionProposal("chk_1", "cat /etc/shadow", "/etc/shadow", 1)
passed, reason = evaluate(p)
# passed -> False
# reason -> "Blocked: path resolves to protected directory '/etc'"
```

---

## Verifying Audit Log Integrity

```bash
python3 src/admission_gate/verify.py audit_log.jsonl
```

---

## Running Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

---

## License

[MIT](LICENSE)
