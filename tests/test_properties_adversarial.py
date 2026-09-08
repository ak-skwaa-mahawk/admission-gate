import os
import random
import string
import pytest
from admission_gate import evaluate, GateConfig, ActionProposal

ALPHABET = "../abcdefghijklmnopqrstuvwxyz0123456789_/-"
ACTIVE_CONFIG = GateConfig(
    write_roots=["./workspace", "./scratch"],
    read_roots=["./workspace", "./scratch"],
    blocked_patterns=["rm -rf /", ":(){ :|:& };:", "/dev/sd", "> /dev/null"]
)

def generate_adversarial_paths(iterations=1000):
    corpus = [
        "../", "../../", "../../../etc/passwd", "..//..//",
        "./../", "/../", "/etc/shadow", "/data/data/com.termux",
        "./scratch/../../", "./workspace/../../../", "..\\..\\",
        "/proc/self/environ", "/dev/null", "~/../", "./scratch/../workspace"
    ]
    for _ in range(iterations):
        choice = random.randint(1, 4)
        if choice == 1:
            yield random.choice(corpus)
        elif choice == 2:
            base = random.choice(["./workspace", "./scratch", "/etc", "."])
            traversal = "/".join([".."] * random.randint(1, 5))
            suffix = "".join(random.choices(string.ascii_lowercase, k=4))
            yield f"{base}/{traversal}/{suffix}"
        elif choice == 3:
            segs = ["..", ".", "scratch", "workspace", "etc", "bin"]
            yield "/".join(random.choices(segs, k=random.randint(3, 6)))
        else:
            length = random.randint(1, 25)
            yield "".join(random.choices(ALPHABET, k=length))

def is_path_genuinely_contained(path: str, roots: list[str]) -> bool:
    try:
        norm_target = os.path.realpath(os.path.abspath(path))
        for root in roots:
            norm_root = os.path.realpath(os.path.abspath(root))
            if norm_target == norm_root or norm_target.startswith(norm_root + os.sep):
                return True
        return False
    except Exception:
        return False

def test_property_path_confinement_invariant():
    """
    Formal Map Invariant:
    When write_roots are enforced, any target_path resolving outside them
    MUST be rejected by policy.
    """
    random.seed(99733)
    tested_cases = 0

    for candidate in generate_adversarial_paths(500):
        tested_cases += 1
        prop = ActionProposal(
            action_id=f"fuzz-{tested_cases}",
            command=f"echo data > {candidate}",
            target_path=candidate,
            risk_tier=2
        )
        passed, reason = evaluate(prop, config=ACTIVE_CONFIG)

        contained = is_path_genuinely_contained(candidate, ACTIVE_CONFIG.write_roots)
        if not contained:
            assert passed is False, (
                f"Boundary bypass on '{candidate}'! Normalized target escaped write_roots: {reason}"
            )

    print(f"\n[PASS] Verified {tested_cases} adversarial paths against containment invariant.")

def test_property_blocked_patterns_never_pass():
    """
    Formal Policy Invariant:
    Any command matching blocked_patterns MUST fail policy evaluation unconditionally.
    """
    for pattern in ACTIVE_CONFIG.blocked_patterns:
        prop = ActionProposal(
            action_id="pattern-test",
            command=f"{pattern}",
            target_path="./scratch",
            risk_tier=2
        )
        passed, reason = evaluate(prop, config=ACTIVE_CONFIG)
        assert passed is False, f"Blocked pattern permitted: {pattern}"
