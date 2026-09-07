import re
import shlex
from typing import Tuple

TIER_3_COMMANDS = {
    "rm", "mv", "chmod", "chown", "dd", "truncate",
    "kill", "pkill", "systemctl", "mkfs", "fdisk"
}

TIER_1_COMMANDS = {
    "cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep",
    "ls", "pwd", "which", "whereis", "find", "stat", "file",
    "wc", "diff", "echo", "printf", "true", "false", "test"
}

class PolicyEngine:
    # ... existing canonicalization & patterns ...

    @classmethod
    def classify_risk(cls, command: str) -> Tuple[int, str]:
        """
        Infers the minimum risk tier (1-3) based on command structure and binaries.
        Returns (computed_tier, justification).
        """
        # 1. Pipeline and segment splitting
        segments = re.split(r"[;&|]+", command)
        max_tier = 1
        reasons = []

        # Check for output redirection anywhere in command
        if re.search(r"(?:^|[^<])>{1,2}", command):
            max_tier = max(max_tier, 2)
            reasons.append("output redirection detected")

        for segment in segments:
            seg = segment.strip()
            if not seg:
                continue

            try:
                tokens = shlex.split(seg, posix=True)
            except ValueError:
                return 3, "malformed command quotes/syntax"

            if not tokens:
                continue

            binary = os.path.basename(tokens[0])

            # In-place editing flags
            if binary == "sed" and any(arg.startswith("-i") or arg == "--in-place" for arg in tokens[1:]):
                max_tier = max(max_tier, 3)
                reasons.append("sed in-place edit (-i)")
                continue

            # Destructive checks
            if binary in TIER_3_COMMANDS:
                max_tier = max(max_tier, 3)
                reasons.append(f"destructive binary '{binary}'")
            elif binary in TIER_1_COMMANDS:
                # Retains current tier unless already elevated
                pass
            else:
                # Unrecognized or mutating binary (python, gcc, git, touch, etc.)
                max_tier = max(max_tier, 2)
                reasons.append(f"mutating or unclassified binary '{binary}'")

        if not reasons:
            reasons.append("read-only binary match")

        return max_tier, "; ".join(reasons)
