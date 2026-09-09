#!/data/data/com.termux/files/usr/bin/bash
set -u

echo "================================================================"
echo "  admission-gate: Out-of-Band Agent Boundary Enforcement Demo   "
echo "================================================================"
echo

# 1. Initialize charter
echo "[1] Initializing statutory charter..."
admission-gate init --path ./demo_charter.json 2>/dev/null || true
echo

# 2. Test permitted intra-vires execution
echo "[2] Testing INTRA-VIRES permitted operation..."
admission-gate exec \
  --charter ./demo_charter.json \
  --action "SHELL_READ" \
  --resource "./telemetry.json" \
  -- echo ">> SUCCESS: Work directory read executed within chartered bounds."
echo "Exit code: $?"
echo

# 3. Test illegal ultra-vires operation (path violation)
echo "[3] Testing ULTRA-VIRES prompt-injection / escape attempt..."
admission-gate exec \
  --charter ./demo_charter.json \
  --action "SHELL_READ" \
  --resource "/sys/kernel/override" \
  -- cat /sys/kernel/override
echo "Exit code: $?"
echo

echo "================================================================"
echo "  Result: Exit 126 veto prevents execution before shell launch. "
echo "================================================================"
