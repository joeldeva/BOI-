#!/usr/bin/env python3
"""Script to clone and verify official Quark behavior rules for FraudShield DeceptiScope."""

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TARGET_DIR = PROJECT_ROOT / "runtime" / "quark-rules"

print("================ Quark Rules Setup ================")
print(f"Target directory: {TARGET_DIR}")

if TARGET_DIR.is_dir() and any(TARGET_DIR.rglob("*.json")):
    json_count = len(list(TARGET_DIR.rglob("*.json")))
    print(f"Quark rules already present ({json_count} JSON rules found).")
else:
    TARGET_DIR.parent.mkdir(parents=True, exist_ok=True)
    print("Cloning official quark-rules repository...")
    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        "https://github.com/quark-engine/quark-rules.git",
        str(TARGET_DIR),
    ]
    try:
        subprocess.run(cmd, check=True)
        json_count = len(list(TARGET_DIR.rglob("*.json")))
        print(f"Successfully cloned {json_count} Quark detection rules!")
    except Exception as e:
        print(f"Error cloning repository: {e}")
        sys.exit(1)

print("\nTo enable Quark in FraudShield DeceptiScope:")
print("Ensure .env contains:")
print("  FRAUDSHIELD_QUARK_ENABLED=true")
print(f"  FRAUDSHIELD_QUARK_RULES_DIR={TARGET_DIR}")
print("  FRAUDSHIELD_QUARK_MAX_RULES=300")
