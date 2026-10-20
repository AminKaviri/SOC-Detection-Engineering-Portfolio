#!/usr/bin/env python3
"""Check basic Sigma YAML structure and required metadata.

This is a lightweight content check, not a Sigma backend or detection test.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"
REQUIRED = {"title", "id", "status", "description", "logsource", "detection", "level"}


def main() -> int:
    rule_paths = sorted(RULES_DIR.rglob("*.yml")) + sorted(RULES_DIR.rglob("*.yaml"))
    if not rule_paths:
        print(f"ERROR: no YAML rules found under {RULES_DIR}", file=sys.stderr)
        return 1

    errors: list[str] = []
    seen_ids: set[str] = set()
    for path in rule_paths:
        try:
            parsed: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            errors.append(f"{path.relative_to(ROOT)}: YAML parse failed: {exc}")
            continue
        if not isinstance(parsed, dict):
            errors.append(f"{path.relative_to(ROOT)}: top-level YAML value must be a mapping")
            continue
        missing = sorted(REQUIRED - parsed.keys())
        if missing:
            errors.append(f"{path.relative_to(ROOT)}: missing required keys: {', '.join(missing)}")
        rule_id = parsed.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            errors.append(f"{path.relative_to(ROOT)}: id must be a non-empty string")
        elif rule_id in seen_ids:
            errors.append(f"{path.relative_to(ROOT)}: duplicate id {rule_id}")
        else:
            seen_ids.add(rule_id)
        if not isinstance(parsed.get("detection"), dict) or "condition" not in parsed["detection"]:
            errors.append(f"{path.relative_to(ROOT)}: detection must include a condition")

    if errors:
        print("\n".join(f"ERROR: {item}" for item in errors), file=sys.stderr)
        return 1

    print(f"Metadata/YAML checks passed for {len(rule_paths)} rules.")
    print("Note: this does not test backend conversion or detection behavior.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
