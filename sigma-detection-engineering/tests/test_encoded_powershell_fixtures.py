"""Narrow fixture-level checks for the encoded-PowerShell Sigma rule.

This is deliberately not a general Sigma interpreter or backend conversion test.
It evaluates only the field operators used by this one rule so the documented
positive and negative fixtures are executable in CI.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = ROOT / "rules" / "windows" / "suspicious_powershell_encoded_command.yml"
POSITIVE_PATH = ROOT / "tests" / "positive" / "powershell_encoded_command.json"
NEGATIVE_PATH = ROOT / "tests" / "negative" / "powershell_regular_command.json"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def selector_matches(event: dict[str, Any], selector: dict[str, Any]) -> bool:
    """Evaluate the endswith/contains operators used in the selected rule."""
    for expression, expected in selector.items():
        if "|" not in expression:
            raise AssertionError(f"Unsupported fixture-test expression: {expression}")
        field, operator = expression.split("|", maxsplit=1)
        actual = event.get(field)
        if not isinstance(actual, str):
            return False
        candidates = expected if isinstance(expected, list) else [expected]
        if not all(isinstance(candidate, str) for candidate in candidates):
            raise AssertionError(f"Expected string values for {expression}")
        actual_folded = actual.casefold()
        candidate_values = [candidate.casefold() for candidate in candidates]
        if operator == "endswith":
            matched = any(actual_folded.endswith(value) for value in candidate_values)
        elif operator == "contains":
            matched = any(value in actual_folded for value in candidate_values)
        else:
            raise AssertionError(f"Unsupported fixture-test operator: {operator}")
        if not matched:
            return False
    return True


def rule_matches(event: dict[str, Any], rule: dict[str, Any]) -> bool:
    detection = rule["detection"]
    condition = detection["condition"]
    # This intentionally supports only the exact conjunction used by this rule.
    if condition != "selection_image and selection_switch":
        raise AssertionError(f"Unexpected rule condition for this test: {condition}")
    return (
        selector_matches(event, detection["selection_image"])
        and selector_matches(event, detection["selection_switch"])
    )


class EncodedPowerShellFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rule = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))

    def test_positive_fixture_matches_rule_logic(self) -> None:
        fixture = load_json(POSITIVE_PATH)
        self.assertEqual(fixture["expected_rule"], self.rule["id"])
        self.assertTrue(rule_matches(fixture["event"], self.rule))

    def test_negative_fixture_does_not_match_rule_logic(self) -> None:
        fixture = load_json(NEGATIVE_PATH)
        self.assertEqual(fixture["expected_rule_not"], self.rule["id"])
        self.assertFalse(rule_matches(fixture["event"], self.rule))


if __name__ == "__main__":
    unittest.main()
