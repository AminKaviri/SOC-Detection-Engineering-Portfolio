# Sigma Detection Engineering Lab

A defensive detection-engineering workstream focused on readable Sigma rules, explicit telemetry assumptions, synthetic validation fixtures, and false-positive tuning.

## Included candidate rules
- **Suspicious PowerShell encoded command** — searches process command lines for encoded-command switches.
- **Repeated failed logons** — documents a candidate signal; backend-specific aggregation is still needed.
- **Windows service creation** — flags a possible service-creation pattern using a system utility.

These are starting points, not claims that each rule is production-ready. Validate field mappings and behavior in your SIEM/EDR backend before deployment.

## Validate basic metadata
Python 3.10+ and PyYAML are required:
```bash
python -m pip install -r requirements-dev.txt
python scripts/validate_rules.py
```

The validator checks parseability and required Sigma metadata. It does **not** prove conversion, matching, performance, or operational efficacy.

## Lifecycle
1. Define behavior and a defensible hypothesis.
2. Confirm telemetry source and field mapping.
3. Write the rule and ATT&CK context when justified.
4. Prepare expected-match and expected-non-match examples.
5. Review false positives and benign administrative uses.
6. Convert and test against the target platform.
7. Version, document, monitor, and tune.
