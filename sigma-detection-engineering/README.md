# Sigma Detection Engineering Lab

A defensive detection-engineering workstream focused on readable Sigma rules, explicit telemetry assumptions, synthetic validation fixtures, false-positive tuning, and portable Splunk SPL examples.

## Included candidate rules
- **Suspicious PowerShell encoded command** — searches process command lines for encoded-command switches.
- **Repeated failed logons** — candidate event selector; the Splunk companion adds a documented aggregation threshold.
- **Windows service creation** — flags a possible service-creation pattern using a system utility.

**Required companion:** Every detection must include a corresponding Splunk SPL query. The current examples, assumptions, positive/negative scenarios, and tuning notes are documented in [Splunk SPL Companion Queries](./splunk/README.md). These are starting points, not claims that each rule is production-ready. Validate field mappings and behavior in your SIEM/EDR backend before deployment.

## Validate locally

Python 3.10+ and PyYAML are required:

```bash
python -m pip install -r requirements-dev.txt
python scripts/validate_rules.py
python -m unittest discover -s tests -p 'test_*.py' -v
```

The metadata validator checks YAML parseability and required Sigma fields. The fixture tests execute a deliberately narrow evaluator for the field operators and condition used by the encoded-PowerShell rule, then assert that the positive fixture matches and the benign negative fixture does not. They are **not** a general Sigma interpreter, backend conversion test, or proof of operational efficacy.

## Lifecycle
1. Define behavior and a defensible hypothesis.
2. Confirm telemetry source and field mapping.
3. Write the Sigma rule and a corresponding Splunk SPL query.
4. Document index/sourcetype assumptions, field mappings, time window, expected matches, limitations, and false-positive handling.
5. Prepare expected-match and expected-non-match examples.
6. Run available fixture assertions and review false positives.
7. Convert and test against the target platform.
8. Version, document, monitor, and tune.

The SPL examples have not been executed against a live Splunk instance. Their positive/negative examples are test specifications until validated against representative events in a Splunk lab.
