# Amin Kaviri — SOC Analyst T2 & Defensive Security Portfolio

Practical work focused on SOC Tier 2 investigation, detection engineering, threat hunting, incident response, and progressive development toward security architecture.

> **Data handling:** examples use synthetic or authorized data. Do not commit production logs, credentials, personal data, internal hostnames, or customer information.

## Workstreams

| Project | Focus | Current evidence |
|---|---|---|
| [Sigma Detection Engineering](./sigma-detection-engineering/) | Detection logic, synthetic fixtures, basic content validation | Three candidate Sigma rules; YAML/metadata validator; executable positive/negative fixture assertions for the encoded-PowerShell rule; [Splunk SPL companion queries](./sigma-detection-engineering/splunk/README.md); [false-positive analysis](./sigma-detection-engineering/docs/false-positive-analysis.md) |
| [SOC Investigation Lab](./soc-investigation-lab/) | Alert triage and evidence-led investigations | [Synthetic case study: encoded PowerShell alert](./soc-investigation-lab/cases/CASE-001-encoded-powershell.md) and reusable case-report template |
| [Threat Hunting Lab](./threat-hunting-lab/) | Hypothesis-driven hunts and telemetry requirements | [Hunt 001: contextual PowerShell risk](./threat-hunting-lab/hunts/HUNT-001-encoded-powershell.md) and hunt-plan template |
| [Incident Response Playbooks](./incident-response-playbooks/) | Escalation, containment, recovery, and lessons learned | Playbook template |
| [MITRE ATT&CK Coverage](./mitre-attack-coverage/) | Traceable technique mapping and evidence states | Initial candidate coverage matrix |
| [Profile README draft](./profile-README/README.md) | Public-facing portfolio overview | Draft ready to adapt to the special profile repository |

## Engineering principles

1. **Evidence over claims:** separate observations, hypotheses, and conclusions.
2. **Reproducibility:** document prerequisites, inputs, expected outputs, and validation limits.
3. **Operational value:** include triage steps, escalation criteria, false-positive handling, and follow-up.
4. **Honest testing:** metadata checks and narrow fixture assertions are not backend conversion or SIEM detection tests.
5. **Defensive scope:** use authorized environments and approved procedures.

## Current validation status

The GitHub Actions workflow validates Sigma YAML/metadata and executes narrow positive/negative fixture assertions for the encoded-PowerShell rule. The Splunk SPL companion provides queries, field/index assumptions, false-positive guidance, and positive/negative test scenarios for all three starter detections; the SPL has not been executed against a live Splunk instance. Fixture assertions are not a general Sigma interpreter and do not prove SIEM/backend conversion or detection efficacy. All candidate rules require backend conversion, representative replay testing, and environment-specific tuning before operational use.

## Roadmap

- [x] Establish project structure and core documentation
- [x] Add starter detection rules and a lightweight validator
- [x] Run the validator in GitHub Actions
- [x] Add executable positive/negative fixture assertions for the encoded-PowerShell rule
- [x] Add Splunk SPL companions for all three starter detections
- [x] Publish a worked synthetic SOC investigation case study
- [x] Document an initial threat-hunt workflow and tuning considerations
- [ ] Add actual Sigma backend conversion and representative event-replay tests
- [ ] Expand ATT&CK mappings based on test evidence rather than tags alone

Portfolio direction: **SOC Analyst T2 → Detection Engineering → Threat Hunting → Incident Response → Security Architecture**.
