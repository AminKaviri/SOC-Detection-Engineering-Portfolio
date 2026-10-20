# Amin Kaviri — SOC Analyst T2 & Defensive Security Portfolio

Practical work focused on SOC Tier 2 investigation, detection engineering, threat hunting, incident response, and progressive development toward security architecture.

> **Data handling:** examples use synthetic or authorized data. Do not commit production logs, credentials, personal data, internal hostnames, or customer information.

## Workstreams

| Project | Focus | Current evidence |
|---|---|---|
| [Sigma Detection Engineering](./sigma-detection-engineering/) | Detection logic, synthetic fixtures, basic content validation | Three candidate Windows rules; YAML/metadata validator |
| [SOC Investigation Lab](./soc-investigation-lab/) | Alert triage and evidence-led investigations | Case report template and investigation principles |
| [Threat Hunting Lab](./threat-hunting-lab/) | Hypothesis-driven hunts and telemetry requirements | Hunt plan template |
| [Incident Response Playbooks](./incident-response-playbooks/) | Escalation, containment, recovery, and lessons learned | Playbook template |
| [MITRE ATT&CK Coverage](./mitre-attack-coverage/) | Traceable technique mapping and evidence states | Initial candidate coverage matrix |
| [Profile README draft](./profile-README/README.md) | Public-facing portfolio overview | Draft ready to adapt to the special profile repository |

## Engineering principles

1. **Evidence over claims:** separate observations, hypotheses, and conclusions.
2. **Reproducibility:** document prerequisites, inputs, expected outputs, and validation limits.
3. **Operational value:** include triage steps, escalation criteria, false-positive handling, and follow-up.
4. **Honest testing:** metadata checks are not backend conversion or detection tests.
5. **Defensive scope:** use authorized environments and approved procedures.

## Current validation status

The Sigma lab includes a validator for YAML parsing, key metadata, unique IDs, and a detection condition. Synthetic JSON fixtures document expected-match/non-match intent but are not automatically executed against a SIEM. All candidate rules require backend conversion, representative replay testing, and environment-specific tuning before operational use.

## Roadmap

- [x] Establish project structure and core documentation
- [x] Add starter detection rules and a lightweight validator
- [ ] Run the validator in GitHub Actions and verify the workflow result
- [ ] Add executable backend/event tests
- [ ] Publish a fully worked, sanitized SOC investigation
- [ ] Expand ATT&CK mappings based on test evidence rather than tags alone

Portfolio direction: **SOC Analyst T2 → Detection Engineering → Threat Hunting → Incident Response → Security Architecture**.
