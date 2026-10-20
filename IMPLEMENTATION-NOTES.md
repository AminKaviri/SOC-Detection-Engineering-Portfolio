# Implementation Notes

## Target progression
SOC Analyst Tier 2 → Detection Engineering → Threat Hunting → Incident Response → Security Architecture.

## Current state
This repository is the canonical public portfolio: [SOC-Detection-Engineering-Portfolio](https://github.com/AminKaviri/SOC-Detection-Engineering-Portfolio). The workstreams below live together in this repository and are organized as separate, navigable project areas.

## Quality and safety principles
- Use synthetic telemetry or data explicitly authorized for sharing.
- Separate observations, hypotheses, and conclusions.
- Document telemetry dependencies, false positives, blind spots, and limits.
- A YAML/metadata check is not proof of backend execution or detection efficacy.
- Never commit credentials, tokens, internal hostnames, customer data, or unredacted production logs.
- State exactly what each test validates; do not describe a narrow fixture assertion as a full Sigma-engine test.

## Build order
1. Detection engineering: rules, fixtures, CI, and tuning notes.
2. SOC investigations: repeatable triage and evidence-led reports.
3. Threat hunting: hypotheses, required data, queries, and stopping criteria.
4. Incident response: escalation, containment, recovery, and lessons learned.
5. ATT&CK coverage: mappings with evidence-based status.
6. Professional profile and project navigation.

## Immediate engineering priorities
- Add executable positive/negative assertions for the encoded-PowerShell rule's documented field logic.
- Add automated checks for local Markdown links and stale repository URLs.
- Add backend conversion and representative replay testing when a concrete SIEM/backend is selected.
- Expand ATT&CK coverage only when supported by rule behavior and test evidence.
