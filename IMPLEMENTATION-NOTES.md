# Implementation Notes

## Target progression
SOC Analyst Tier 2 → Detection Engineering → Threat Hunting → Incident Response → Security Architecture.

## Status
This is a staging bundle of independent portfolio workstreams. Each subdirectory is intended to be separable into its own repository. The connected GitHub actions in this session do not expose repository creation or archive operations, so no such actions are claimed.

## Quality and safety principles
- Use synthetic telemetry or data explicitly authorized for sharing.
- Separate observations, hypotheses, and conclusions.
- Document telemetry dependencies, false positives, blind spots, and limits.
- A YAML/metadata check is not proof of backend execution or production efficacy.
- Never commit credentials, tokens, internal hostnames, customer data, or unredacted production logs.

## Build order
1. Detection engineering: rules, fixtures, CI, and tuning notes.
2. SOC investigations: repeatable triage and evidence-led reports.
3. Threat hunting: hypotheses, required data, queries, and stopping criteria.
4. Incident response: escalation, containment, recovery, and lessons learned.
5. ATT&CK coverage: mappings with evidence-based status.
6. Professional profile and project navigation.
