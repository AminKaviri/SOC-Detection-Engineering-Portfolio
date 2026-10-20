# Security Scripts — SOC & Detection Engineering Portfolio

This repository is being reorganized into a focused defensive-security portfolio. The active portfolio content is currently staged in the [portfolio-staging branch](https://github.com/AminKaviri/Security-Scripts/tree/portfolio-staging) while the repository layout is being finalized.

## Portfolio workstreams

- [Sigma Detection Engineering](https://github.com/AminKaviri/Security-Scripts/tree/portfolio-staging/sigma-detection-engineering) — three candidate Windows rules, metadata validation, and false-positive analysis.
- [SOC Investigation Lab](https://github.com/AminKaviri/Security-Scripts/tree/portfolio-staging/soc-investigation-lab) — case-report template and a synthetic encoded-PowerShell investigation.
- [Threat Hunting Lab](https://github.com/AminKaviri/Security-Scripts/tree/portfolio-staging/threat-hunting-lab) — hunt plan template and a contextual PowerShell hunt.
- [Incident Response Playbooks](https://github.com/AminKaviri/Security-Scripts/tree/portfolio-staging/incident-response-playbooks) — response workflow template.
- [MITRE ATT&CK Coverage](https://github.com/AminKaviri/Security-Scripts/tree/portfolio-staging/mitre-attack-coverage) — candidate mappings with explicit evidence status.
- [Profile README draft](https://github.com/AminKaviri/Security-Scripts/blob/portfolio-staging/profile-README/README.md) — a public-facing profile draft.

## Validation

The [GitHub Actions validation run](https://github.com/AminKaviri/Security-Scripts/actions/runs/39493942416) passed the basic Sigma YAML/metadata checks for three rules. It does not prove backend conversion or detection efficacy. The candidate rules still require target-backend testing, representative replay, and environment-specific tuning.

## Principles

- Use synthetic or explicitly authorized telemetry.
- Separate observed facts, hypotheses, and conclusions.
- Document false positives, limitations, and telemetry dependencies.
- Never commit production logs, credentials, or customer information.

Career direction: **SOC Analyst T2 → Detection Engineering → Threat Hunting → Incident Response → Security Architecture**.
