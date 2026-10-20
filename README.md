# Security Scripts — SOC & Detection Engineering Portfolio

A practical cybersecurity portfolio focused on SOC Tier 2 workflows, detection engineering, threat hunting, log analysis, and incident response.

> **Scope:** Educational and defensive security work using synthetic or authorized data. Never commit production logs, secrets, credentials, or customer information.

## Portfolio roadmap

| Workstream | Objective | Evidence |
|---|---|---|
| Detection engineering | Develop, document, and validate Sigma detections | Rule metadata, test fixtures, false-positive notes |
| SOC investigations | Turn alerts into repeatable investigations | Triage checklists, investigation reports, evidence timelines |
| Threat hunting | Form hypotheses and test them against telemetry | Hunt plans, queries, findings, limitations |
| Incident response | Standardize containment, eradication, and recovery decisions | Playbooks, decision points, post-incident review templates |
| ATT&CK coverage | Map detection ideas to MITRE ATT&CK techniques | Coverage matrix with confidence and validation status |
| Engineering quality | Keep content reproducible and maintainable | Tests, CI, usage instructions, changelog |

## Planned structure

- `sigma-detection-engineering/` — Sigma rules, synthetic test cases, and validation workflow
- `soc-investigation-lab/` — alert triage and evidence-based case reports
- `threat-hunting-lab/` — hypothesis-driven hunt plans and query examples
- `incident-response-playbooks/` — actionable response procedures
- `mitre-attack-coverage/` — traceable coverage mapping

## Working principles

1. **Evidence over claims:** separate observed facts, inferences, and unknowns.
2. **Reproducibility:** explain prerequisites, inputs, expected outputs, and validation.
3. **Safe data handling:** use synthetic data; sanitize all examples.
4. **Honest validation:** distinguish syntax/metadata checks from actual backend execution.
5. **Operational usefulness:** include triage steps, escalation criteria, and tuning guidance.

## Roadmap

- [ ] Validate the project structure and remove broken references
- [ ] Add CI checks for detection content
- [ ] Publish an end-to-end SOC investigation using synthetic telemetry
- [ ] Add ATT&CK mapping and coverage criteria
- [ ] Add quality gates and release notes

## Disclaimer

This repository is for defensive security education and authorized environments only. Detection results depend on available telemetry, backend behavior, and environment-specific tuning.
