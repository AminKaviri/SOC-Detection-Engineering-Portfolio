# Case Study 001 — Encoded PowerShell Alert (Synthetic Lab)

> **Training data only.** All hostnames, identities, timestamps, and events in this case are fictional. This is an example of evidence-led triage, not a real incident.

## Summary

A detection candidate fired because a PowerShell command line contained an encoded-command switch. Decoding the supplied synthetic payload produces `Write-Output`, a benign command in this scenario. The event is therefore a **benign positive for the broad behavior rule**, not proof of malicious activity.

- **Initial severity:** Medium (candidate rule default)
- **Final disposition:** Benign positive in this synthetic scenario
- **Confidence:** High for the narrow conclusion based on the provided fixture; no claim is made about other activity outside the reviewed telemetry
- **Primary lesson:** Encoded PowerShell is a triage signal. Context and decoded behavior determine the assessment.

## Evidence reviewed

| Time (UTC) | Source | Synthetic observation | Interpretation |
|---|---|---|---|
| 09:41:03 | Endpoint process telemetry | `powershell.exe -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA` | Encoded-command switch meets the rule's condition |
| 09:41:03 | Parent-process telemetry | Parent is `explorer.exe` | Consistent with a user-launched lab example; not inherently safe |
| 09:41:04 | Payload review | UTF-16LE Base64 decodes to `Write-Output` | Decoded behavior is benign in the observed command |
| 09:41–09:46 | Correlated endpoint events | No additional suspicious child process or network activity in the supplied synthetic dataset | No corroborating signal in this limited dataset; this is not proof of absence |

## Triage process

1. Preserve the original process event, timestamp, host identity, user context, and rule version.
2. Validate the image path and command line; do not rely only on the process name.
3. Decode the argument safely in an isolated analysis context. Do not execute unknown payloads.
4. Review parent process, signer, user role, process ancestry, child processes, network activity, and nearby alerts.
5. Check change records or approved scripts where relevant.
6. Record what evidence was and was not available before assigning a disposition.

## Hypothesis review

| Hypothesis | Evidence | Outcome |
|---|---|---|
| A suspicious script is using PowerShell encoding to conceal behavior | Encoded switch is present | Candidate behavior observed, intent not established |
| The payload performs a benign operation | Decoded content is `Write-Output`; no corroborating suspicious behavior in the supplied dataset | Supported for this synthetic case |
| The host is otherwise clean | Only limited, synthetic events were provided | Not assessed |

## Disposition and tuning

**Disposition:** Benign positive for this synthetic case. Do not suppress all encoded PowerShell. Prefer contextual tuning that retains visibility for encoded commands launched by unusual parents, unexpected users, uncommon paths, or commands followed by suspicious process/network activity.

Potential tuning candidates must be tested against representative data and reviewed with the detection owner. Avoid broad allowlists based only on a filename or user.

## What would change the assessment?

Escalate for further investigation if decoded content, process ancestry, signer/path, child processes, outbound connections, account context, or related alerts indicate suspicious behavior. Preserve evidence and follow the organization's approved incident-response path.

## Validation limits

This case demonstrates analysis structure only. It is not a production investigation, does not establish the rule's false-positive rate, and does not prove coverage for PowerShell abuse generally.
