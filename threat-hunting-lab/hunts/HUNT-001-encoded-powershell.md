# Hunt 001 — Encoded PowerShell with Contextual Risk

> **Defensive lab hunt.** Use only authorized telemetry. The query below is a starting point and must be checked against the target tenant's schema and retention.

## Objective

Identify encoded PowerShell launches and prioritize those with contextual signals beyond the encoded switch alone.

## Hypothesis

If encoded PowerShell is being used for suspicious execution, some events may be associated with uncommon parent processes, unusual user/host combinations, suspicious child processes, or correlated network activity. Encoded arguments alone are insufficient to prove malicious intent.

## Data required

- Endpoint process creation events with image, command line, parent process, user, host, and timestamp
- Script-block or PowerShell operational telemetry where available
- Network connection telemetry and alert/case context
- Asset inventory, privileged-account context, and approved automation/change records

## Example query (Microsoft Defender Advanced Hunting / KQL starting point)

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FolderPath, SHA1
| order by Timestamp desc
```

Validate column names, query semantics, data availability, and licensing in the target environment before use. This query finds candidate events; it does not classify them as malicious.

## Review sequence

1. Confirm the executable path, command line, and signed binary context.
2. Decode the encoded argument safely; never execute an unknown payload.
3. Review parent/child process relationships and nearby script-block/network events.
4. Compare user, device, parent process, and command pattern against a documented baseline.
5. Check approved administrative automation and change records.
6. Record both corroborating and contradictory evidence.

## Outcome recording

- Events reviewed:
- Distinct devices/users:
- Confirmed suspicious cases:
- Benign patterns / candidate tuning:
- Telemetry gaps:
- Escalation or detection change:
- Confidence and limitations:

## Stopping criteria

Stop and escalate under the organization's incident procedure if high-confidence malicious execution, credential access, lateral movement, or active impact is observed. Do not take disruptive containment action based on this hunt template alone.
