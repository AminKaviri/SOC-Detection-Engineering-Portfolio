# Splunk SPL Companion Queries

These SPL examples accompany the three candidate Sigma rules in `rules/windows/`. They are starting points, not production-ready detections. Replace `index=windows` with the index used in your environment and confirm field extraction before use. No query here has been executed against a live Splunk instance.

## Data and field assumptions

- **PowerShell encoded command:** Sysmon process creation events, typically `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`, Event ID 1, with `Image` and `CommandLine` extracted.
- **Failed logons:** Windows Security events, typically `sourcetype="XmlWinEventLog:Security"`, Event ID 4625, with `IpAddress`, `TargetUserName`, and `ComputerName` extracted. Some environments use CIM aliases such as `src`, `user`, and `dest`.
- **Service creation via sc.exe:** Sysmon process creation Event ID 1 with `Image` and `CommandLine`. If using Security Event ID 4688 instead, adapt the sourcetype and field names to your process-creation audit configuration.

## 1. Suspicious PowerShell encoded command

**Related Sigma:** [suspicious_powershell_encoded_command.yml](../rules/windows/suspicious_powershell_encoded_command.yml)  
**Telemetry:** Sysmon Event ID 1 / process creation  
**Purpose:** Find PowerShell command lines using common encoded-command switches.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval image_l=lower(coalesce(Image, New_Process_Name, process_path, ""))
| eval cmd_l=lower(coalesce(CommandLine, Process_Command_Line, process, ""))
| where (like(image_l, "%\powershell.exe") OR like(image_l, "%\pwsh.exe"))
| where match(cmd_l, "(^|\s)-(enc|encodedcommand|e)(\s|$)")
| eval detection_name="Suspicious PowerShell encoded command"
| table _time host User Image CommandLine ParentImage ParentCommandLine detection_name
| sort - _time
```

**Positive test:** A synthetic process event where `Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` and `CommandLine=powershell.exe -EncodedCommand SQBFAFgA` should match.  
**Negative test:** A synthetic event where `Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` and `CommandLine=powershell.exe -NoProfile -File inventory.ps1` should not match.  
**False positives / tuning:** Approved software deployment, endpoint management, and administrative scripts may use encoded arguments. Do not globally exclude encoded PowerShell; prefer scoped, owner-attributed exceptions with expiry. This query intentionally matches a switch, not whether the decoded payload is malicious.

## 2. Repeated failed logons from one source

**Related Sigma:** [multiple_failed_logons_single_source.yml](../rules/windows/multiple_failed_logons_single_source.yml)  
**Telemetry:** Windows Security Event ID 4625  
**Purpose:** Aggregate failed logons by source, account, and destination over a 10-minute window. Unlike the Sigma event selector, this SPL adds thresholding.

```spl
index=windows sourcetype="XmlWinEventLog:Security" EventCode=4625
| eval src_ip=coalesce(IpAddress, src, Source_Network_Address, "unknown")
| eval target_user=coalesce(TargetUserName, user, Account_Name, "unknown")
| eval target_host=coalesce(ComputerName, dest, host, "unknown")
| bin _time span=10m
| stats count as failures values(Status) as statuses values(Sub_Status) as sub_statuses by _time src_ip target_user target_host
| where failures >= 10
| eval detection_name="Repeated failed logons from one source"
| sort - failures
```

**Threshold:** 10 or more failures per source/account/destination in a 10-minute bucket. Tune based on baselines and authentication patterns; this is a starter threshold, not a universal brute-force criterion.  
**Positive test:** At least 10 synthetic EventCode 4625 events with the same source IP, target account, destination, and 10-minute bucket should produce a result.  
**Negative test:** Nine otherwise identical events in that bucket should not produce a result. Events spread across buckets may not meet the threshold.  
**False positives / tuning:** Mistyped passwords, expired service credentials, scheduled tasks, and application retries. Consider also a separate source-wide/multi-account analytic; this query groups by one target account and will not detect every password-spraying pattern. Confirm how your Windows XML field extraction represents missing IP addresses and status codes.

## 3. Windows service creation using sc.exe

**Related Sigma:** [windows_service_creation_system_utility.yml](../rules/windows/windows_service_creation_system_utility.yml)  
**Telemetry:** Sysmon Event ID 1 / process creation  
**Purpose:** Find `sc.exe create` command lines for triage of possible service installation/persistence.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval image_l=lower(coalesce(Image, New_Process_Name, process_path, ""))
| eval cmd_l=lower(coalesce(CommandLine, Process_Command_Line, process, ""))
| where like(image_l, "%\sc.exe")
| where match(cmd_l, "(^|\s)create(\s|$)")
| eval detection_name="Windows service creation using sc.exe"
| table _time host User Image CommandLine ParentImage ParentCommandLine detection_name
| sort - _time
```

**Positive test:** A synthetic process event with `Image=C:\Windows\System32\sc.exe` and `CommandLine=sc.exe create ExampleSvc binPath= C:\Temp\agent.exe` should match.  
**Negative test:** A synthetic event with `Image=C:\Windows\System32\sc.exe` and `CommandLine=sc.exe query ExampleSvc` should not match.  
**False positives / tuning:** Authorized software installs and endpoint-management tools. Review the service name, binary path, signer, parent process, invoking account, change records, and whether the binary path is writable by unprivileged users.

## Validation notes

- The queries are authored SPL examples and have **not** been run against a live Splunk deployment.
- Field names and sourcetypes vary by Windows collection method, add-ons, and CIM normalization. Verify them in your environment.
- The failed-logon SPL implements a threshold that the linked Sigma rule does not; its aggregation semantics are therefore intentionally different.
- The positive/negative scenarios are test specifications, not evidence that a real Splunk search was executed.
