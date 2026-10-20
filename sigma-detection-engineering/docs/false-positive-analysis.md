# False-Positive Analysis — Starter Sigma Rules

This document records likely benign patterns and practical triage context. These are hypotheses to test in a lab, not a substitute for measured false-positive statistics.

## 1. Suspicious PowerShell Encoded Command

**Signal:** PowerShell process command line includes `-enc`, `-encodedcommand`, or a short encoded-command switch.

**Potential benign sources**
- Approved endpoint-management and software-deployment agents
- Administrative scripts that encode arguments to transport Unicode text
- Lab exercises and automation tests

**Triage pivots**
- Decode the argument without executing it.
- Validate process path, signer, parent process, user, and execution context.
- Correlate child processes, script-block telemetry, network events, and nearby alerts.
- Compare with approved script deployment/change records.

**Tuning guardrails**
- Do not globally suppress encoded PowerShell.
- Prefer narrowly scoped, time-bounded exceptions with an owner and expiry date.
- Test rule behavior with representative benign and suspicious examples before deployment.

## 2. Failed Windows Logons (Event ID 4625)

**Signal:** A failed logon event is observed.

**Potential benign sources**
- Mistyped passwords
- Expired service credentials
- Misconfigured scheduled tasks
- Legitimate application retry behavior

**Triage pivots**
- Source address/workstation, target account, logon type, status/substatus, event rate, and time distribution
- Successful logons after failures and activity across multiple accounts
- Asset criticality and whether the source is expected to authenticate to the target

**Important limitation:** the included rule is a candidate event selector, not an implemented threshold/aggregation rule. It must not be presented as brute-force detection until thresholding, grouping, exclusions, and tests are implemented in the actual backend.

## 3. Windows Service Creation via sc.exe

**Signal:** Process creation shows `sc.exe create`.

**Potential benign sources**
- Authorized software installation
- Endpoint management and service deployment
- Approved system administration

**Triage pivots**
- Parent process, invoking account, service name, binary path, signer, change ticket, and service start behavior
- Whether the binary path is writable by an unprivileged user
- Related process, registry, logon, and network activity

## Recording a tuning decision

For every exception, record the detection version, evidence, affected scope, owner, approval, expiry, expected impact on true-positive visibility, and rollback method. Re-evaluate exceptions after major rule or telemetry changes.
