# Servers Outbound Connections

A Splunk Dashboard Studio / Classic Simple XML dashboard for monitoring outbound network connections from internal Windows and Linux servers to external IP addresses.

## Dashboard overview

The dashboard is organized by operating system and provides:

### Windows
- Total outbound connections to external IPs
- Number of distinct hosts
- Number of distinct external destination IPs
- Top processes by connection count
- Detailed outbound connection table with first/last seen, destination host, user, process, destination IP/port, event code, initiation flag, source and count

Windows data selection includes Sysmon and Windows XML event sources. Sysmon network connection events (EventCode 3) are retained only when `Initiated=true`.

### Linux
- Total outbound connections to external IPs
- Number of distinct hosts
- Number of distinct external destination IPs
- Top processes by connection count
- Detailed outbound connection table with first/last seen, destination host, user, process, destination IP/port, source and count

Linux data selection includes Auditbeat and auditd sources.

## Filtering and data assumptions

- Default time range: last 24 hours; the time picker controls all panels.
- Searches use the accelerated `Endpoint.Ports` data model with `summariesonly=true`.
- DNS destination port 53 and port 0 are excluded.
- RFC1918/private, loopback, link-local, carrier-grade NAT, multicast and selected non-routable IPv4/IPv6 destinations are excluded from the external-IP view.
- The dashboard depends on correctly populated Endpoint.Ports data-model fields, including destination IP/port, destination host, process, user and source.
- The dashboard XML is a starting point. Validate the field mappings, sourcetypes, data-model acceleration and CIM normalization in your Splunk environment before operational use.

## Import

1. In Splunk, open **Dashboards** and create or import a dashboard.
2. Use the XML source/import option available in your Splunk version.
3. Review the data-model and sourcetype assumptions above.
4. Confirm that the panels return expected results using a controlled time range and known test telemetry.

## Scope and limitations

This dashboard provides visibility and investigation context; it is not, by itself, a detection or an alerting rule. High connection volume does not necessarily indicate malicious activity. Use host/process baselines, destination reputation, business context and additional telemetry to triage anomalies.

The dashboard uses accelerated data-model summaries. Results may be incomplete or delayed if acceleration is unavailable or the relevant events are not mapped into the Endpoint.Ports data model.

---

Created by Amin Kaviri as part of the SOC / Defensive Security portfolio.
