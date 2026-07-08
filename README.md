# Threat Hunting Scenario: Credential Access Alert on a Domain Controller
**Author:** Madelynn Charron  
**Date:** June 2026  
**Tools used:** Wazuh (OpenSearch Dashboards / DQL)


## Overview

While proactively threat hunting for unauthorized credential access activity, I identified a pattern on `DC-01`. a domain controller, matching the MITRE ATT&CK **Credential Access** tactic — specifically resembling a Pass-the-Hash pattern. This write-up walks through the investigation from initial discovery to root cause, using Wazuh's Threat Hunting query interface (DQL) to query Windows Security Event Log data and authentication activity ingested into Wazuh via agent.

**Status:** Closed — False Positive


---

_Screenshots have been redacted to remove internal hostnames and IP addresses in accordance with data handling practices_

## Investigation Walkthrough

### Step 1 — Initial Discovery
```
rule.mitre.tactic: "Credential Access"
```
Queried for activity mapped to the Credential Access tactic to identify leads worth investigating further, and scoped the time window to the last 24 hours for the rest of the hunt.
<img width="1901" height="80" alt="image" src="https://github.com/user-attachments/assets/d4bcecc4-f81a-48e9-ab22-4adcfeed12e5" />


### Step 2 — Find the underlying failed logon events
```
agent.name: "DC-01" and data.win.system.eventID: 4625
```
Pulls the raw failed-logon events (Event ID 4625) that triggered the detection rule, rather than relying on the alert summary alone.
<img width="2335" height="139" alt="image" src="https://github.com/user-attachments/assets/f56e8ce5-fad8-4941-85db-eabb0005d1e4" />


### Step 3 — Check for successful logons from the same source IP
```
agent.name: "DC-01" and data.win.system.eventID: 4624 and data.win.eventdata.ipAddress: 10.10.0.10
```
Determines whether the source IP eventually succeeded in authenticating — an important distinction between "someone is guessing passwords" and "known authentication traffic that looks noisy."
<img width="2446" height="712" alt="image" src="https://github.com/user-attachments/assets/cffdbfdb-a09c-4139-b5e9-efaadc9497fa" />


### Step 4a — Check for lateral movement
```
data.win.eventdata.ipAddress: 10.10.0.10 and not agent.name: "DC-01"
```
Searches for the same source IP authenticating against *other* hosts in the environment. No hits — no evidence of lateral movement.
<img width="2481" height="140" alt="image" src="https://github.com/user-attachments/assets/27ed7c3d-4125-4cf1-bd61-8d7e2bc4841e" />


### Step 4b — Check for persistence or post-exploitation activity
```
data.win.system.eventID: (7045 or 4698 or 4702) and data.win.eventdata.ipAddress: 10.10.0.10
```
Looks for new services, scheduled tasks, or task modifications (common persistence mechanisms) tied to the source IP. No hits.

### Step 5 — Identify what the source actually is
```
agent.name: "PROXY-01"
```
The query results pointed to a Wazuh-monitored host named `PROXY-01`. I confirmed this with the IT team in standup, who verified the IP belongs to the organization's Duo MFA Authentication Proxy — cross-checking the log data against a human source rather than relying on the hostname alone.

---

## Root Cause

The NTLM authentication pattern is expected behavior for a MFA proxy, not an attacker — confirmed with the IT team, who verified the source IP belongs to the organization's MFA Authentication Proxy. MFA proxies relay authentication requests to the domain controller in a way that structurally resembles NTLM relay/PtH traffic to a signature-based rule, without actually being malicious.

No evidence of lateral movement, privilege escalation, or post-exploitation activity was found anywhere in the environment tied to this source.

## Why This Matters

It's tempting to treat every suspicious-looking hit as a real incident, but the more useful skill is knowing how to actually rule something out. Here, that meant checking the obvious next questions an attacker's activity would also show up in — did the source move laterally? Did it try to set up persistence? Once both came back clean, I could confidently call it a false positive tied to normal MFA proxy behavior instead of just shrugging and moving on.

It also pointed to a real fix: if this pattern keeps showing up and getting investigated every time, that's wasted analyst time. Worth either tuning the detection rule or adding an exception for known Duo proxy traffic so it doesn't keep popping up.

## Recommendations

1. Create a detection exception/allowlist entry for known proxy NTLM traffic from `PROXY-01` to reduce recurring false positives on this rule.
2. Document the expected authentication pattern for MFA proxy infrastructure so future analysts can triage this pattern faster.
3. Periodically review the Pass-the-Hash rule's false positive rate against other known infrastructure (e.g., other proxies, service accounts) to catch similar noise sources proactively.

---

*Queries were run in Wazuh's Threat Hunting interface using DQL (Dashboards Query Language) with the time range set to the last 24 hours.*
