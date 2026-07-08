# Threat Hunting Scenario: Credential Access Alert on a Domain Controller
**Author:** Madelynn Charron  
**Date:** June 2026  
**Tools used:** Wazuh (OpenSearch Dashboards / DQL)


## Overview

While proactively threat hunting for unauthorized credential access activity, I identified a pattern on `DC-01`. a domain controller, matching the MITRE ATT&CK Credential Access tactic — specifically resembling a Pass-the-Hash pattern. This write-up walks through the investigation from initial discovery to root cause, using Wazuh's Threat Hunting query interface (DQL) to query Windows Security Event Log data and authentication activity ingested into Wazuh via agent.

| Field | Value |
|-------|-------|
| Date of Alert | June 16, 2026 |
| Alert Rule ID | 60204 — Multiple Windows Logon Failures |
| MITRE Tactic | Credential Access |
| Affected Agent | DC-01 (Domain Controller) |
| Source IP | 10.10.0.10 (PROXY-01) |
| Severity | Low — False Positive |
| Outcome | Closed. Exclusion rule recommended. |


---

_Screenshots have been redacted to remove internal hostnames and IP addresses in accordance with data handling practices. Internal hostnames and IP addresses have also been altered to protect confidentialy._

## Investigation Walkthrough

### Step 1 — Initial Discovery
```
rule.mitre.tactic: "Credential Access"
```
Queried for activity mapped to the Credential Access tactic to identify leads worth investigating further, and scoped the time window to the last 24 hours for the rest of the hunt.
<img width="1901" height="80" alt="image" src="https://github.com/user-attachments/assets/d4bcecc4-f81a-48e9-ab22-4adcfeed12e5" />
"Credential Access" covers techniques used to steal account credentials such as passwords and hashes. Starting with a broad MITRE tactic query is a good first step when triaging unknown activity because it surfaces activity that Wazuh has already mapped to known attack patterns, making them higher priority to investigate.

#### What Was Found
- Rule ID: 60204 — Multiple Windows Logon Failures
- Agent: DC-01 (a Domain Controller)
- The document showed no username in the standard fields due to being a summary alert, which prompted further investigation


### Step 2 — Find the underlying failed logon events
```
agent.name: "DC-01" and data.win.system.eventID: 4625
```
Pulls the raw failed-logon events (Event ID 4625) that triggered the detection rule, rather than relying on the alert summary alone.
<img width="2335" height="139" alt="image" src="https://github.com/user-attachments/assets/f56e8ce5-fad8-4941-85db-eabb0005d1e4" />
Rule 60204 is a composite/aggregation rule, meaning Wazuh fired it as a summary after detecting multiple individual failed logon events. To find the raw underlying events, I queried for Windows Event ID 4625 (Failed Logon) directly on `DC-01`. Windows Event ID 4625 is the standard Windows Security log event for a failed logon attempt. By filtering to `DC-01` specifically, I narrowed the scope to just the Domain Controller that triggered the alert. Domain Controllers are high-value targets because they manage authentication for the entire organization, so failed logon events on a DC warrant close attention.

#### What Was Found
- 4 failed logon attempts throughout the day: 5:22, 6:39, 8:10, and 16:05
- All 4 originated from the same source IP: `10.10.0.10`
- Logon Type 3 (Network) — meaning the attempts came over the network, not from a local console or RDP session

The spread-out timing of the attempts (not clustered together) is consistent with slow/low brute force or password spraying behavior, where an attacker deliberately paces attempts to avoid lockout thresholds.


### Step 3 — Check for successful logons from the same source IP
```
agent.name: "DC-01" and data.win.system.eventID: 4624 and data.win.eventdata.ipAddress: 10.10.0.10
```
Determines whether the source IP eventually succeeded in authenticating — an important distinction between "someone is guessing passwords" and "known authentication traffic that looks noisy."
<img width="2446" height="712" alt="image" src="https://github.com/user-attachments/assets/cffdbfdb-a09c-4139-b5e9-efaadc9497fa" />
The most critical question after finding failed logons is whether any succeeded. Windows Event ID 4624 is a successful logon event. If an attacker was failing to log in and then suddenly succeeded, that would represent a critical finding. Combining the agent filter, the event ID, and the source IP ensures we are looking at successful logons specifically from the suspicious IP, not all logons on the DC.

#### What Was Found
- 102 successful logon events from `10.10.0.10`
- Rule descriptions read: "Successful Remote Logon Detected — NTLM authentication, possible pass-the-hash attack"
- Multiple employee account usernames were listed across the events
- A service account (Service_ADISync) also appeared
- All descriptions referenced `PROXY-01` and suggested verifying if it is allowed to perform RDP connections

Pass-the-Hash (PtH) is an attack technique where a threat actor steals a user's NTLM password hash from memory and uses it to authenticate without knowing the actual plaintext password. Wazuh flagged this pattern because NTLM authentication from a single IP across many accounts matches the PtH signature.


### Step 4a — Check for lateral movement
```
data.win.eventdata.ipAddress: 10.10.0.10 and not agent.name: "DC-01"
```
Searches for the same source IP authenticating against *other* hosts in the environment. No hits — no evidence of lateral movement.
<img width="2481" height="140" alt="image" src="https://github.com/user-attachments/assets/27ed7c3d-4125-4cf1-bd61-8d7e2bc4841e" />
To determine if `10.10.0.10` had touched any other systems beyond `DC-01`, I broadened the search across all agents

### Step 4b — Check for persistence or post-exploitation activity
```
data.win.system.eventID: (7045 or 4698 or 4702) and data.win.eventdata.ipAddress: 10.10.0.10
```
I also specifically checked for high-risk post-exploitation event IDs that would indicate an attacker installing persistence or scheduled tasks. No hits.

| Event ID | Meaning | Why It Matters |
|----------|---------|-----------------|
| 7045 | New service installed | Attackers install services to maintain persistence |
| 4698 | Scheduled task created | Common technique to run malicious code repeatedly |
| 4702 | Scheduled task updated | Modification of existing tasks to add malicious actions |

If this were a real Pass-the-Hash attack, the attacker would likely attempt to move laterally to other systems using the stolen credentials. Excluding `DC-01` from the first query reveals activity on other machines. The second query targets specific event IDs that are strong indicators of post-exploitation activity.

#### What Was Found
- 3 events on agent `FS-01` (a file server)
- Event IDs were 4624 (1 successful logon) and 5140 (2 network share access events)
- The logon showed the account `PROXY-01$` — the machine account (computer accounts end in $) for `PROXY-01`
- All 3 events occurred at 4:29, clustered together suggesting a single automated task
- No 7045, 4698, or 4702 events — no services or scheduled tasks were created

### Step 5 — Identify what the source actually is
```
agent.name: "PROXY-01"
```
The repeated references to `PROXY-01` in the alert descriptions, combined with the `PROXY-01$` machine account appearing in the `FS-01` events, pointed to a known system. I confirmed this with the IT team in standup, who verified the IP belongs to the organization's MFA Authentication Proxy — cross-checking the log data against a human source rather than relying on the hostname alone.

#### What Was Found
- No Wazuh agent exists for `PROXY-01` — it is not enrolled in Wazuh monitoring
- `PROXY-01` is the organization's MFA Authentication Proxy server
- The MFA proxy authenticates users via NTLM/LDAP against Active Directory as a normal part of its operation
- Every user who logs in through MFA will generate a logon event on the DC originating from the MFA proxy's IP
- This explains the 102 successful logons across multiple accounts — it represents normal user authentication through MFA, not an attacker

---

## Root Cause

The NTLM authentication pattern is expected behavior for a MFA proxy, not an attacker — confirmed with the IT team, who verified the source IP belongs to the organization's MFA Authentication Proxy. MFA proxies relay authentication requests to the domain controller in a way that structurally resembles NTLM relay/PtH traffic to a signature-based rule, without actually being malicious.

No evidence of lateral movement, privilege escalation, or post-exploitation activity was found anywhere in the environment tied to this source.

---

## Why This Matters

It's tempting to treat every suspicious-looking hit as a real incident, but the more useful skill is knowing how to actually rule something out. Here, that meant checking the obvious next questions an attacker's activity would also show up in — did the source move laterally? Did it try to set up persistence? Once both came back clean, I could confidently call it a false positive tied to normal MFA proxy behavior instead of just shrugging and moving on.

It also pointed to a real fix: if this pattern keeps showing up and getting investigated every time, that's wasted analyst time. Worth either tuning the detection rule or adding an exception for known MFA proxy traffic so it doesn't keep popping up.

---

### Conclusion & Overall Assessment

| Finding | Assessment |
|---------|------------|
| 4 failed logons (4625) on `DC-01` | Likely MFA proxy retry or timeout behavior |
| 102 successful logons (4624) from `10.10.0.10` | Normal MFA proxy authenticating users against AD |
| Multiple employee accounts in logon events | Expected — MFA processes all user authentications |
| Service_ADISync account appearing | Expected — AD sync service authenticates through MFA |
| NTLM flagged as possible Pass-the-Hash | False positive — NTLM is MFA proxy's authentication method |
| `PROXY-01$` accessing `FS-01` (5140) | Routine machine account activity (GP, sync, or scheduled task) |
| No 7045 / 4698 / 4702 events | No persistence mechanisms installed — no post-exploitation |
| No Domain Admin accounts involved | Low risk even if activity were suspicious |

**Overall verdict:** This is a false positive generated by Wazuh's Pass-the-Hash detection rule misidentifying normal MFA proxy NTLM traffic. No malicious activity was found.

---

## Recommendations

1. Create a detection exception/allowlist entry for known proxy NTLM traffic from `PROXY-01` to reduce recurring false positives on this rule.
2. Document the expected authentication pattern for MFA proxy infrastructure so future analysts can triage this pattern faster.
3. Periodically review the Pass-the-Hash rule's false positive rate against other known infrastructure (e.g., other proxies, service accounts) to catch similar noise sources proactively.

---

## Appendix: All Queries Used

| Step | Query | Purpose |
|------|-------|---------|
| 1 | `rule.mitre.tactic: "Credential Access"` | Find the initial discovery |
| 2 | `agent.name: "DC-01" and data.win.system.eventID: 4625` | Find underlying failed logon events |
| 3 | `agent.name: "DC-01" and data.win.system.eventID: 4624 and data.win.eventdata.ipAddress: 10.10.0.10` | Check for successful logons from same IP |
| 4a | `data.win.eventdata.ipAddress: 10.10.0.10 and not agent.name: "DC-01"` | Check for lateral movement to other systems |
| 4b | `data.win.system.eventID: (7045 or 4698 or 4702) and data.win.eventdata.ipAddress: 10.10.0.10` | Check for persistence/post-exploitation |
| 5 | `agent.name: "PROXY-01"` | Check if source machine has a Wazuh agent |

---
