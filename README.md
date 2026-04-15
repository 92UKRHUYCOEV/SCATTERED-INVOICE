# 🛡️ BEC Investigation – MFA Fatigue Attack (Scattered Spider)

![SOC Analysis](https://img.shields.io/badge/SOC-Analysis-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-TTPs-red)
![KQL](https://img.shields.io/badge/KQL-Queries-green)

---

## 🚨 Overview

This project documents a full-scale Security Operations Center (SOC) investigation into a Business Email Compromise (BEC) attack.

The attacker leveraged:

- MFA fatigue (push bombing)
- Inbox rule persistence
- Internal email spoofing (thread hijacking)
- Cloud data access (OneDrive / SharePoint)

The investigation was conducted using:

- Microsoft Sentinel (KQL)
- SigninLogs, CloudAppEvents, EmailEvents
- MITRE ATT&CK framework for threat mapping

---

## 🎯 Key Outcomes
- Identified MFA fatigue attack leading to account compromise
- Correlated attacker activity across identity, email, and cloud telemetry
- Detected malicious inbox rules used for persistence and evasion
- Confirmed fraudulent internal email targeting finance operations
- Identified post-compromise data access in Microsoft OneDrive

---

## Indicators of Compromise

| IOC Type | Value | Context |
|---|---|---|
| IP Address | `205.147.16.190` | Attacker source IP (Netherlands) |
| Email Address | `insights@duck.com` | Inbox rule forwarding destination |
| Email Address | `jwilson.vhr@proton.me` | *(not observed in this hunt, included from threat intel on Scattered Spider)* |
| Session ID | `00225cfa-a0ff-fb46-a079-5d152fcdf72a` | Attacker session GUID across all activity |
| User Agent | `Firefox 147.0 / Linux` | Attacker browser and OS |
| Email Subject | `RE: Invoice #INV-2026-0892 - Updated Banking Details` | BEC email subject line |
| Inbox Rule | `.` (single dot) | Forward rule name |
| Inbox Rule | `..` (double dot) | Delete rule name |

---
  
## Attack Flow (Kill Chain)
<p align="leftr">
  <img src="attack-diagram.png" width="70%">
</p>
### Figure 1 – BEC Attack Kill Chain

---

## Attack Timeline

| Time (UTC) | Event |
|---|---|
| 21:54:24 | First MFA fatigue attempt (ResultType 50074) |
| 21:54:55 | Second MFA denial (ResultType 50140) |
| 21:55:15 | Third MFA denial (ResultType 50140) |
| 21:59:52 | MFA approved, attacker signs in to One Outlook Web |
| ~22:00 | MailItemsAccessed, attacker reads Mark's emails |
| 22:02 | Forward rule (`.`) created, sends invoice emails to insights@duck.com |
| 22:03 | Delete rule (`..`) created, auto-deletes security alerts |
| ~22:09 | Attacker accesses SharePoint and OneDrive files |
| ~22:24 | BEC email sent to j.reynolds with fraudulent invoice |

---

## 🔎 Detection & Analysis

### Key Artifacts

- **KQL Queries & Detection Rules (Primary)**  
  Investigation queries were used to identify attacker behavior and later refined into production detection rules.  
  - `queries` (coming soon)  
  - [`sentinel-analytics.md`](./detection-rules/sentinel-analytics.md) – Primary detection rules  

 - **Automation / SOAR**  
  See [playbooks.md](./automation/playbooks.md) for response playbooks  

---

## Flag Summary

| # | Question | Flag |
|---|----------|------|
| Q00 | Workspace name | `law-cyber-range` |
| Q01 | Compromised account | `m.smith@lognpacific.org` |
| Q02 | Attacker source IP | `205.147.16.190` |
| Q03 | Attack origin country | `NL` |
| Q04 | MFA denial error code | `50074` |
| Q05 | MFA fatigue intensity | `3` |
| Q06 | Application accessed | `One Outlook Web` |
| Q07 | Attacker OS | `Linux` |
| Q08 | Attacker browser | `Firefox 147.0` |
| Q09 | First post-auth action | `MailItemsAccessed` |
| Q10 | Rule creation method | `New-InboxRule` |
| Q11 | Forward rule name | `.` |
| Q12 | Forward destination | `insights@duck.com` |
| Q13 | Forward keywords | `invoice, payment, wire, transfer` |
| Q14 | Rule processing flag | `StopProcessingRules` |
| Q15 | Delete rule name | `..` |
| Q16 | Delete keywords | `suspicious, security, phishing, unusual, compromised, verify` |
| Q17 | BEC target | `j.reynolds@lognpacific.org` |
| Q18 | BEC subject line | `RE: Invoice #INV-2026-0892 - Updated Banking Details` |
| Q19 | Email direction | `Intra-org` |
| Q20 | BEC sender IP | `205.147.16.190` |
| Q21 | Cloud app accessed | `Microsoft OneDrive for Business` |
| Q22 | SharePoint app accessed | `Microsoft SharePoint Online` |
| Q23 | Session correlation | `00225cfa-a0ff-fb46-a079-5d152fcdf72a` |
| Q24 | Conditional Access status | `notApplied` |
| Q25 | MFA fatigue MITRE ID | `T1621` |
| Q26 | Email rules MITRE ID | `T1564.008` |
| Q27 | Credential source | `infostealer` |
| Q28 | Immediate containment | `revoke sessions` |
| Q29 | Threat actor attribution | `Scattered Spider` |

---

🚨 Detection Capabilities

This project includes:

- MFA fatigue detection (T1621)
- Inbox rule persistence detection (T1564.008)
- Email exfiltration monitoring (T1114)
- BEC fraud detection (T1566)
- Post-compromise data access detection (T1213)
- Session-based attack correlation (T1078)

All detections are:

- Production-ready
- MITRE ATT&CK aligned
- Designed for Microsoft Sentinel
  
---

⚙️ Automation & Response

SOAR playbooks were developed to:

- Revoke user sessions
- Remove malicious inbox rules
- Purge fraudulent emails
- Notify SOC and affected users
- Enrich incidents with correlated activity
-- See: /automation/playbooks.md

---

📁 Project Structure

- /queries
-- KQL queries used during investigation
- /detection-rules
-- Microsoft Sentinel analytics rules
- sentinel-analytics.md – Primary detection reference
-- /automation
- SOAR playbooks and response workflows
-- /docs  Final incident report and documentation

---

## MITRE ATT&CK Mapping

| Attack Phase | Technique | ID | What Happened | Detection Gap |
|---|---|---|---|---|
| Initial Access | Valid Accounts: Cloud Accounts | T1078.004 | Attacker used Mark's stolen credentials to authenticate | No alerting on sign-ins from anomalous locations or devices |
| Initial Access | MFA Request Generation | T1621 | 3 MFA push spam attempts before user approved | No detection for repeated MFA denials followed by approval |
| Persistence | Email Forwarding Rule | T1114.003 | Forward rule (`.`) sending invoice-related emails to external address | No alerting on new inbox rules with external forwarding |
| Defence Evasion | Email Hiding Rules | T1564.008 | Delete rule (`..`) removing security alert emails automatically | No alerting on rules that delete emails matching security keywords |
| Collection | Email Collection: Remote Email Collection | T1114.002 | MailItemsAccessed events from attacker IP across the session | No alerting on mailbox access from new/unusual IPs |
| Lateral Movement | Internal Spearphishing | T1534 | BEC email sent internally from compromised account to Finance | Intra-org email bypassed external gateway controls entirely |
| Collection | Data from Cloud Storage | T1530 | Attacker accessed OneDrive and SharePoint files | No alerting on file access from suspicious session context |
| Resource Development | Obtain Credentials: Purchase | T1589.001 | Credentials likely purchased from infostealer marketplace | Outside org's detection scope, but password hygiene and monitoring for leaked creds could help |

---

🏆 Skills Demonstrated

- Security Incident Investigation (SOC)
- Microsoft Sentinel & KQL
- Threat Detection Engineering
- MITRE ATT&CK Mapping
- Identity-Based Attack Analysis
- SOAR Automation (Logic Apps)

---

🧠 Key Insight

This investigation highlights how modern attackers:

- Exploit user behavior (MFA fatigue)
- Establish persistence through inbox rules
- Operate entirely within trusted cloud services
- Execute fraud without malware

Effective detection requires correlating identity, email, and cloud activity, not relying on a single data source.






- `/queries` → KQL queries used during investigation  
- `/docs` → Final incident reports and documentation (placeholder)
