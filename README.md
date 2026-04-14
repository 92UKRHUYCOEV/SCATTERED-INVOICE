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

## Attack Flow (Kill Chain)
<p align="leftr">
  <img src="attack-diagram.png" width="70%">
</p>
### Figure 1 – BEC Attack Kill Chain

---

## 🔎 Detection & Analysis

### Key Artifacts

- **KQL Queries & Detection Rules (Primary)**  
  Investigation queries were used to identify attacker behavior and later refined into production detection rules.  
  - `queries` (coming soon)  
  - [`sentinel-analytics.md`](./detection-rules/sentinel-analytics.md) – Primary detection rules  

- **Automation / SOAR**  
  See [`automation`](./automation.md) for response playbooks  

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
