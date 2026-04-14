# 🛡️ BEC Investigation – MFA Fatigue Attack (Scattered Spider)

![SOC Analysis](https://img.shields.io/badge/SOC-Analysis-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-TTPs-red)
![KQL](https://img.shields.io/badge/KQL-Queries-green)

<p align="leftr">
  <img src="attack-diagram.png" width="70%">
</p>
### Figure 1 – BEC Attack Kill Chain
MFA fatigue → Inbox rule persistence → Internal fraud → Data access

---

## 📌 Overview

This project demonstrates a full-scale SOC investigation of a Business Email Compromise (BEC) attack leveraging MFA fatigue and inbox rule persistence.
The analysis was performed using Microsoft Sentinel log sources, including SigninLogs, CloudAppEvents, and EmailEvents, to trace attacker behavior from initial access to impact.

---

## 🏆 Key Wins

* Identified MFA fatigue attack pattern from authentication logs
* Correlated attacker activity across multiple telemetry sources
* Detected persistence via malicious inbox rules
* Confirmed BEC execution targeting internal finance user
* Traced attacker activity to OneDrive and SharePoint access

---


The attack leveraged MFA fatigue, inbox rule persistence, and internal email fraud to target financial operations.

---

## 🔍 Key Findings

- Compromised User: m.smith@lognpacific.org
- Attacker IP: 205.147.16.190
- Technique: MFA Fatigue (T1621)
- Persistence: Inbox Rules (T1564.008)
- Impact: Fraudulent email sent internally
- Data Access: OneDrive & SharePoint

---

## ⚔️ Attack Flow

1. MFA fatigue prompts sent to user
2. User approved authentication
3. Attacker accessed Outlook Web
4. Inbox rules created (forward + delete)
5. Fraud email sent to finance
6. Files accessed via OneDrive

---

## 🧠 MITRE ATT&CK Mapping

| Stage | Technique |
|------|----------|
| Initial Access | T1621 |
| Persistence | T1564.008 |
| Credential Use | T1078 |
| Collection | T1114 |

---

## 🚨 Detection & Response

- SigninLogs → MFA fatigue detection  
- CloudAppEvents → Inbox rule creation  
- EmailEvents → Fraud confirmation  

---

## 🔐 Containment Actions

- Revoke active sessions  
- Reset credentials  
- Remove inbox rules  
- Block attacker IP  

---

## 📂 Project Structure

- `/queries` → KQL queries used during investigation  
- `/docs` → Final incident reports and documentation (placeholder)
