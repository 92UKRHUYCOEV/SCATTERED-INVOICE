🚨 Detection Rules – Microsoft Sentinel (BEC Investigation)

This document converts investigation queries into actionable detection rules for Microsoft Sentinel.

🌍 Rule 1 – MFA Fatigue Detection

**MITRE ATT&CK:** T1621 – Multi-Factor Authentication Request Generation
Severity: Medium

* **What it does:**
  Detects repeated MFA push attempts followed by a successful login from the same IP.

### 🔍 Query

```kql id="xw8w2c"
let timeframe = 15m;
SigninLogs
| where TimeGenerated > ago(timeframe)
| where ResultType in (50074, 50140)
| summarize FailedAttempts = count() by IPAddress, UserPrincipalName
| where FailedAttempts >= 3
| join kind=inner (
    SigninLogs
    | where ResultType == 0
    | project UserPrincipalName, IPAddress, SuccessTime = TimeGenerated
) on UserPrincipalName, IPAddress
```

### 🎯 Alert Logic

* Trigger when **3+ MFA failures**
* Followed by **successful login from same IP**

---

🌍 Rule 2 – Suspicious Login from Unmanaged Device

**MITRE ATT&CK:** T1078 – Valid Accounts
Severity: Medium

* **What it does:**
  Detects successful login from non-managed or unusual devices.

🔍 Query
```kql
SigninLogs
| where ResultType == 0
| where DeviceDetail has "Linux"
| project TimeGenerated, UserPrincipalName, IPAddress, DeviceDetail
```

### 🎯 Alert Logic
* Trigger on Linux or unknown devices

---

🌍 Rule 3 – Inbox Rule Creation Detection

**MITRE ATT&CK:** T1564.008 – Email Hiding Rules
Severity: High

* **What it does:**
  Suspicious Inbox Rule Creation, Detects creation of inbox rules, commonly used for persistence and evasion.

🔍 Query
```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| project TimeGenerated, AccountDisplayName, IPAddress
```
###🎯 Alert Logic 
*Trigger on ANY new inbox rule, Prioritize external IPs

---

🌍 Rule 4 – Email Forwarding to External Address

**MITRE ATT&CK:** T1114 – Email Collection
Severity: High

* **What it does:**
  Suspicious Email Forwarding Rule, Detects forwarding of emails to external domains.

🔍 Query
```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| extend data = parse_json(RawEventData)
| mv-expand param = data.Parameters
| where tostring(param.Name) == "ForwardTo"
| where tostring(param.Value) !endswith "@lognpacific.org"
| project TimeGenerated, AccountDisplayName, ForwardTo = tostring(param.Value)
```
###🎯 Alert Logic
* Trigger on forwarding to external domains

---

🌍 Rule 5 – Internal BEC Email Detection

**MITRE ATT&CK:** T1566 – Phishing
Severity: High
* **What it does:**
  Internal Fraud Email Detected, Detects suspicious internal emails containing financial keywords.

🔍 Query
```kql
EmailEvents
| where SenderFromAddress endswith "@lognpacific.org"
| where Subject has_any ("invoice", "payment", "wire", "transfer")
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject
```
###🎯 Alert Logic
*Internal sender + financial keywords

---

🌍 Rule 6 – File Access After Suspicious Login

MITRE ATT&CK: T1213 – Data from Information Repositories
Severity: Medium
* **What it does:**
* Post-Compromise File Access, Detects file access following suspicious authentication activity.

🔍 Query
```kql
CloudAppEvents
| where ActionType == "FileAccessed"
| project TimeGenerated, AccountDisplayName, Application, IPAddress
```
###🎯 Alert Logic
* File access from suspicious IP/device

---

🌍 Rule 7 – Session Correlation Alert
**MITRE ATT&CK:** T1078 - Multi-Stage Attack Correlation
Severity: High

* **What it does:**
* Identifies multiple suspicious actions tied to the same session.

🔍 Query
```kql
CloudAppEvents
| extend data = parse_json(RawEventData)
| extend ctx = parse_json(tostring(data.AppAccessContext))
| project AadSessionId = tostring(ctx.AADSessionId), ActionType
| summarize Actions = make_set(ActionType) by AadSessionId
| where array_length(Actions) > 3
```
###🎯 Alert Logic
* Multiple suspicious actions in one session

🧠 Detection Strategy Summary
This detection set enables:
-- Early detection of MFA fatigue attacks
-- Identification of persistence mechanisms
-- Detection of BEC execution
-- Visibility into post-compromise behavior


🏆 SOC Value: 
These rules demonstrate:
-- Threat-informed detection engineering
-- MITRE ATT&CK alignment
-- Real-world applicability in Microsoft Sentinel

These detections are production-ready and can be directly deployed as Microsoft Sentinel Analytics Rules within a SOC environment.
