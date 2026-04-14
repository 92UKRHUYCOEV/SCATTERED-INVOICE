# 🚨 Microsoft Sentinel Detection Rules – BEC Investigation

This document defines **production-ready analytics rules** derived from the investigation of a Business Email Compromise (BEC) attack involving MFA fatigue, inbox rule persistence, and post-compromise activity.

These detections are designed for **operational deployment within a SOC**, enabling automated alerting, investigation, and response.

---

## 🚪 Rule 1 – MFA Fatigue Attack Detection

**Severity:** High
**MITRE ATT&CK:** T1621 – Multi-Factor Authentication Request Generation

### 📌 Description

Detects repeated MFA challenges followed by a successful authentication from the same IP address, indicative of MFA fatigue (push bombing).

### 🔍 Detection Query

```kql
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

### 🎯 Detection Logic

* ≥ 3 MFA failures within 15 minutes
* Followed by successful authentication
* Same user and IP address

### 🛠️ Operational Considerations

* Tune threshold to reduce false positives
* Consider excluding known trusted IP ranges

---

## 🌍 Rule 2 – Suspicious Login from Unmanaged Device

**Severity:** Medium
**MITRE ATT&CK:** T1078 – Valid Accounts

### 📌 Description

Identifies successful authentication from unmanaged or unusual devices (e.g., Linux systems in enterprise environments).

### 🔍 Detection Query

```kql
SigninLogs
| where ResultType == 0
| where DeviceDetail has "Linux"
| project TimeGenerated, UserPrincipalName, IPAddress, DeviceDetail
```

### 🎯 Detection Logic

* Successful login
* Device not aligned with corporate baseline

### 🛠️ Operational Considerations

* Validate against known admin or developer systems
* Combine with geo/location anomalies for stronger signal

---

## ⚙️ Rule 3 – Inbox Rule Persistence Detection

**Severity:** High
**MITRE ATT&CK:** T1564.008 – Email Hiding Rules

### 📌 Description

Detects creation of inbox rules commonly used for persistence and evasion in BEC attacks.

### 🔍 Detection Query

```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| project TimeGenerated, AccountDisplayName, IPAddress
```

### 🎯 Detection Logic

* Trigger on all new inbox rule creation events
* Prioritize external or anomalous IPs

### 🛠️ Operational Considerations

* Baseline normal rule creation activity
* Alert enrichment should include rule parameters

---

## 📤 Rule 4 – External Email Forwarding Detection

**Severity:** High
**MITRE ATT&CK:** T1114 – Email Collection

### 📌 Description

Detects forwarding of emails to external domains, commonly used for data exfiltration.

### 🔍 Detection Query

```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| extend data = parse_json(RawEventData)
| mv-expand param = data.Parameters
| where tostring(param.Name) == "ForwardTo"
| where tostring(param.Value) !endswith "@lognpacific.org"
| project TimeGenerated, AccountDisplayName, ForwardTo = tostring(param.Value)
```

### 🎯 Detection Logic

* Inbox rule with external forwarding destination

### 🛠️ Operational Considerations

* Maintain allowlist for approved forwarding domains
* Combine with user risk signals for prioritization

---

## 📧 Rule 5 – Internal BEC Email Detection

**Severity:** High
**MITRE ATT&CK:** T1566 – Phishing

### 📌 Description

Identifies potentially fraudulent internal emails containing financial or payment-related keywords.

### 🔍 Detection Query

```kql
EmailEvents
| where SenderFromAddress endswith "@lognpacific.org"
| where Subject has_any ("invoice", "payment", "wire", "transfer")
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject
```

### 🎯 Detection Logic

* Internal sender
* Financial keywords in subject

### 🛠️ Operational Considerations

* Tune keyword list to reduce noise
* Correlate with recent login anomalies

---

## 📁 Rule 6 – Post-Compromise File Access Detection

**Severity:** Medium
**MITRE ATT&CK:** T1213 – Data from Information Repositories

### 📌 Description

Detects file access activity that may indicate data exposure following account compromise.

### 🔍 Detection Query

```kql
CloudAppEvents
| where ActionType == "FileAccessed"
| project TimeGenerated, AccountDisplayName, Application, IPAddress
```

### 🎯 Detection Logic

* File access activity post-authentication

### 🛠️ Operational Considerations

* Correlate with suspicious login events
* Prioritize sensitive file access

---

## 🔗 Rule 7 – Multi-Stage Attack Correlation

**Severity:** High
**MITRE ATT&CK:** T1078 – Valid Accounts

### 📌 Description

Identifies multiple suspicious actions occurring within the same session, indicating a coordinated attack sequence.

### 🔍 Detection Query

```kql
CloudAppEvents
| extend data = parse_json(RawEventData)
| extend ctx = parse_json(tostring(data.AppAccessContext))
| project AadSessionId = tostring(ctx.AADSessionId), ActionType
| summarize Actions = make_set(ActionType) by AadSessionId
| where array_length(Actions) > 3
```

### 🎯 Detection Logic

* Multiple suspicious actions within a single session

### 🛠️ Operational Considerations

* Use for high-confidence alerting
* Ideal for incident enrichment

---

# 🧠 Detection Strategy Overview

These analytics rules collectively provide:

* Early detection of identity-based attacks
* Visibility into persistence mechanisms
* Detection of BEC execution
* Monitoring of post-compromise activity

Microsoft Sentinel analytics rules operate as **scheduled KQL queries that generate alerts when conditions are met**, enabling automated incident creation and investigation workflows. ([OneUptime][1])

---

# 🏆 SOC Implementation Value

These detections are production-ready and can be directly deployed as Microsoft Sentinel Analytics Rules within a SOC environment, supporting:

* Threat-informed detection engineering
* Reduced time to detect (MTTD)
* Integration with automation playbooks for rapid response

---

# 🔥 Analyst Insight

This detection set reflects modern attacker behavior, where identity compromise, persistence, and data access occur within a single session.

Combining identity, email, and cloud telemetry is critical for detecting and responding to these attack patterns effectively.

[1]: https://oneuptime.com/blog/post/2026-02-16-how-to-create-microsoft-sentinel-analytics-rules-to-detect-suspicious-sign-in-patterns/view?utm_source=chatgpt.com "Create Microsoft Sentinel Analytics Rules to Detect ..."
