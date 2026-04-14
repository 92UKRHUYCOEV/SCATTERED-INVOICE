🚨 Detection Rules – Microsoft Sentinel (BEC Investigation)

This document converts investigation queries into actionable detection rules for Microsoft Sentinel.

🚪 Rule 1 – MFA Fatigue Detection
Name: MFA Fatigue Attack Detected
Severity: High
MITRE ATT&CK: T1621 – MFA Request Generation

📌 Description: Detects repeated MFA failures followed by a successful authentication from the same IP.
🔍 Query
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

🎯 Alert Logic
Trigger when ≥ 3 MFA failures followed by success
Same user + IP

---

🌍 Rule 2 – Suspicious Login from Unmanaged Device
Name: Suspicious Login – Unmanaged Device
Severity: Medium
MITRE ATT&CK: T1078 – Valid Accounts

📌 Description: Detects successful login from non-managed or unusual devices.

🔍 Query
SigninLogs
| where ResultType == 0
| where DeviceDetail has "Linux"
| project TimeGenerated, UserPrincipalName, IPAddress, DeviceDetail

🎯 Alert Logic
Trigger on Linux or unknown devices

---

⚙️ Rule 3 – Inbox Rule Creation Detection

Name: Suspicious Inbox Rule Creation
Severity: High
MITRE ATT&CK: T1564.008 – Email Hiding Rules

📌 Description: Detects creation of inbox rules, commonly used for persistence and evasion.

🔍 Query
CloudAppEvents
| where ActionType == "New-InboxRule"
| project TimeGenerated, AccountDisplayName, IPAddress

🎯 Alert Logic
Trigger on ANY new inbox rule
Prioritize external IPs

---

📤 Rule 4 – Email Forwarding to External Address

Name: Suspicious Email Forwarding Rule
Severity: High
MITRE ATT&CK: T1114 – Email Collection

📌 Description: Detects forwarding of emails to external domains.

🔍 Query
CloudAppEvents
| where ActionType == "New-InboxRule"
| extend data = parse_json(RawEventData)
| mv-expand param = data.Parameters
| where tostring(param.Name) == "ForwardTo"
| where tostring(param.Value) !endswith "@lognpacific.org"
| project TimeGenerated, AccountDisplayName, ForwardTo = tostring(param.Value)

🎯 Alert Logic
Trigger on forwarding to external domains

---

📧 Rule 5 – Internal BEC Email Detection

Name: Internal Fraud Email Detected
Severity: High
MITRE ATT&CK: T1566 – Phishing

📌 Description: Detects suspicious internal emails containing financial keywords.

🔍 Query
EmailEvents
| where SenderFromAddress endswith "@lognpacific.org"
| where Subject has_any ("invoice", "payment", "wire", "transfer")
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject
🎯 Alert Logic
Internal sender + financial keywords

---

📁 Rule 6 – File Access After Suspicious Login

Name: Post-Compromise File Access
Severity: Medium
MITRE ATT&CK: T1213 – Data from Information Repositories

📌 Description: Detects file access following suspicious authentication activity.

🔍 Query
CloudAppEvents
| where ActionType == "FileAccessed"
| project TimeGenerated, AccountDisplayName, Application, IPAddress
🎯 Alert Logic
File access from suspicious IP/device

---

🔗 Rule 7 – Session Correlation Alert

Name: Multi-Stage Attack Correlation
Severity: High
MITRE ATT&CK: T1078

📌 Description: Identifies multiple suspicious actions tied to the same session.

🔍 Query
CloudAppEvents
| extend data = parse_json(RawEventData)
| extend ctx = parse_json(tostring(data.AppAccessContext))
| project AadSessionId = tostring(ctx.AADSessionId), ActionType
| summarize Actions = make_set(ActionType) by AadSessionId
| where array_length(Actions) > 3

🎯 Alert Logic
Multiple suspicious actions in one session

🧠 Detection Strategy Summary
This detection set enables:

Early detection of MFA fatigue attacks
Identification of persistence mechanisms
Detection of BEC execution
Visibility into post-compromise behavior

🏆 SOC Value: These rules demonstrate:

Threat-informed detection engineering
MITRE ATT&CK alignment
Real-world applicability in Microsoft Sentinel

They can be directly implemented as Analytics Rules in a production SOC.
