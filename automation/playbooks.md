⚙️ SOAR Playbooks & Automation – BEC Investigation

This document outlines automated response workflows (SOAR) for detecting and responding to a Business Email Compromise (BEC) attack using Microsoft Sentinel and Logic Apps.

🚨 Playbook 1 – MFA Fatigue Response

Trigger: MFA Fatigue Detection Alert
Severity: High

📌 Objective

Automatically respond to suspected MFA fatigue attacks to prevent account compromise.

🔄 Automated Actions
1. Revoke all active user sessions
2. Force password reset
3. Notify SOC team via Teams/Email
4. Tag user as "High Risk"

🛠️ Implementation (Logic Apps)
- Connector: Azure AD
- Action: Revoke Sign-In Sessions
- Action: Reset Password
- Action: Send notification (Teams/Email)

---

⚙️ Playbook 2 – Inbox Rule Persistence Response

Trigger: Suspicious Inbox Rule Creation
Severity: High

📌 Objective

Remove attacker persistence mechanisms and prevent data exfiltration.

🔄 Automated Actions
1. Enumerate inbox rules
2. Delete suspicious rules
3. Disable auto-forwarding
4. Alert SOC

🛠️ Implementation
- Connector: Office 365
- Action: List inbox rules
- Action: Delete rule
- Action: Send alert

---

📧 Playbook 3 – BEC Email Containment

Trigger: Internal Fraud Email Detection
Severity: High

📌 Objective

Contain fraudulent emails and prevent financial loss.

🔄 Automated Actions
1. Identify affected recipients
2. Remove email from all mailboxes
3. Notify recipients of compromise
4. Escalate to Incident Response
   
🛠️ Implementation
- Connector: Office 365 Security & Compliance
- Action: Search and purge email
- Action: Send notification

---

📁 Playbook 4 – Post-Compromise Data Access Investigation

Trigger: File Access After Suspicious Login
Severity: Medium

📌 Objective

Investigate potential data exfiltration.

🔄 Automated Actions
1. Log accessed files
2. Flag sensitive file access
3. Alert SOC analyst
4. Generate investigation ticket
   
🛠️ Implementation
- Connector: Microsoft Graph
- Action: Retrieve file activity
- Action: Send alert

---

🔗 Playbook 5 – Session Correlation & Incident Enrichment

Trigger: Multi-Stage Attack Correlation
Severity: High

📌 Objective

Enrich incidents with full attack context.

🔄 Automated Actions
1. Correlate activity across logs
2. Attach timeline to incident
3. Tag incident as "BEC Attack"
4. Assign to analyst

🛠️ Implementation
- Connector: Microsoft Sentinel
- Action: Update incident
- Action: Add comments and entities
