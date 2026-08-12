# 🚨 Cloud Identity Threat Detection - BEC Investigation
MFA Bypass & Behavioral Correlation (Scattered Spider–Inspired)

![SOC Analysis](https://img.shields.io/badge/SOC-Analysis-blue)
![Detection Engineering](https://img.shields.io/badge/Detection-Engineering-purple)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-TTPs-red)
![KQL](https://img.shields.io/badge/KQL-Queries-green)
![Microsoft Sentinel](https://img.shields.io/badge/Sentinel-SIEM-orange)
![Identity Security](https://img.shields.io/badge/Identity-Security-yellow)

---

## BEC Attack Kill Chain
<p align="left">
  <img src="./SCATTERED-INVOICEREADME_DIAGRAM_FINAL.png" alt="BEC Attack Kill Chain" width="70%">
</p>

---

## 📢Executive Summary

This threat hunt investigated a Business Email Compromise (BEC) incident involving the abuse of a finance employee’s account to facilitate a fraudulent wire transfer attempt valued at GBP 24,500. Authentication telemetry confirmed that the attacker gained access to m.smith@lognpacific.org through MFA fatigue: after multiple push notifications were denied, one request was approved, establishing an authenticated session from an anomalous external IP address using a Linux/Firefox client.
Following authentication, the attacker accessed the victim’s mailbox and created malicious inbox rules. These rules forwarded financially relevant messages to an external address and deleted emails that could expose the compromise, including security notifications. This activity supported persistence, defense evasion, and intelligence gathering ahead of the fraudulent payment attempt.
Correlation across SigninLogs, CloudAppEvents, and EmailEvents connected the suspicious sign-in, inbox-rule creation, and transmission of a fraudulent internal email through a shared Azure AD session identifier. The evidence established a high-confidence attack sequence involving account compromise, mailbox manipulation, thread hijacking, and attempted payment fraud. Access to additional Microsoft cloud resources also indicated that the potential impact extended beyond email.
Key indicators included the attacker’s IP address, external forwarding destination, anomalous Linux/Firefox client profile, and shared session identifier. Recommended containment actions include revoking active sessions, resetting the compromised credentials, removing malicious inbox rules, reviewing cloud and mailbox activity, and validating whether sensitive information was accessed or transferred. The hunt also identified detection opportunities for MFA fatigue, suspicious inbox-rule creation, external forwarding, anomalous cloud access, and session-based correlation across multiple stages of identity-driven attacks.

---

## 🚨 Incident Overview

A suspected Business Email Compromise (BEC) triggered this threat hunt after fraudulent banking details were used in an attempted GBP 24,500 wire transfer. The bank stopped the transaction before completion, preventing financial loss. Because the payment instructions appeared to originate from Mark Smith, a finance employee, the incident indicated that a trusted internal account may have been compromised.
Mark reported receiving repeated multi-factor authentication (MFA) prompts the previous evening and eventually approving one to stop the notifications. The following morning, his team discovered unauthorized inbox rules in his Microsoft 365 account. These events raised concerns that an attacker had gained authenticated access, manipulated the mailbox, and used trusted internal communications to target finance operations.
The investigation used SigninLogs, CloudAppEvents, and EmailEvents in Microsoft Sentinel to reconstruct activity across identity, email, and Microsoft cloud services. The hunt sought to determine:
	• How the attacker gained access
	• What actions occurred after authentication
	• Whether mailbox persistence or defense-evasion mechanisms were established
	• Whether fraudulent communications were sent
	• Whether other Microsoft cloud resources were accessed
	• Which indicators, control gaps, and detection opportunities could support containment and future response
Analysis focused on MFA fatigue, anomalous sign-in characteristics, mailbox-rule manipulation, thread hijacking, and access to Outlook, OneDrive, and SharePoint. Findings were also evaluated for MITRE ATT&CK mapping and the development of high-confidence Microsoft Sentinel detections.

---

## 🔧 Environment and Data Sources

The investigation was conducted in Microsoft Sentinel using the LAW-Cyber-Range workspace. The investigation window covered 25 February 2026, 21:00 UTC through 26 February 2026, 00:00 UTC, encompassing the reported MFA prompts, unauthorized account access, inbox-rule creation, and fraudulent email activity.
Three primary data sources were used:
Data source	Investigative purpose
SigninLogs	Examined authentication attempts, MFA outcomes, source IP addresses, geographic anomalies, client characteristics, application access, conditional access results, and session identifiers.
CloudAppEvents	Identified post-authentication activity, including mailbox access, inbox-rule creation, forwarding parameters, cloud-resource access, and session-correlation artifacts contained in RawEventData.
EmailEvents	Validated fraudulent email activity by examining sender and recipient details, subject context, email direction, delivery information, and associated IP addresses.
Correlation across these sources connected the attacker’s authentication activity with subsequent mailbox manipulation and fraudulent email transmission, enabling reconstruction of the BEC attack sequence.

---

## 🤖 Hunt Methodology 

The hunt used a structured, hypothesis-driven methodology to validate the reported Business Email Compromise (BEC), reconstruct the attack path, and assess the scope of malicious activity.
The initial hypothesis was that a legitimate Microsoft 365 account had been compromised through MFA fatigue (push bombing), allowing an attacker to establish an authenticated session and use the account for mailbox manipulation and financial fraud.
The investigation proceeded through four phases:
Phase	Investigative objective
1. Validate initial access	Review SigninLogs to identify the compromised account, MFA sequence, suspicious source IP address, anomalous location, client profile, accessed applications, and session identifiers.
2. Analyze post-authentication activity	Review CloudAppEvents chronologically to determine the attacker’s actions following authentication and identify access to Microsoft 365 resources.
3. Identify persistence and evasion	Examine mailbox activity and RawEventData for unauthorized inbox rules, external forwarding, targeted keywords, and message-deletion behavior.
4. Confirm BEC execution	Use EmailEvents to identify fraudulent communications and correlate them with the suspicious authentication and cloud activity.
Cross-table correlation was central to the methodology. IP addresses, timestamps, application context, client characteristics, and Azure AD session identifiers were used to connect related events into a single evidentiary chain. This reduced reliance on isolated events and increased confidence that the observed activities originated from the same compromised session.
The resulting findings were evaluated for indicator extraction, MITRE ATT&CK mapping, detection engineering, and automated response opportunities.





## 🎯 Key Outcomes

- Identified MFA fatigue attack leading to account compromise
- Correlated attacker activity across identity, email, and cloud telemetry
- Detected malicious inbox rules used for persistence and evasion
- Confirmed fraudulent internal email targeting finance operations
- Identified post-compromise data access in Microsoft OneDrive

---

## 🎨 Indicators of Compromise (IOCs)

The investigation identified multiple indicators of compromise across authentication, mailbox activity, and post-authentication cloud access. These artifacts provide high-confidence evidence of unauthorized access and can be used to support detection engineering, incident scoping, threat correlation, and containment activities. In this case, the IOCs are especially valuable because they connect the initial MFA fatigue compromise to the persistence mechanisms, fraudulent email activity, and broader cloud resource access observed during the investigation.

- **Network Indicators**
The primary attacker infrastructure identified during the hunt was the source IP address `205.147.16.190`. This address was associated with the suspicious successful sign-in to the compromised account and was later correlated with fraudulent email activity, making it one of the strongest network-level indicators in the case. Its geolocation to the `Netherlands (NL)` further reinforced the anomaly when compared with the expected context of the legitimate user's activity.

- **Identity and Session Indicators**
The compromised account was `m.smith@lognpacific.org`, which served as the central identity abused throughout the incident. Once access was obtained, activity across authentication logs, cloud application telemetry, and email records was linked through the Azure AD session identifier `00225cfa-a0ff-fb46-a079-5d152fcdf72a`. This session ID was a critical correlation artifact because it connected the successful sign-in, inbox rule creation, mailbox access, and related cloud activity to the same authenticated attacker session.

- **Device and User-Agent Indicators**
The malicious session was associated with an anomalous device profile that differed from the user's expected corporate baseline. The attacker activity was logged from Linux using `Firefox 147.0 \ Linux`, a combination that stood out against the normal Windows-based enterprise device context. These attributes are valuable supporting indicators because they add device and browser-level anomalies to the IP and identity evidence already established.

- **Mailbox Persistence Indicators**
The attacker created two malicious inbox rules to maintain visibility into sensitive communications and suppress signs of compromise. The first rule, named ".", `was configured to forward finance-related messages externally`, while the second rule, named "..", `was designed to delete security-related notifications`. These rule names are themselves indicators of suspicious activity because they were intentionally minimal and visually inconspicuous.
A particularly important mailbox IOC was the forwarding destination `insights@duck.com`, which represented attacker-controlled infrastructure used to receive selected email content from the compromised mailbox. Additional configuration artifacts included the use of the `StopProcessingRules` parameter, which ensured that once the malicious forwarding rule was triggered, subsequent inbox rules would not execute.

- **Keyword-Based Rule Indicators**
The rule logic also exposed content-based indicators that reflected attacker intent. The forwarding rule targeted finance-related keywords associated with invoice and payment discussions, confirming that the objective was selective interception of business-relevant communications. The deletion rule targeted the keywords `suspicious`, `security`, `phishing`, `unusual`, `compromised`, `verify`, indicating deliberate suppression of warning messages, security notifications, and other emails likely to alert the user or defenders.

- **Email Fraud Indicators**
The compromised session was used to send a fraudulent internal email as part of the BEC workflow. The message was classified as `Intra-org`, showing that the attacker operated within the trusted internal email environment rather than relying on external spoofing infrastructure. The sender IP observed in the email telemetry matched `205.147.16.190`, directly linking the malicious sign-in session to the attempted fraud.

- **Cloud Access Indicators**
Beyond mailbox abuse, the attacker also accessed `Microsoft Cloud Services` associated with `OneDrive` and `SharePoint`. These application access artifacts are important because they indicate that the incident extended beyond email compromise alone and introduced the possibility of `document access`, `internal reconnaissance`, or`broader data exposure`. As a result, the IOC set for this case should not be limited to email artifacts, but should also include the cloud applications touched during the malicious session.

- **Operational Value of the IOC Set**
Taken together, these indicators form a coherent and actionable IOC set that can support both immediate response and long-term detection improvement. The IP address, compromised user identity, session ID, forwarding destination, suspicious rule names, rule keywords, browser profile, and cloud applications accessed all contribute to a high-confidence picture of attacker behavior. These artifacts can be used to search for related activity elsewhere in the environment, tune Microsoft Sentinel detections, enrich case documentation, and guide containment actions such as session revocation, inbox rule removal, and retrospective review of similar mailbox activity across other accounts.


| IOC Type | Value | Context |
|---|---|---|
| IP Address | `205.147.16.190` | Attacker source IP (Netherlands) |
| Email Address | `insights@duck.com` | Inbox rule forwarding destination |
| Email Address | `j.reynolds@lognpacific.org` | BEC Target email address|
| Session ID | `00225cfa-a0ff-fb46-a079-5d152fcdf72a` | Attacker session GUID across all activity |
| User Agent | `Firefox 147.0 / Linux` | Attacker browser and OS |
| Email Subject | `RE: Invoice #INV-2026-0892 - Updated Banking Details` | BEC email subject line |
| Inbox Rule | `.` (single dot) | Forward rule name |
| Inbox Rule | `..` (double dot) | Delete rule name |

---
  
## 🕑 Attack Timeline

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

- **KQL Queries**  
  [`queries.md`](./queries/queries.md)  
  Used during the investigation to identify attacker behavior, later refined into production detection rules.

- **Detection Engineering**  
  [`sentinel-analytics.md`](./detection-rules/sentinel-analytics.md)  
  Primary detection rules developed for Microsoft Sentinel analytics.

- **Automation / SOAR**  
  [`playbooks.md`](./automation/playbooks.md)  
  SOAR playbooks designed to automate security operations and enable faster, more consistent incident response.

---

## 📊 Detection Flow

1. **User Authentication**  
   Successful login using valid credentials  

2. **Authentication Control Failure**  
   MFA expected but not enforced  

3. **Identity Manipulation**  
   MFA method reset or modification detected  

4. **Post-Authentication Expansion**  
   Access to multiple applications and IP addresses  

5. **Anomalous Activity**  
   Geographic inconsistency (impossible travel)  

6. **Detection Trigger**  
   Risk score threshold exceeded (Score ≥ 6)  

7. **Automated Response**  
   SOAR playbook executed (account containment and session revocation)

## 📊 Detection Flow Diagram

<p align="left">
<img width="700" height="250" alt="detection-flow-mfa-bypass_crop2" src="https://github.com/user-attachments/assets/b0b293d7-7c66-4eae-994c-6a3b4d41b3c5" />
</p>

## 🗝️ Solution Summary

| # | Question | Answer |
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

## 🧠 MITRE ATT&CK Mapping

| Attack Phase         | Technique                             | ID        | Activity Observed                                                                 | Detection Gap                                                                     |
| -------------------- | ------------------------------------- | --------- | --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Initial Access       | Valid Accounts: Cloud Accounts        | T1078.004 | Compromised credentials were used to successfully authenticate to the environment | No detection for anomalous sign-ins based on location, device, or risk signals    |
| Initial Access       | MFA Request Generation                | T1621     | Multiple MFA push notifications were sent prior to user approval                  | No detection for repeated MFA denials followed by a successful authentication     |
| Persistence          | Email Forwarding Rule                 | T1114.003 | Malicious inbox rule created to forward invoice-related emails externally         | No alerting on inbox rules configured with external forwarding destinations       |
| Defense Evasion      | Email Hiding Rules                    | T1564.008 | Rule naming with . and .. to reduce visibility and avoid casual detection         | Hide Artifacts: Email Hiding Rules that suppress or delete security or alert-related emails   |
| Collection           | Email Collection: Remote Email Access | T1114.002 | Mailbox accessed remotely from attacker-controlled IP during active session       | No alerting on mailbox access from unfamiliar or anomalous IP addresses           |
| Lateral Movement     | Internal Spearphishing                | T1534     | Fraudulent email sent internally to finance personnel from compromised account    | Internal email traffic bypassed traditional email security controls               |
| Collection           | Data from Cloud Storage               | T1530     | Files accessed from OneDrive and SharePoint following account compromise          | No detection for suspicious file access tied to anomalous session activity        |
| Resource Development | Obtain Credentials: Purchase          | T1589.001 | Credentials likely sourced from external infostealer marketplace                  | Limited visibility into credential exposure; no monitoring for leaked credentials |

These findings highlight multiple gaps across identity, email, and cloud telemetry, emphasizing the need for improved detection coverage and correlation across attack stages.


---

## ⚓ Detection Engineering Opportunities

The findings from this hunt highlight several opportunities to improve detection coverage for identity-driven Business Email Compromise (BEC) activity in Microsoft Sentinel. The attack succeeded not because of a single control failure, but because multiple low-signal events - repeated MFA prompts, anomalous authentication context, mailbox rule creation, internal email abuse, and cloud resource access - were able to occur in sequence without being correlated into a high-confidence alert. The strongest detection opportunities therefore lie in behavioral correlation, where multiple weak indicators are combined into a more actionable signal.

### 1. MFA Fatigue Correlation Detection
A priority detection opportunity is the identification of repeated MFA denials followed by a successful sign-in from the same IP address or session context. On their own, failed MFA events can generate noise, but when clustered within a short time window and followed by success, they become a strong indicator of MFA fatigue. This is particularly valuable when paired with contextual enrichments such as anomalous geolocation, unusual application access, or unfamiliar device characteristics.

A production detection should correlate:
- multiple MFA-related failures within a short period,
- a subsequent successful authentication,
- the same user account,
- and matching or closely related attacker infrastructure.
  
This logic would directly target the initial access pattern observed in this case and provide defenders with earlier visibility before the attacker can establish persistence.
### 2. Anomalous Successful Sign-In Detection
A second high-value opportunity is detection of successful sign-ins that deviate from the user's normal access profile. In this incident, the attacker used an external IP address, foreign geolocation, Linux operating system, and Firefox browser profile, all of which differed from the user's expected enterprise baseline. A stronger analytic would identify successful authentications where multiple anomaly features occur together rather than alerting on a single deviation in isolation.

This type of detection is especially effective when based on a scoring or threshold model, for example:
- unfamiliar IP address,
- unusual country,
- non-standard operating system,
- unusual browser,
- and web-based access to cloud services outside the user's norm.

The goal is to reduce false positives by emphasizing stacked anomalies, not isolated ones.
### 3. Inbox Rule Creation and Persistence Detection
The creation of malicious inbox rules represents one of the clearest and most actionable signals in this hunt. A dedicated analytic should alert on all new inbox rule creation events, then elevate severity when the rule includes suspicious characteristics such as:
- forwarding to an external address,
- deletion behavior,
- finance-related keyword filters,
- security-related keyword filters,
- or suppression settings such as StopProcessingRules.

Because inbox rule abuse is a common persistence and defense evasion mechanism in BEC cases, these events should be treated as high-priority when they occur shortly after an anomalous authentication event. Detection quality improves further when the rule name itself is suspicious, such as single-character or visually inconspicuous naming conventions like "." or "..".

### 4. External Forwarding Detection
A dedicated rule for external mailbox forwarding would provide additional value, especially in financial and executive user populations. Not all forwarding activity is malicious, but forwarding to an untrusted domain immediately after suspicious sign-in activity should be treated as a strong escalation point. Detection logic should extract forwarding destinations from rule configuration data and compare them against trusted organizational domains or approved allowlists.

This analytic becomes particularly useful when paired with:
- recent identity anomalies,
- first-time forwarding behavior for the user,
- or forwarding rules filtered around finance and payment terminology.

### 5. Internal BEC / Thread Hijacking Detection
The fraudulent message in this incident was classified as intra-organizational, meaning the attacker operated within the trusted internal email environment. This creates a blind spot for traditional email controls that are tuned primarily for external phishing or spoofing. Detection opportunities therefore exist for identifying internal emails sent from compromised accounts under suspicious conditions, especially when the sender IP, device profile, or sign-in context differs from the user's baseline.

High-value detection logic could include:
- internal emails sent shortly after risky or anomalous sign-in activity,
- unusual sender IP correlation,
- finance-related subject matter,
- reply or thread-hijack behavior,
- and messages sent from accounts with recent inbox rule creation activity.

This is one of the most important opportunities in the hunt because it directly addresses the fraud execution stage rather than only the compromise stage.

## 6. Multi-Stage Session Correlation
The strongest engineering opportunity is the creation of a multi-stage correlation analytic that links identity abuse, mailbox manipulation, and fraud activity within a single session or short timeframe. In this case, the most convincing evidence emerged only when SigninLogs, CloudAppEvents, and EmailEvents were considered together. 

A high-confidence rule should therefore correlate:
-  repeated MFA denials,
-  successful sign-in,
-  mailbox access,
-  new inbox rule creation,
-  and internal or suspicious email activity.

Where available, shared artifacts such as session ID, source IP, user account, and timestamp sequence should be used to bind events together. This kind of analytic is far more resilient than any single-indicator rule and is better aligned to the actual attack path used by modern cloud-focused adversaries.

### 7. Cloud Resource Access Expansion Detection
Because the attacker also accessed OneDrive and SharePoint, there is a clear opportunity to detect post-authentication expansion into cloud-hosted data sources following suspicious sign-in behavior. Successful mailbox compromise often serves as the first stage of broader data access, and detections should account for that progression. Monitoring should focus on cloud application access immediately following risky authentication events, especially when the user has not previously shown similar patterns of access.

This type of analytic helps move the organization from narrow BEC detection into broader cloud compromise scoping, which is important for measuring exposure and determining whether sensitive files were reviewed or collected.

### 8. Risk-Based Detection Prioritization
A practical improvement would be to combine these behaviors into a risk-based analytic model rather than treating them as separate alerts of equal importance. For example:
- MFA fatigue pattern = moderate risk
- anomalous successful sign-in = moderate risk
- malicious inbox rule creation = high risk
- external forwarding = high risk
- intra-org fraud email = critical risk

Stacking these detections into a cumulative score can help analysts distinguish benign anomalies from coordinated attack activity. This reduces alert fatigue while increasing the chance that meaningful BEC patterns are escalated quickly.

### 9. Detection Tuning Considerations
To make these detections operationally effective, tuning is important. False positives can be reduced by:
- excluding approved administrative forwarding scenarios,
- allowlisting trusted internal or sanctioned service accounts where appropriate,
- establishing per-user or per-role baselines for geography and browser use,
- and prioritizing detections for high-risk populations such as finance, payroll, executives, and privileged cloud users.

This matters because identity-based BEC attacks often blend normal and abnormal behavior. High-fidelity detection depends less on raw event volume and more on carefully tuned context.

### 10. Defensive Value

The overall detection engineering lesson from this hunt is that no single event was sufficiently conclusive on its own, but the sequence was highly suspicious when correlated. That makes this case a strong example of why Sentinel detections should be engineered around attack progression, not isolated telemetry. By linking authentication abuse, mailbox persistence, internal fraud behavior, and cloud application access into a single analytical framework, defenders can detect this style of compromise earlier and respond before financial loss or broader data exposure occurs.
  
---

Automation & Response

SOAR playbooks were developed to:

- Revoke user sessions
- Remove malicious inbox rules
- Purge fraudulent emails
- Notify SOC and affected users
- Augment incidents with correlated telemetry to improve contextual analysis.

---

Project Structure

- /queries  KQL queries used during investigation
- /detection-rules  Microsoft Sentinel analytics rules
- sentinel-analytics.md  Primary detection reference SOAR playbooks and response workflows

---

Skills Demonstrated

- Security Incident Investigation (SOC)
- Microsoft Sentinel & KQL
- Threat Detection Engineering
- MITRE ATT&CK Mapping
- Identity-Based Attack Analysis
- SOAR Automation (Logic Apps)

---

Key Insight

This investigation highlights how modern attackers:

- Exploit user behavior (MFA fatigue)
- Establish persistence through inbox rules
- Operate entirely within trusted cloud services
- Execute fraud without malware

Effective detection requires correlating identity, email, and cloud activity, not relying on a single data source.

