## Answer-by-Answer Walkthrough

---

### Q00 — Workspace Name
**Answer:** `law-cyber-range`

This was provided from the Sentinel UI workspace.

---

### Q01 — Compromised Account
**Answer:** `m.smith@lognpacific.org`

The investigation began by querying SigninLogs for activity associated with the reported user, Mark Smith. His User Principal Name (UPN) was immediately identified in the results.

---

### Q02 — Attacker Source IP
**Answer:** `205.147.16.190`

Review of the user’s sign-in activity identified an unfamiliar IP address at 21:54, which generated multiple MFA failures prior to a successful authentication. This activity was inconsistent with the user’s normal sign-in behavior.

---

### Q03 — Attack Origin Country
**Answer:** `NL`

Analysis of the Location field for the sign-in events identified the Netherlands as the source of authentication. A foreign IP address accessing a UK-based mailbox in conjunction with MFA fatigue activity represents a strong indicator of compromise.
---

### Q04 — MFA Denial Error Code
**Answer:** `50074`

This Azure AD error code indicates that strong authentication is required, confirming that valid credentials were used but MFA was not completed. This suggests the attacker had obtained the user’s password but was initially blocked by MFA, consistent with behavior observed prior to an MFA fatigue attack.

---

### Q05 — MFA Fatigue Intensity
**Answer:** `3`

Review of authentication events identified three failed MFA attempts (ResultType 50074 and 50140) originating from the attacker’s IP address prior to a successful sign-in. MFA fatigue attacks commonly involve repeated authentication prompts to induce user approval; the limited number of attempts observed may indicate rapid user approval or successful compromise with minimal interaction.
---

### Q06 — Application Accessed
**Answer:** `One Outlook Web`

The first successful authentication from the attacker’s IP address was to Outlook Web (AppDisplayName in SigninLogs). This indicates the attacker accessed the mailbox immediately after compromise, consistent with BEC activity aimed at intercepting invoice-related communications.

---

### Q07 — Attacker OS
**Answer:** `Linux`

Review of the DeviceDetail.operatingSystem field in SigninLogs indicated that the authentication originated from a Linux-based system. This is inconsistent with the organization’s standard endpoint profile, which primarily consists of Windows and macOS devices. The use of a Linux system in this context represents a significant anomaly and aligns with known adversary tooling, including activity attributed to Scattered Spider.

---

### Q08 — Attacker Browser
**Answer:** `Firefox 147.0`

Review of the DeviceDetail.browser field in the attacker’s sessions provides further insight into the client environment. When combined with the identified Linux operating system, this information helps profile the attacker’s setup.

---

### Q09 — First Post-Auth Action
**Answer:** `MailItemsAccessed`

Review of CloudAppEvents, filtered for the attacker’s IP address following successful authentication and sorted by time, identified MailItemsAccessed as the first recorded action. This indicates immediate access to the user’s mailbox. This behavior is characteristic of the reconnaissance phase in BEC attacks, during which adversaries examine email communications to identify and exploit ongoing financial or invoice-related exchanges.

---

### Q10 — Rule Creation Method
**Answer:** `New-InboxRule`

Analysis of CloudAppEvents identified inbox rule creation events at 22:02 and 22:03, with ActionType New-InboxRule. Inbox rules are a common persistence and defense evasion technique in BEC attacks, enabling attackers to silently redirect or delete emails without the user’s awareness.

---

### Q11 — Forward Rule Name
**Answer:** `.`

Analysis revealed that the first inbox rule was assigned a single-character name (“.”), significantly reducing its visibility within the rules interface. This technique is commonly used to evade detection during routine user inspection.

---

### Q12 — Forward Destination
**Answer:** `insights@duck.com`

Analysis of the RawEventData JSON for the inbox rule creation event identified the ForwardTo parameter configured with a DuckDuckGo email alias. The use of this privacy-focused service helps obscure the ultimate recipient, making attribution and tracking more difficult.

---

### Q13 — Forward Keywords
**Answer:** `invoice, payment, wire, transfer`

Analysis of the SubjectOrBodyContainsWords parameter within the rule’s RawEventData identified financial keywords used to selectively forward emails. This targeted filtering confirms the attacker’s intent to intercept invoice-related communications, consistent with BEC fraud activity.

---

### Q14 — Rule Processing Flag
**Answer:** `StopProcessingRules`

This parameter was configured within the attacker’s forwarding rule to stop the evaluation of subsequent inbox rules once triggered. This prevents any legitimate user-defined rules from executing, effectively bypassing potential detection mechanisms and adding an additional layer of defense evasion.

---

### Q15 — Delete Rule Name
**Answer:** `..`

Analysis identified a second inbox rule named using two dots (“..”), significantly reducing its visibility within the rules interface, especially in proximity to the first rule. The rule was configured to automatically delete security-related notifications, reflecting a deliberate defense evasion strategy.

---

### Q16 — Delete Keywords
**Answer:** `suspicious, security, phishing, unusual, compromised, verify`

Review of the rule configuration identified keywords used to selectively delete emails from the user’s inbox. Any messages containing these terms, including potential security alerts, would be automatically removed. This indicates a deliberate attempt to suppress detection mechanisms and conceal malicious activity in real time.

---

### Q17 — BEC Target
**Answer:** `j.reynolds@lognpacific.org`

Analysis of EmailEvents, filtered for emails sent from the attacker’s IP address during the investigation window, identified j.reynolds as the recipient. Based on the scenario context, this user is part of the Finance team, indicating the attacker deliberately targeted an individual with authority to process financial transactions, consistent with BEC activity.

---

### Q18 — BEC Subject Line
**Answer:** `RE: Invoice #INV-2026-0892 - Updated Banking Details`

Analysis of the subject line, which begins with “RE:”, indicates that the attacker replied within an existing email thread. This technique, known as thread hijacking, leverages legitimate conversation context to enhance credibility, causing the message to appear as a genuine continuation rather than a malicious communication.

---

### Q19 — Email Direction
**Answer:** `Intra-org`

This represents a critical finding. The email was classified as intra-organizational (intra-org), as it was sent from a compromised internal account to another internal user. As a result, email gateway controls designed to detect external phishing or BEC activity were not triggered, allowing the attacker to operate within the organization’s trust boundary.

---

### Q20 — BEC Sender IP
**Answer:** `205.147.16.190`

Analysis confirmed that the SenderIPv4 address on the BEC email matched the attacker’s sign-in IP address. This verifies that the fraudulent email was sent from the same session established via MFA fatigue, demonstrating a complete attack chain from initial access through BEC execution.

---

### Q21 — Cloud App Accessed
**Answer:** `Microsoft OneDrive for Business`

Analysis of CloudAppEvents identified FileAccessed events originating from the attacker’s IP address, with the Application field indicating Microsoft OneDrive for Business. This confirms the attacker accessed the user’s cloud-stored files, suggesting an effort to identify additional financial information, contracts, or other sensitive data for further exploitation.

---

### Q22 — SharePoint App Accessed
**Answer:** `Microsoft SharePoint Online`

This finding highlights the importance of referencing the correct telemetry source during analysis. Initial attempts using values from SigninLogs (e.g., "Office 365 SharePoint Online," "SharePoint Online Web Client Extensibility," and "OfficeHome") did not produce the expected result. The correct value was identified in the Application field of CloudAppEvents, where the service is recorded as "Microsoft SharePoint Online." This illustrates how service naming can vary across log sources and reinforces the need to validate the appropriate table when conducting investigations.

---

### Q23 — Session Correlation
**Answer:** `00225cfa-a0ff-fb46-a079-5d152fcdf72a`

This GUID serves as a key correlation artifact for the investigation. It was extracted from the RawEventData of inbox rule creation events in CloudAppEvents via AppAccessContext.AADSessionId and matched to the SessionId from the attacker’s successful sign-in in SigninLogs. This linkage ties authentication, inbox rule creation, email access, and file activity to a single attacker session.

---

### Q24 — Conditional Access Status
**Answer:** `notApplied`

Analysis of the attacker’s successful sign-in revealed a ConditionalAccessStatus of “notApplied,” indicating that no Conditional Access policies were evaluated or enforced. This represents a critical defensive gap. The implementation of policies requiring managed devices or restricting access from anomalous locations—such as a foreign IP authenticating to a UK-based organization—could have prevented the attack at the initial access stage.

---

### Q25 — MFA Fatigue MITRE ID
**Answer:** `T1621`

This activity aligns with MITRE ATT&CK technique T1621: Multi-Factor Authentication Request Generation. The repeated MFA push notifications observed are consistent with MFA fatigue tactics, intended to prompt user approval through persistent requests.

---

### Q26 — Email Rules MITRE ID
**Answer:** `T1564.008`

This activity aligns with MITRE ATT&CK technique T1564.008: Hide Artifacts — Email Hiding Rules. The attacker created inbox rules to forward financial communications externally and delete security-related notifications, effectively concealing evidence of compromise. This behavior falls under the Defense Evasion tactic within the ATT&CK framework.

---

### Q27 — Credential Source
**Answer:** `infostealer`

The presence of valid credentials prior to the MFA fatigue activity indicates that the attacker had already obtained the user’s password. Scattered Spider is known to leverage credentials harvested by infostealer malware, such as Raccoon, RedLine, and Vidar, which collect stored passwords, session tokens, and browser data from compromised systems. These data sets are frequently sold on underground marketplaces, making it likely the credentials were acquired through this method.

---

### Q28 — Immediate Containment
**Answer:** `revoke sessions`

The most critical containment action was the immediate revocation of all active user sessions. The attacker maintained a valid session and persistence through malicious inbox rules, enabling continued access. Session revocation invalidates all active authentication tokens, effectively removing the attacker’s access. A password reset alone would not terminate existing sessions, making session revocation the priority containment step.

---

### Q29 — Threat Actor Attribution
**Answer:** `Scattered Spider`

The observed activity aligns with tactics, techniques, and procedures commonly attributed to the Scattered Spider threat group. This includes MFA fatigue as the initial access method, the use of credentials likely sourced from infostealer malware, inbox rule manipulation for persistence and defense evasion, targeted BEC activity against finance personnel, and the use of anonymizing infrastructure. These patterns are consistent with publicly reported Scattered Spider campaigns, including those involving MGM Resorts and Caesars Entertainment.

---

