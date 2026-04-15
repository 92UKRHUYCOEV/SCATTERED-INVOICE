## Flag-by-Flag Walkthrough

---

### Q00 — Workspace Name
**Flag:** `law-cyber-range`

This came straight from the Sentinel UI. The workspace for all the hunt exercises on the Log(N) Pacific CyberRange.

---

### Q01 — Compromised Account
**Flag:** `m.smith@lognpacific.org`

I started by filtering SigninLogs for activity related to the reported user, Mark Smith. His UPN showed up immediately.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-25T23:00:00Z))
| where UserPrincipalName has "smith"
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType
```

<img width="924" height="246" alt="image" src="https://github.com/user-attachments/assets/de938a27-926e-4a45-836c-d45895164b7c" />

---

### Q02 — Attacker Source IP
**Flag:** `205.147.16.190`

Filtering Mark's sign-in activity, I spotted an unfamiliar IP appearing at 21:54 with MFA failures followed by a successful authentication. This IP did not match any of Mark's normal sign-in patterns.

```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-25T23:00:00Z))
| project TimeGenerated, IPAddress, ResultType, Location
| sort by TimeGenerated asc
```

<img width="922" height="282" alt="image" src="https://github.com/user-attachments/assets/00b60500-74b0-47dd-a66d-f1ac61b375b3" />

---

### Q03 — Attack Origin Country
**Flag:** `NL`

The Location field on the attacker's sign-in entries showed the Netherlands. A Dutch IP authenticating to a UK organisation's mailbox during an MFA fatigue attack is a strong indicator of compromise.

---

### Q04 — MFA Denial Error Code
**Flag:** `50074`

This is the Azure AD error code for "Strong authentication required." It means the user's credentials were correct but MFA was not completed. The attacker had Mark's password but was being blocked by MFA, which is exactly what you would expect before an MFA fatigue attack.

---

### Q05 — MFA Fatigue Intensity
**Flag:** `3`

I counted 3 failed MFA attempts (ResultType 50074 and 50140) from the attacker's IP before the first successful sign-in. MFA fatigue works by spamming the user with push notifications until they get frustrated and just approve one. Three attempts is not a lot, which could mean Mark approved quickly or the attacker got lucky.

---

### Q06 — Application Accessed
**Flag:** `One Outlook Web`

The first successful authentication from the attacker's IP was to One Outlook Web. This is the AppDisplayName value from SigninLogs. The attacker went straight for the mailbox, which makes sense for a BEC attack where the goal is to intercept invoice communications.

---

### Q07 — Attacker OS
**Flag:** `Linux`

I pulled this from the DeviceDetail.operatingSystem field in SigninLogs. The attacker was using a Linux machine, which is consistent with Scattered Spider's known tooling. Most corporate users at a law firm would be on Windows or macOS, so a Linux sign-in is another red flag.

---

### Q08 — Attacker Browser
**Flag:** `Firefox 147.0`

From DeviceDetail.browser on the attacker's sessions. Combined with Linux, this paints a picture of the attacker's setup.

---

### Q09 — First Post-Auth Action
**Flag:** `MailItemsAccessed`

Moving to CloudAppEvents, I filtered for the attacker's IP after the successful sign-in and sorted by time. The first action was MailItemsAccessed, meaning the attacker immediately started reading Mark's emails. This is the reconnaissance phase of the BEC, where they look for ongoing invoice threads to hijack.

```kql
CloudAppEvents
| where IPAddress == "205.147.16.190"
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-25T23:00:00Z))
| project TimeGenerated, ActionType, Application
| sort by TimeGenerated asc
```

---

### Q10 — Rule Creation Method
**Flag:** `New-InboxRule`

The attacker created inbox rules at 22:02 and 22:03. The ActionType in CloudAppEvents was New-InboxRule. Inbox rules are a favourite persistence and evasion technique for BEC attackers because they can silently redirect or delete emails without the victim noticing.

---

### Q11 — Forward Rule Name
**Flag:** `.`

The first rule was named with just a single dot. This is nearly invisible in the inbox rules list. Most people scrolling through their rules would not even notice it. Very deliberate.

---

### Q12 — Forward Destination
**Flag:** `insights@duck.com`

I found this in the ForwardTo parameter within the RawEventData JSON on the inbox rule creation event. The attacker was forwarding copies of emails to a DuckDuckGo email alias, which provides privacy and makes the recipient harder to trace.

---

### Q13 — Forward Keywords
**Flag:** `invoice, payment, wire, transfer`

The SubjectOrBodyContainsWords parameter in the rule's RawEventData showed exactly what the attacker was after. The rule only forwarded emails containing these financial keywords. This confirms the intent was invoice fraud from the start.

```kql
CloudAppEvents
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| extend RawData = parse_json(RawEventData)
| project TimeGenerated, ActionType, RawData
```

<img width="914" height="188" alt="image" src="https://github.com/user-attachments/assets/ee131f66-9a7e-42bb-b7b6-d7d590f4c4cb" />

---

### Q14 — Rule Processing Flag
**Flag:** `StopProcessingRules`

This parameter was set on the attacker's forwarding rule. What it does is tell Exchange to stop evaluating any other inbox rules after this one fires. So if the victim had their own rules that might have caught or flagged the forwarded emails, those rules would never run. Another layer of evasion.

<img width="922" height="448" alt="image" src="https://github.com/user-attachments/assets/c5a3873b-2996-4c8c-907d-d85c49c8db14" />

---

### Q15 — Delete Rule Name
**Flag:** `..`

The second rule was named with two dots. If the first rule (single dot) was hard to spot, this one is even sneakier sitting right next to it. This rule was designed to automatically delete security-related notifications.

---

### Q16 — Delete Keywords
**Flag:** `suspicious, security, phishing, unusual, compromised, verify`

These are the keywords the delete rule was targeting. Any email containing these words would be automatically deleted from Mark's inbox. The purpose is obvious: if the security team or Microsoft sends Mark a warning about suspicious activity on his account, he would never see it. The attacker was covering their tracks in real time.

---

### Q17 — BEC Target
**Flag:** `j.reynolds@lognpacific.org`

Moving to EmailEvents, I filtered for emails sent from the attacker's IP during the investigation window. The recipient was j.reynolds, who based on the scenario context works in Finance. The attacker specifically targeted someone with the authority to process wire transfers.

```kql
EmailEvents
| where SenderIPv4 == "205.147.16.190"
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-25T23:00:00Z))
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject
```

<img width="923" height="214" alt="image" src="https://github.com/user-attachments/assets/c43ea386-fe77-4b56-9e22-fc61ac4797ca" />

---

### Q18 — BEC Subject Line
**Flag:** `RE: Invoice #INV-2026-0892 - Updated Banking Details`

The subject line starts with "RE:" which means the attacker was replying to an existing invoice thread. This is a thread hijack. By replying within a legitimate conversation, the email looks completely normal to the recipient. J. Reynolds would see what appears to be Mark following up on a real invoice, not a fraudulent message from an attacker.

---

### Q19 — Email Direction
**Flag:** `Intra-org`

This is a critical finding. The email was classified as internal (intra-org) because it was sent from Mark's compromised account to another internal user. This means any email gateway rules designed to catch external phishing or BEC would not have flagged it. The attacker was operating from inside the trust boundary.

<img width="925" height="265" alt="image" src="https://github.com/user-attachments/assets/5763a5a4-e9f7-403d-b2bc-82af193196dd" />

---

### Q20 — BEC Sender IP
**Flag:** `205.147.16.190`

The SenderIPv4 on the BEC email matched the attacker's sign-in IP exactly. This confirms the fraudulent email was sent from the same session the attacker established through MFA fatigue. One session, one attacker, full chain from initial access to the BEC.

---

### Q21 — Cloud App Accessed
**Flag:** `Microsoft OneDrive for Business`

The attacker did not stop at email. I found FileAccessed events in CloudAppEvents from the attacker's IP. The Application field showed Microsoft OneDrive for Business. The attacker was browsing Mark's files, possibly looking for more financial information, contracts, or other data they could use.

---

### Q22 — SharePoint App Accessed
**Flag:** `Microsoft SharePoint Online`

This one caught me out initially. I tried several values from SigninLogs (Office 365 SharePoint Online, SharePoint Online Web Client Extensibility, OfficeHome) and they were all wrong. The answer was in the Application field in CloudAppEvents, which logs it as "Microsoft SharePoint Online" rather than the SigninLogs AppDisplayName of "Office 365 SharePoint Online." Lesson learned: always check which table the question is pointing to, because the same service can have different display names across tables.

---

### Q23 — Session Correlation
**Flag:** `00225cfa-a0ff-fb46-a079-5d152fcdf72a`

This GUID ties the entire investigation together. I found it by parsing the RawEventData on the inbox rule creation events in CloudAppEvents and extracting AppAccessContext.AADSessionId. I then confirmed it matched the SessionId on the attacker's successful sign-in in SigninLogs. One session ID linking sign-ins, inbox rule creation, email access, and file browsing.

```kql
CloudAppEvents
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| extend RawData = parse_json(RawEventData)
| extend AADSessionId = tostring(RawData.AppAccessContext.AADSessionId)
| project TimeGenerated, ActionType, AADSessionId
```

---

### Q24 — Conditional Access Status
**Flag:** `notApplied`

The IR Lead asked what failed in the defences. The ConditionalAccessStatus on the attacker's successful sign-in was "notApplied," meaning no Conditional Access policies evaluated or blocked the sign-in. A policy requiring managed devices or blocking risky locations (like a Dutch IP signing into a UK org) would have stopped this attack at the door. This is the single biggest defence gap in this incident.

---

### Q25 — MFA Fatigue MITRE ID
**Flag:** `T1621`

This maps to MITRE ATT&CK T1621: Multi-Factor Authentication Request Generation. The technique describes exactly what happened here: the attacker repeatedly triggered MFA push notifications to wear down the user until they approved one.

---

### Q26 — Email Rules MITRE ID
**Flag:** `T1564.008`

This maps to T1564.008: Hide Artifacts — Email Hiding Rules. The attacker created inbox rules specifically to hide evidence of the compromise by forwarding financial emails out and deleting security alerts. This falls under Defence Evasion in the ATT&CK framework.

---

### Q27 — Credential Source
**Flag:** `infostealer`

The IR Lead asked how the attacker already had Mark's password before the MFA fatigue started. Scattered Spider is well known for purchasing credentials harvested by infostealer malware. Tools like Raccoon, RedLine, and Vidar steal saved passwords, session tokens, and browser data from infected machines, and the logs are sold on dark web marketplaces. The attacker likely bought Mark's credentials from one of these sources.

---

### Q28 — Immediate Containment
**Flag:** `revoke sessions`

The IR Lead wanted to know the single most important containment action. The attacker still had a valid session and the inbox rules were still active. Revoking sessions invalidates all active tokens immediately, kicking the attacker out. A password reset alone would not kill existing session tokens, so revoking sessions had to come first.

---

### Q29 — Threat Actor Attribution
**Flag:** `Scattered Spider`

Everything in this investigation points to Scattered Spider. MFA fatigue as the initial access method, purchasing credentials from infostealer logs, inbox rule manipulation for persistence and evasion, BEC targeting finance, and the use of anonymising infrastructure. This is the same group that targeted MGM Resorts and Caesars Entertainment using very similar TTPs.

---

