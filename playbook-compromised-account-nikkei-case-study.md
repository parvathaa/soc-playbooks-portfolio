# Playbook: Compromised Cloud Email Account (with Nikkei Case Study)

**Scope:** Microsoft 365 / Entra ID and Google Workspace accounts used to send malicious mail, access data, or persist.
**Audience:** SOC analysts (L1 to L2) and incident leads.
**Basis:** Public reporting on the October 2026 Nikkei incident. This is an analysis and playbook built from public sources. It is not a record of a response I performed.
**Sources current as of:** 6 October 2026. Details may change as the investigation continues.

---

## Part 1: Case Study

### What was reported

| Date (2026) | Event | Confidence |
|---|---|---|
| Late July | Unauthorized access to Nikkei's Google Workspace cloud accounts begins | Reported by Nikkei |
| Early August | Nikkei learns of it **after Google notifies the company** | Reported |
| 30 September | Attackers use hijacked Microsoft 365 accounts to send about 9,000 emails with links to malicious sites, to staff and to external contacts who had corresponded with employees | Reported |
| 4 October | Nikkei discloses both incidents and reports them to Japan's Personal Information Protection Commission | Reported |

**Reported impact:** Names, email addresses, and the content of some messages. Nikkei says possible exposure of 1,646 employees and business partners via Google Workspace, and no sign of leaked reader or source information. It says it changed affected passwords, detected no further unauthorized logins, and contacted recipients individually to ask them to delete the emails.

**Not reported (treat as unknown):** the initial access method, whether the two incidents are linked, the attacker identity, and the full scope.

### Why it is a useful case

1. **Trusted-sender abuse.** Mail came from genuine accounts, so sender reputation and "external sender" banners did not help recipients.
2. **Third-party notification as detection.** The Google Workspace access was found because Google told Nikkei. That points to a gap in internal detection.
3. **External blast radius.** Recipients included partners and past correspondents, so response goes beyond the company's own users.
4. **Two platforms, two incidents.** Containment and investigation had to cover both Microsoft 365 and Google Workspace.

### Hypotheses to test (not in the reporting)

*These are what an analyst would investigate. They are not claims about what happened at Nikkei.*

- Credential phishing or an infostealer harvesting passwords and session cookies
- Session or token theft that bypassed MFA
- MFA fatigue or push-bombing
- Reuse of credentials from an earlier breach on accounts without phishing-resistant MFA
- A malicious OAuth app consent granting persistent access

### What would have detected it earlier

| Control | What it catches | ATT&CK |
|---|---|---|
| Alert on sudden spikes in outbound mail volume per user | The 9,000-email burst | T1534 Internal Spearphishing |
| Sign-in risk alerts (new country, anonymous IP, impossible travel, unfamiliar device) | Hijacked logins | T1078.004 Valid Accounts: Cloud Accounts |
| New inbox-rule and forwarding-rule alerts | Attacker persistence and hiding | T1114.003 Email Forwarding Rule |
| New OAuth consent / app grant alerts | Persistent access without a password | T1528 Steal Application Access Token |
| Review of Google Workspace login and token audit logs | Long-running access since July | T1078.004 |
| Phishing-resistant MFA (FIDO2/passkeys) and token-binding policies | Credential and session theft | T1621, T1550.004 |

---

## Part 2: Playbook

### 2.1 Triggers

Start this playbook on any of:
- Alert for risky or anomalous sign-in on a user account
- Spike in outbound email, or outbound email containing URLs flagged malicious
- User or recipient reports a suspicious message from a known colleague
- Third-party notice (cloud provider, partner, law enforcement)
- New inbox rule, forwarding rule, or OAuth consent flagged

### 2.2 Severity guide

| Severity | Criteria | Response target* |
|---|---|---|
| **Critical** | Privileged or executive account, confirmed data access, or malicious mail sent externally | Immediate; incident lead and management notified |
| **High** | Confirmed compromised standard account, no confirmed data loss | Contain within 1 hour |
| **Medium** | Suspicious sign-in, not yet confirmed malicious | Triage within 4 hours |
| **Low** | Likely benign (travel, VPN) with a verified explanation | Close with notes |

*\*Adapt targets to your own SLAs.*

### 2.3 Roles

| Role | Responsibility |
|---|---|
| L1 analyst | Initial triage, evidence collection, escalate with a summary |
| L2 analyst (case owner) | Scoping, containment, root cause, report |
| Incident lead | Declares incident, coordinates comms and decisions |
| IT / identity admin | Executes resets, policy changes |
| Legal / privacy / comms | Notification duties and external messaging |

### 2.4 Phase 1: Triage (first 15 to 30 minutes)

- [ ] Identify the account(s), user role, and privilege level
- [ ] Pull the last 7 days of sign-in logs; list IPs, locations, apps, devices, result codes
- [ ] Check MFA events: unexpected prompts, new methods registered, repeated denials then success
- [ ] Check for new inbox rules, forwarding, delegates, and OAuth grants
- [ ] Check recent outbound mail: volume, recipients, URLs, attachments
- [ ] Contact the user through a **separate trusted channel** (not email from that account) to confirm the activity
- [ ] Decide: true positive, benign, or needs more data. Record the reasoning.

### 2.4.1 Example queries (Microsoft Sentinel / Defender, KQL)

*Adjust table and column names to your environment and licensing.*

**Sign-ins for one user**
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ "user@example.com"
| project TimeGenerated, IPAddress, Location, AppDisplayName,
          ResultType, ConditionalAccessStatus, UserAgent, DeviceDetail
| order by TimeGenerated desc
```

**New or changed inbox rules**
```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| project TimeGenerated, UserId, Operation, ClientIP, Parameters
```

**Outbound mail spikes with URLs**
```kql
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Outbound"
| summarize Sent = count(),
            UniqueRecipients = dcount(RecipientEmailAddress),
            WithUrls = countif(UrlCount > 0)
          by SenderFromAddress, bin(Timestamp, 1h)
| where Sent > 200
| order by Sent desc
```

**OAuth app consent**
```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName in ("Consent to application", "Add OAuth2PermissionGrant")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
```

**Google Workspace:** use the Admin console **Security investigation tool** and **Reporting > Audit logs** (Login, Token, Drive, Gmail log events) for the same checks: unfamiliar logins, new app authorizations, forwarding settings, and mass sharing or downloads.

### 2.5 Phase 2: Containment (do together, in this order)

1. **Revoke all active sessions and refresh tokens** (Entra: revoke sessions; Google: sign user out and reset sign-in cookies). A password reset alone does not end a stolen session.
2. **Reset the password** and require re-registration of MFA. Remove unknown MFA methods.
3. **Block the attacker IPs / sessions** via conditional access where appropriate.
4. **Remove attacker persistence:** malicious inbox and forwarding rules, delegates, unknown OAuth app grants, app passwords.
5. **Stop the spread:** search for and purge the malicious messages from all mailboxes (Defender/Purview content search and purge; Google Workspace email log search and delete). Block the URLs and domains at the proxy and mail gateway.
6. **Preserve evidence** before changes where possible: export sign-in, audit, and mail trace logs; screenshot rules and grants.

### 2.6 Phase 3: Scoping and investigation

- [ ] How long was the account compromised? Find the **first** anomalous sign-in, not just the alert time
- [ ] Which other accounts show the same IPs, user agents, or patterns? Hunt across the tenant
- [ ] What mailbox and file data was accessed? (mailbox audit, Drive/SharePoint activity)
- [ ] Who received malicious mail? Split internal and external; identify who clicked
- [ ] Did any recipient enter credentials or run a download? Treat those accounts and hosts as suspect
- [ ] Is there lateral movement (the attacker emailing from one account to compromise another)?
- [ ] Is there evidence of data access in **other platforms** (like the second platform in the Nikkei case)?

### 2.7 Phase 4: Eradication and recovery

- [ ] Confirm no remaining attacker access: sign-in logs clean for 48 to 72 hours after containment
- [ ] Re-enable the account with phishing-resistant MFA where possible
- [ ] Reset credentials for every account that interacted with the malicious links
- [ ] Re-image or investigate endpoints where payloads were run
- [ ] Review conditional access: block legacy authentication, require compliant devices for sensitive apps

### 2.8 Phase 5: Communication and notification

| Audience | Action |
|---|---|
| Internal staff | Warn about the malicious mail; give a clear "delete and report" instruction |
| External recipients | Contact individually or by notice; advise deleting the mail and not clicking. *(Nikkei contacted recipients individually.)* |
| Leadership | Brief on scope, impact, and decisions needed |
| Regulators / affected individuals | Engage legal/privacy early. Reporting clocks start from awareness. Examples: GDPR 72 hours; Japan's regime requires a preliminary report soon after discovery and a final report within 30 days (60 if malicious). Confirm current rules for your jurisdiction. |

### 2.9 Phase 6: Post-incident

- [ ] Complete the case report (`incident-case-report-template.md`)
- [ ] Hold a blameless review within 5 business days
- [ ] Deploy or tune detections identified as gaps (see table in Part 1)
- [ ] Update this playbook with anything learned
- [ ] Share a short summary with junior analysts as a learning case

### 2.10 Decision points

| Question | If yes | If no |
|---|---|---|
| Privileged or executive account? | Escalate to Critical; notify management now | Continue at current severity |
| Malicious mail sent externally? | Start external communication and legal review | Contain internally |
| Evidence of data access or download? | Treat as data breach; engage privacy/legal | Document why no access is believed |
| Unknown initial access? | Keep investigation open; widen hunt across tenant | Close root cause with evidence |

---

## Part 3: MITRE ATT&CK Mapping

| Tactic | Technique | Relevance |
|---|---|---|
| Initial Access | T1078.004 Valid Accounts: Cloud Accounts | Hijacked M365 and Workspace accounts |
| Initial Access / Credential Access | T1566.002 Spearphishing Link; T1621 MFA Request Generation | Possible entry hypotheses |
| Credential Access | T1528 Steal Application Access Token | Token or OAuth theft hypothesis |
| Defense Evasion / Lateral Movement | T1550.004 Use Alternate Authentication Material: Web Session Cookie | Session theft hypothesis |
| Persistence | T1114.003 Email Forwarding Rule; T1098 Account Manipulation | Rules, delegates, new MFA methods |
| Lateral Movement / Initial Access | T1534 Internal Spearphishing | Mass mail from trusted accounts |
| Collection | T1114.002 Remote Email Collection | Mailbox content access |

---

## Sources

- The Cyber Express, "Nikkei Cyberattack Hijacks Employee Accounts, Sends 9,000 Spoofed Emails," 5 October 2026: https://thecyberexpress.com/nikkei-cyberattack/
- Nikkei's own statements, linked from that article (nikkei.co.jp and nikkeibp.co.jp)

*This document is for education and portfolio use. It uses public reporting only and does not describe any real response or internal data.*
