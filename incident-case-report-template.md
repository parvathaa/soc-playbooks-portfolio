# Incident Case Report Template

> Copy this file for each incident. Delete the guidance text in *italics* once a section is filled in.
> Keep facts, assumptions, and unknowns clearly separate. Every claim should be traceable to evidence.

---

## 1. Case Summary

| Field | Value |
|---|---|
| Case ID | `IR-YYYY-NNN` |
| Title | *Short, factual (e.g. "M365 account takeover used for outbound phishing")* |
| Status | Open / Contained / Eradicated / Recovered / Closed |
| Severity | Critical / High / Medium / Low *(see Section 3)* |
| Incident type | Account compromise / Phishing / Malware / Data breach / Extortion / Other |
| Detected (UTC) | |
| Declared (UTC) | |
| Contained (UTC) | |
| Closed (UTC) | |
| Case owner | |
| Escalated from | *Junior analyst / alert / external notification / user report* |
| Report author / date | |
| Report version | |

### Executive summary (max 5 sentences)
*What happened, what was affected, current status, business impact, and the single most important next step. Write it so a non-technical manager can act on it.*

---

## 2. Detection and Triage

- **How was it detected?** *(alert name / user report / third-party notice / threat intel)*
- **Detection source and rule:** *(tool, rule ID, MITRE technique)*
- **Time from first malicious activity to detection (dwell time):**
- **Initial triage verdict:** True positive / False positive / Benign true positive
- **Why:** *(evidence behind the verdict)*

---

## 3. Severity and Classification

| Factor | Assessment |
|---|---|
| Data sensitivity (personal, financial, credentials, IP) | |
| Number of users / systems / customers affected | |
| Business function disrupted | |
| Regulatory or contractual exposure | |
| Attacker activity ongoing? | |
| **Final severity** | |

*Justify any change in severity during the incident and note when it changed.*

---

## 4. Timeline of Events

*All times in UTC. Mark each entry as **Confirmed** (evidence in hand), **Reported** (from a third party), or **Assumed**.*

| Time (UTC) | Event | Source / evidence | Confidence |
|---|---|---|---|
| | | | |

---

## 5. Scope and Impact

- **Affected accounts / hosts / services:**
- **Data accessed or exfiltrated:** *(types and volume; state what is confirmed vs. suspected)*
- **External parties affected:** *(customers, partners, recipients of malicious mail)*
- **Operational impact:** *(downtime, workarounds, cost)*
- **Business impact summary:** *(plain language)*
- **Unknowns still being investigated:**

---

## 6. Technical Analysis

### 6.1 Initial access
*Vector, evidence, and your confidence level. If unknown, say so and list hypotheses to test.*

### 6.2 Attacker actions (mapped to MITRE ATT&CK)

| Tactic | Technique ID | Observed behaviour | Evidence |
|---|---|---|---|
| | | | |

### 6.3 Indicators of compromise (IOCs)

| Type | Value | Context | First / last seen | Action taken |
|---|---|---|---|---|
| IP | | | | Blocked / Monitored |
| Domain / URL | | | | |
| File hash | | | | |
| Account | | | | |

### 6.4 Root cause
*One or two sentences on the control failure or condition that allowed the incident.*

---

## 7. Response Actions

| Phase | Action | Owner | Time (UTC) | Result |
|---|---|---|---|---|
| Containment | | | | |
| Eradication | | | | |
| Recovery | | | | |

---

## 8. Communications and Notifications

| Audience | What was communicated | Owner | Time (UTC) |
|---|---|---|---|
| Internal leadership | | | |
| Affected users | | | |
| External recipients / customers | | | |
| Regulator(s) | | | |
| Legal / HR / PR | | | |

*Note the regulatory clock that applied (e.g. GDPR 72 hours; national regimes vary) and whether it was met.*

---

## 9. Lessons Learned

### What worked

### What did not work

### Detection gaps
*Which signal should have caught this earlier, and why did it not?*

---

## 10. Recommendations

| # | Recommendation | Type (Prevent / Detect / Respond) | Priority | Owner | Target date |
|---|---|---|---|---|---|
| 1 | | | | | |

*Include at least one **detection improvement** (new or tuned rule) and one **process or documentation** update.*

---

## 11. Appendices

- A. Queries used (sanitised)
- B. Screenshots / log excerpts (sanitised)
- C. Related cases and tickets
- D. Sources and references

---

### Report quality checklist

- [ ] Facts, assumptions, and unknowns are clearly separated
- [ ] Timeline is in UTC with evidence references
- [ ] Impact is stated in business terms
- [ ] Every recommendation has an owner and a priority
- [ ] Sensitive data (names, IPs, tokens) is sanitised before sharing
- [ ] A peer or senior analyst has reviewed it
