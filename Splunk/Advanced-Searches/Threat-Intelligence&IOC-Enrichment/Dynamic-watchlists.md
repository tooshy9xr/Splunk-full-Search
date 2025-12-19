# 🔄 Dynamic Watchlists
## Detection Engineering & Threat Intelligence (Advanced Splunk Practices)

This document focuses on **dynamic watchlists**, a powerful technique for maintaining **adaptive, self-updating lists** of entities (users, IPs, hosts, hashes, domains, API keys, etc.) that are **continuously refreshed based on behavior, intelligence, and risk**.

Dynamic watchlists replace static allow/deny lists and enable:
- Adaptive detections
- Context-aware alerting
- Reduced false positives
- Faster response to evolving threats

Designed for:
- SOC Tier 2 / Tier 3 Analysts
- Detection Engineers
- Threat Hunters
- Threat Intelligence Teams
- Splunk Mastery – Advanced Searches

---

## 🎯 Objectives
- Build behavior-driven watchlists
- Automatically update watchlists based on risk
- Use watchlists as context, not hard blocks
- Reduce manual list maintenance
- Improve detection precision and adaptability

---

## 🧠 What Is a Dynamic Watchlist?

A dynamic watchlist is:
- Automatically populated
- Continuously updated
- Driven by detections, anomalies, or intelligence
- Time-bound and self-cleaning

Examples:
- Recently suspicious users
- Hosts with repeated anomalies
- IPs seen in multiple detections
- API keys showing abuse patterns
- Domains linked to emerging campaigns

> Static lists go stale. Dynamic lists evolve.

---

## 🧠 Common Watchlist Types

| Watchlist | Entities |
|---------|----------|
| High-Risk Users | user, account |
| Suspicious Hosts | hostname, IP |
| Malicious Infrastructure | IP, domain |
| Compromised Credentials | user, API key |
| Cloud Abuse Entities | role, service account |
| Insider Risk | user |

---

## 🟡 BUILDING A DYNAMIC WATCHLIST (FOUNDATION)

### 🔍 Example: Identify Suspicious Users
```spl
index IN (windows_logs, linux_logs, app_logs)
| stats count AS actions by user
| eventstats avg(actions) AS avg_actions stdev(actions) AS sd_actions
| where actions > avg_actions + (3*sd_actions)
| table user
```

Purpose:
- Identify users behaving abnormally
- Feed results into a watchlist

---

## 🔴 WATCHLIST POPULATION (AUTOMATED)

### 📥 Populate Watchlist via Lookup Output
```spl
index=network_logs
| stats count by src_ip
| where count > 100
| outputlookup suspicious_ips.csv
```

Purpose:
- Automatically update watchlist files
- Eliminate manual updates

---

## 🟠 TIME-BOUND WATCHLIST ENTRIES

### ⏳ Add Expiration Logic
```spl
index=*
| eval expires_at=relative_time(now(), "+7d")
| table user expires_at
```

Purpose:
- Prevent permanent entries
- Ensure watchlists self-clean

---

## 🔵 USING WATCHLISTS IN DETECTIONS

### 🔗 Apply Watchlist as Context
```spl
index=network_logs
| lookup suspicious_ips.csv src_ip OUTPUT src_ip AS watchlisted_ip
| where isnotnull(watchlisted_ip)
```

Purpose:
- Increase detection confidence
- Avoid hard blocking on first sighting

---

## 🟣 WATCHLIST + BEHAVIOR CORRELATION

### 🧠 Watchlisted Entity + Anomaly
```spl
index IN (network_logs, windows_logs, linux_logs)
| lookup high_risk_users.csv user OUTPUT user AS flagged_user
| where isnotnull(flagged_user)
| table _time user host action
```

Purpose:
- Combine context + behavior
- Reduce false positives

---

## 🔥 ESCALATION THROUGH REPEAT APPEARANCE

### 🔁 Recurrent Watchlist Hits
```spl
index=*
| lookup suspicious_hosts.csv host OUTPUT host AS flagged_host
| stats count by host
| where count > 3
```

Purpose:
- Promote entities to higher risk
- Enable progressive response

---

## ☁️ CLOUD DYNAMIC WATCHLISTS

### ☁️ Abnormal Cloud Identities
```spl
index=cloud_logs
| stats count AS api_calls by user
| eventstats avg(api_calls) AS avg_calls stdev(api_calls) AS sd_calls
| where api_calls > avg_calls + (3*sd_calls)
| outputlookup cloud_high_risk_users.csv
```

Purpose:
- Track risky cloud identities
- Detect compromised service accounts

---

## 🔗 WATCHLIST LIFECYCLE MANAGEMENT

### ♻️ Expire Old Entries
```spl
| inputlookup suspicious_ips.csv
| where expires_at > now()
```

Purpose:
- Automatically remove stale entries
- Maintain list hygiene

---

## ⏱️ WATCHLIST ACTIVITY TIMELINE

```spl
index=*
| lookup high_risk_users.csv user OUTPUT user AS watchlisted
| where isnotnull(watchlisted)
| sort _time
| table _time user host action
```

Purpose:
- Track behavior of watchlisted entities
- Support investigation and reporting

---

## 🛡️ SOC & DETECTION ENGINEERING NOTES
- Never use watchlists as sole detection logic
- Prefer temporary entries with expiration
- Promote entities through risk tiers
- Combine with anomaly, rarity, and intel signals
- Review watchlist criteria regularly
- Measure false positive impact

---

## 🧠 Watchlist Maturity Model

| Level | Characteristics |
|------|----------------|
| Static | Manually updated, stale |
| Semi-Dynamic | Periodic scripted updates |
| Dynamic | Behavior-driven, auto-expiring |
| Mature | Risk-scored, multi-signal driven |

---

## 🧠 MITRE ATT&CK Mapping (Contextual)

| Focus Area | Techniques |
|-----------|------------|
| Credential Abuse | T1078 |
| C2 Infrastructure | T1071 |
| Exfiltration | T1041 |
| Lateral Movement | T1021 |
| Discovery | T1087 |

---

## 📌 Summary
This file provides **advanced dynamic watchlist techniques** that enable SOC teams to maintain **adaptive, low-noise, and intelligence-driven context** for detections—bridging the gap between **raw telemetry and actionable alerts**.

Dynamic watchlists are not alerts —  
they are **force multipliers** for detection.

