# ☁️📊 SaaS Behavioral Anomalies
## Cloud & Hybrid Advanced Detection (M365 • Google Workspace • Salesforce • SaaS Apps)

This document focuses on **detecting behavioral anomalies in SaaS platforms**, where attackers abuse **valid accounts, OAuth tokens, APIs, and built-in features** to perform **data theft, persistence, reconnaissance, and privilege abuse**.

SaaS attacks are difficult to detect because:
- Activity is authenticated
- Infrastructure is managed by the provider
- Logs are limited and high-level
- Abuse blends into normal user behavior

Designed for:
- SOC Tier 2 / Tier 3 Analysts
- Cloud & SaaS Security Engineers
- Threat Hunters
- Detection Engineers
- Splunk Mastery – Advanced Searches

---

## 🎯 Objectives
- Detect anomalous SaaS user behavior
- Identify compromised SaaS accounts and tokens
- Detect data exfiltration via SaaS features
- Correlate SaaS anomalies with identity and network signals
- Support SaaS-focused incident response

---

## 🧠 What Are SaaS Behavioral Anomalies?

SaaS behavioral anomalies include:
- Unusual login locations or devices
- Sudden spikes in file access or downloads
- Abnormal sharing or permission changes
- Rare admin or configuration actions
- API and automation abuse
- Off-hours or atypical access patterns

> In SaaS, **behavior is the primary signal**.

---

## 🧠 Common SaaS Data Sources

| Platform | Example Logs |
|-------|--------------|
| Microsoft 365 | AuditLogs, SignInLogs |
| Google Workspace | Admin, Drive, Login |
| Salesforce | EventLogFile |
| SaaS APIs | Access, Activity, OAuth logs |

Assume normalized logs:
- `index=saas_logs`

---

## 🟡 BASELINE NORMAL SAAS BEHAVIOR

### 🔍 Normal Activity Volume per User
```spl
index=saas_logs
| stats avg(count) AS avg_actions by user
```

Purpose:
- Establish normal SaaS usage
- Detect deviations later

---

## 🔴 ANOMALOUS LOGIN BEHAVIOR

### 🌍 Unusual Login Locations
```spl
index=saas_logs
| search action="Login"
| stats dc(country) AS countries by user
| where countries > 2
```

Purpose:
- Detect compromised credentials
- Identify impossible or suspicious travel

---

## 🟠 OFF-HOURS SAAS ACTIVITY

### 🌙 Activity Outside Normal Working Hours
```spl
index=saas_logs
| eval hour=strftime(_time,"%H")
| search hour < 6 OR hour > 22
| stats count by user action
```

Purpose:
- Detect stealthy account abuse
- Identify automated or attacker-driven activity

---

## 🔵 FILE ACCESS & DOWNLOAD ANOMALIES

### 📂 Excessive File Downloads
```spl
index=saas_logs
| search action IN ("DownloadFile","FileAccessed")
| stats count AS downloads by user
| eventstats avg(downloads) AS avg_dl stdev(downloads) AS sd_dl
| where downloads > avg_dl + (3*sd_dl)
```

Purpose:
- Detect data exfiltration via SaaS
- Identify insider or external abuse

---

## 🟣 ABNORMAL SHARING & PERMISSIONS

### 🔗 Sudden Sharing or Permission Changes
```spl
index=saas_logs
| search action IN ("Share","PermissionChange","AddCollaborator")
| stats count by user
```

Purpose:
- Detect data exposure
- Identify attacker persistence

---

## 🔥 RARE OR HIGH-RISK SAAS ACTIONS

### 🧬 Uncommon Administrative Actions
```spl
index=saas_logs
| stats count by user action
| where action IN ("DisableMFA","AddAdmin","ModifySecurityPolicy")
```

Purpose:
- Detect privilege abuse
- Identify account takeover escalation

---

## ☁️ OAUTH & API ABUSE

### 🔌 Abnormal OAuth App Activity
```spl
index=saas_logs
| search action IN ("ConsentGranted","OAuthTokenIssued")
| stats count by user app
```

Purpose:
- Detect malicious app consent
- Identify long-term persistence mechanisms

---

## 🔗 SAAS + IDENTITY CORRELATION

### 🔑 SaaS Anomalies After Risky Login
```spl
index IN (saas_logs, identity_logs)
| table _time user action country device riskLevel
```

Purpose:
- Increase detection confidence
- Correlate access + behavior

---

## 🔗 SAAS + NETWORK CORRELATION

### 🌐 SaaS Activity Followed by Egress
```spl
index IN (saas_logs, network_logs)
| table _time user action dest_ip bytes_out
```

Purpose:
- Detect SaaS-driven data exfiltration
- Identify follow-on activity

---

## ⏱️ SAAS ANOMALY TIMELINE

```spl
index=saas_logs
| sort _time
| table _time user action resource location device
```

Purpose:
- Reconstruct SaaS abuse sequence
- Support incident response

---

## 🛡️ SOC RESPONSE & SAAS IR NOTES
- Force password reset and MFA re-enrollment
- Revoke OAuth tokens and third-party apps
- Review sharing links and permissions
- Audit admin actions and role assignments
- Notify data owners if exposure occurred
- Monitor affected accounts post-remediation

---

## 🧠 MITRE ATT&CK Mapping

| Technique | Description |
|---------|-------------|
| T1078 | Valid Accounts |
| T1098 | Account Manipulation |
| T1530 | Data from Cloud Storage |
| T1567 | Exfiltration Over Web Services |
| T1550 | Use Alternate Authentication Material |

---

## 📌 Summary
This file provides **advanced SaaS behavioral anomaly detection techniques** that enable SOC and cloud security teams to identify **account compromise, data exfiltration, OAuth abuse, and privilege misuse** across **modern SaaS platforms**, where **behavioral analytics are the primary defense layer**.

