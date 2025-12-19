# 🔌 API Abuse Detection
## Cloud & Hybrid Advanced Detection (On-Prem • SaaS • Cloud APIs)

This document focuses on **detecting API abuse**, where attackers exploit **legitimate APIs, tokens, and application logic** to perform **enumeration, automation, data exfiltration, privilege abuse, or stealthy post-exploitation activity**.

API abuse is one of the hardest threats to detect because:
- Requests are authenticated
- Traffic is encrypted (HTTPS)
- Payloads are valid
- Abuse mimics legitimate application usage

Designed for:
- SOC Tier 2 / Tier 3 Analysts
- Cloud & Application Security Engineers
- Threat Hunters
- Detection Engineers
- Splunk Mastery – Advanced Searches

---

## 🎯 Objectives
- Detect abnormal API usage patterns
- Identify compromised API keys and tokens
- Detect enumeration and automation abuse
- Correlate API activity with DB, identity, and network signals
- Support rapid API-centric incident response

---

## 🧠 What Is API Abuse?

API abuse includes:
- High-frequency automated requests
- Resource enumeration (IDOR-style abuse)
- Unauthorized data extraction
- Role and scope misuse
- Abuse of export, list, and search endpoints
- Long-lived token misuse

> No exploit is required — only **valid access + malicious intent**.

---

## 🧠 Common API Abuse Techniques

| Technique | Description |
|--------|-------------|
| Enumeration | Iterating over IDs or objects |
| Automation | Scripted or bot-driven requests |
| Scope Abuse | Using tokens beyond intended permissions |
| Data Harvesting | Bulk API responses |
| Off-Hours Abuse | API usage outside normal patterns |
| Chaining | Combining APIs to bypass controls |

---

## 🟡 BASELINE API BEHAVIOR

### 🔍 Normal API Usage per User / Token
```spl
index=api_logs
| stats avg(count) AS avg_calls by user api_endpoint
```

Purpose:
- Establish expected API usage
- Detect deviations later

---

## 🔴 API ENUMERATION DETECTION

### 🔁 High Number of Unique Resources Accessed
```spl
index=api_logs
| stats dc(resource_id) AS unique_resources by user
| where unique_resources > 50
```

Purpose:
- Detect IDOR and object enumeration
- Identify reconnaissance via APIs

---

## 🟠 API AUTOMATION & BOT ABUSE

### 🤖 High-Frequency API Requests
```spl
index=api_logs
| bucket _time span=1m
| stats count AS requests by user _time
| eventstats avg(requests) AS avg_req stdev(requests) AS sd_req by user
| where requests > avg_req + (3*sd_req)
```

Purpose:
- Detect scripted abuse
- Identify compromised tokens or bots

---

## 🔵 ROLE & SCOPE VIOLATIONS

### 🔐 API Actions Outside Assigned Role
```spl
index=api_logs
| stats count by user role api_action
| where role="user" AND api_action IN ("admin","config_update","permission_change")
```

Purpose:
- Detect broken authorization
- Identify privilege abuse via APIs

---

## 🟣 RARE OR HIGH-RISK API METHODS

### 🧬 Uncommon HTTP Methods
```spl
index=api_logs
| stats count by user http_method
| where http_method IN ("PUT","DELETE","PATCH")
```

Purpose:
- Detect destructive or sensitive operations
- Identify misuse of management APIs

---

## 🔥 BULK DATA EXTRACTION VIA API

### 📦 Large API Response Sizes
```spl
index=api_logs
| stats avg(response_size) AS avg_size max(response_size) AS max_size by user
| where max_size > avg_size * 5
```

Purpose:
- Detect data exfiltration
- Identify abused export or list endpoints

---

## 🌙 TIME-BASED API ABUSE

### ⏱️ Off-Hours API Activity
```spl
index=api_logs
| eval hour=strftime(_time,"%H")
| search hour < 6 OR hour > 22
| stats count by user api_endpoint
```

Purpose:
- Detect stealthy automation
- Identify compromised credentials

---

## ☁️ CLOUD API ABUSE

### ☁️ Abnormal Cloud API Call Patterns
```spl
index=cloud_logs
| stats count AS api_calls by user
| eventstats avg(api_calls) AS avg_calls stdev(api_calls) AS sd_calls
| where api_calls > avg_calls + (3*sd_calls)
```

Purpose:
- Detect cloud API misuse
- Identify abused service accounts

---

## 🔗 API + DATABASE CORRELATION

### 🗄️ API Requests Triggering DB Anomalies
```spl
index IN (api_logs, db_logs)
| table _time user api_endpoint query table rows_returned
```

Purpose:
- Confirm backend data abuse
- Identify exploited API endpoints

---

## 🔗 API + NETWORK CORRELATION

### 🌐 API Abuse Followed by Egress
```spl
index IN (api_logs, network_logs)
| table _time user api_endpoint dest_ip bytes_out
```

Purpose:
- Validate exfiltration path
- Increase detection confidence

---

## ⏱️ API ABUSE TIMELINE

```spl
index=api_logs
| sort _time
| table _time user api_key api_endpoint http_method response_code response_size
```

Purpose:
- Reconstruct API abuse sequence
- Support incident response and reporting

---

## 🛡️ SOC RESPONSE & API SECURITY NOTES
- Rotate compromised API keys and tokens
- Apply least-privilege API scopes
- Enforce rate limiting and quotas
- Monitor export and list endpoints closely
- Add logging to sensitive APIs
- Correlate with DB and exfiltration detections

---

## 🧠 MITRE ATT&CK Mapping

| Technique | Description |
|---------|-------------|
| T1190 | Exploit Public-Facing Application |
| T1078 | Valid Accounts |
| T1041 | Exfiltration |
| T1567 | Exfiltration Over Web Services |
| T1059 | Command Execution |

---

## 📌 Summary
This file provides **advanced API abuse detection techniques** that enable SOC and cloud security teams to uncover **enumeration, automation, token abuse, and data exfiltration** through APIs, across **on-prem, SaaS, and cloud environments**, where traditional perimeter controls often fail.

