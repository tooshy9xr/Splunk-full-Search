# 🌐 DNS Tunneling Detection
## Linux • Windows • Cloud (Advanced Splunk Searches)

This document focuses on **detecting DNS tunneling**, a technique commonly used for **Command & Control (C2)** and **data exfiltration**, where attackers abuse DNS queries to covertly transmit data.

DNS tunneling is difficult to detect because DNS is **widely allowed** and often overlooked, making **behavioral analysis essential**.

Designed for:
- SOC Tier 2 / Tier 3 Analysts
- Threat Hunters
- Incident Responders
- Splunk Mastery – Advanced Searches

---

## 🎯 Objectives
- Detect covert DNS-based C2 communication
- Identify data exfiltration over DNS
- Analyze abnormal query structure and behavior
- Correlate DNS activity across endpoint and cloud
- Support rapid containment of compromised assets

---

## 🧠 What is DNS Tunneling?

DNS tunneling typically exhibits:
- Long, random-looking subdomains
- High query volume to a single domain
- Low TTL values
- Rare or uncommon record types
- Repetitive, automated query patterns

---

## 🧠 DNS Tunneling Detection Strategy

| Indicator | Description |
|---------|-------------|
| Query Length | Unusually long domain names |
| Entropy | Random or encoded strings |
| Frequency | High query rates |
| TTL | Abnormally low values |
| Record Type | TXT, NULL, or uncommon types |

---

## 🟡 BASELINE DNS ACTIVITY

### 🔍 Identify High-Volume DNS Clients
```spl
index IN (dns_logs, windows_logs, linux_logs)
| stats count by src_ip
| where count > 1000
```

Purpose:
- Establish normal DNS query volume
- Identify noisy or compromised clients

---

## 🔴 LONG & SUSPICIOUS DOMAIN NAMES

### 📏 Query Length Detection
```spl
index=dns_logs
| eval query_length=len(query)
| stats avg(query_length) AS avg_len max(query_length) AS max_len count by src_ip
| where max_len > 50
```

Purpose:
- Detect encoded data in subdomains
- Identify tunneling frameworks

---

## 🟠 HIGH-FREQUENCY QUERIES TO SAME DOMAIN

### 🔁 Repetitive Domain Queries
```spl
index=dns_logs
| stats count by src_ip query
| where count > 100
```

Purpose:
- Detect beacon-like DNS communication
- Identify potential C2 domains

---

## 🔵 HIGH ENTROPY DOMAIN DETECTION

### 🔐 Random-Looking Subdomains
```spl
index=dns_logs
| eval entropy=len(replace(query,"[a-zA-Z0-9]",""))
| stats avg(entropy) AS avg_entropy count by src_ip
| where avg_entropy > 15
```

Purpose:
- Identify base64 / encoded strings
- Flag algorithmically generated domains

---

## 🟣 UNUSUAL RECORD TYPES

### 🧾 Rare DNS Record Usage
```spl
index=dns_logs
| search record_type IN ("TXT","NULL","SRV")
| stats count by src_ip record_type
```

Purpose:
- Detect data transfer via DNS records
- Identify misuse of TXT records

---

## 🔥 DATA EXFILTRATION OVER DNS

### 📤 Large DNS Responses
```spl
index=dns_logs
| stats avg(response_size) AS avg_size count by src_ip
| where avg_size > 300
```

Purpose:
- Detect outbound data leakage
- Identify exfiltration channels

---

## ☁️ CLOUD DNS TUNNELING

### 📡 Cloud Resolver Abuse
```spl
index=cloud_logs
(eventName IN ("DnsQuery","ListDnsRecords"))
| stats count by user sourceIPAddress
| where count > 500
```

Purpose:
- Detect compromised cloud workloads
- Identify abused service accounts

---

## 🔗 CROSS-PLATFORM DNS CORRELATION

### 🔑 Same DNS Domain Queried by Multiple Hosts
```spl
index=dns_logs
| stats dc(src_ip) AS hosts count by query
| where hosts > 5 AND count > 100
```

Purpose:
- Identify shared tunneling infrastructure
- Detect coordinated campaigns

---

## ⏱️ DNS TUNNELING TIMELINE

```spl
index IN (dns_logs, windows_logs, linux_logs, cloud_logs)
| sort _time
| table _time src_ip query record_type response_size user host
```

Purpose:
- Reconstruct tunneling activity over time
- Support incident scoping and response

---

## 🛡️ SOC RESPONSE & INVESTIGATION NOTES
- Block identified domains and IPs
- Inspect endpoint generating queries
- Correlate with beaconing detections
- Review proxy and firewall logs
- Rotate credentials and isolate affected hosts

---

## 🧠 MITRE ATT&CK Mapping

| Technique | Description |
|---------|-------------|
| T1071.004 | DNS |
| T1041 | Exfiltration Over C2 Channel |
| T1568.002 | Domain Generation Algorithms |
| T1105 | Ingress Tool Transfer |

---

## 📌 Summary
This file provides **advanced DNS tunneling detection techniques** across **Linux, Windows, and Cloud environments**, enabling SOC teams to identify **covert C2 and data exfiltration channels** hidden within normal DNS traffic.

