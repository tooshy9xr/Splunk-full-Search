# 🔐 Encrypted Traffic Analysis
## Linux • Windows • Cloud (Advanced Splunk Searches)

This document focuses on **analyzing encrypted network traffic** (TLS/SSL/HTTPS) to detect **malicious activity without decryption**, using **metadata, behavior, and correlation techniques**.

Encrypted traffic is commonly abused for:
- Command & Control (C2)
- Data exfiltration
- Malware delivery
- Covert tunneling

Designed for:
- SOC Tier 2 / Tier 3 Analysts
- Threat Hunters
- Incident Responders
- Splunk Mastery – Advanced Searches

---

## 🎯 Objectives
- Detect malicious behavior hidden in encrypted traffic
- Analyze TLS metadata instead of payloads
- Identify anomalous encrypted sessions
- Correlate encrypted traffic with endpoint and cloud activity
- Support investigation without breaking encryption

---

## 🧠 Why Encrypted Traffic Matters

Attackers abuse encryption because:
- Payloads are invisible
- HTTPS is widely allowed
- TLS hides malicious content
- Security teams often trust encrypted sessions

Detection relies on **behavioral signals**, not content.

---

## 🧠 Encrypted Traffic Detection Signals

| Signal | Description |
|------|------------|
| Session Duration | Very short or very long TLS sessions |
| Byte Ratio | Abnormal sent/received ratios |
| JA3 / JA3S | Rare or malicious TLS fingerprints |
| Certificate Age | Self-signed or newly issued certs |
| Destination | Rare or low-reputation domains |

---

## 🟡 BASELINE TLS / HTTPS ACTIVITY

### 🔍 Common Encrypted Destinations
```spl
index=network_logs
| search protocol IN ("TLS","SSL","HTTPS")
| stats count by src_ip dest_ip dest_port
```

Purpose:
- Establish normal encrypted traffic patterns
- Identify expected services

---

## 🔴 ABNORMAL SESSION DURATION

### ⏱️ Very Short or Long TLS Sessions
```spl
index=network_logs
| search protocol="TLS"
| stats avg(duration) AS avg_dur max(duration) AS max_dur by src_ip dest_ip
| where max_dur > 3600 OR avg_dur < 2
```

Purpose:
- Detect beaconing or tunneling over TLS
- Identify automated callbacks

---

## 🟠 ABNORMAL BYTE RATIOS

### 📊 Sent vs Received Anomalies
```spl
index=network_logs
| search protocol="TLS"
| eval byte_ratio=bytes_out/bytes_in
| stats avg(byte_ratio) AS avg_ratio by src_ip dest_ip
| where avg_ratio > 5 OR avg_ratio < 0.2
```

Purpose:
- Detect data exfiltration
- Identify C2 check-ins

---

## 🔵 JA3 / JA3S FINGERPRINT ANALYSIS

### 🔐 Rare TLS Fingerprints
```spl
index=network_logs
| search protocol="TLS"
| stats count by ja3
| where count < 5
```

Purpose:
- Detect malware TLS stacks
- Identify non-standard clients

---

## 🟣 CERTIFICATE ANOMALIES

### 📜 Suspicious Certificates
```spl
index=network_logs
| search protocol="TLS"
| eval cert_age=now()-cert_not_before
| stats avg(cert_age) by dest_ip
| where avg(cert_age) < 86400
```

Purpose:
- Detect self-signed or short-lived certs
- Identify attacker-controlled servers

---

## 🔥 ENCRYPTED C2 BEHAVIOR

### 📡 Beaconing Over HTTPS
```spl
index=network_logs
| search protocol="TLS" dest_port=443
| sort _time
| streamstats window=2 last(_time) AS prev_time by src_ip dest_ip
| eval interval=_time-prev_time
| stats avg(interval) stdev(interval) count by src_ip dest_ip
| where count > 20 AND stdev(interval) < 5
```

Purpose:
- Detect periodic C2 over HTTPS
- Combine encryption + beaconing logic

---

## ☁️ CLOUD ENCRYPTED TRAFFIC ANALYSIS

### ☁️ Suspicious Cloud Egress
```spl
index=cloud_network_logs
| search protocol="TLS"
| stats sum(bytes_out) AS egress by src_instance dest_ip
| where egress > 100000000
```

Purpose:
- Detect cloud workload exfiltration
- Identify compromised instances

---

## 🔗 CORRELATION WITH ENDPOINT ACTIVITY

### 🔑 Encrypted Traffic + Process Context
```spl
index IN (network_logs, windows_logs, linux_logs)
| table _time src_ip dest_ip dest_port process user host
```

Purpose:
- Identify which process initiated encrypted sessions
- Tie network traffic to host activity

---

## ⏱️ ENCRYPTED TRAFFIC TIMELINE

```spl
index IN (network_logs, cloud_network_logs)
| sort _time
| table _time src_ip dest_ip dest_port protocol bytes_out bytes_in ja3
```

Purpose:
- Visualize encrypted communication over time
- Support scoping and response

---

## 🛡️ SOC RESPONSE & INVESTIGATION NOTES
- Enrich destinations with threat intel
- Investigate rare JA3 fingerprints
- Correlate with DNS and beaconing detections
- Inspect process lineage on affected hosts
- Block malicious endpoints at perimeter
- Isolate compromised assets

---

## 🧠 MITRE ATT&CK Mapping

| Technique | Description |
|---------|-------------|
| T1071.001 | Web-based C2 |
| T1095 | Non-Application Layer Protocol |
| T1041 | Exfiltration Over C2 Channel |
| T1573 | Encrypted Channel |
| T1105 | Ingress Tool Transfer |

---

## 📌 Summary
This file provides **advanced encrypted traffic analysis techniques** that enable SOC teams to detect **C2, tunneling, and data exfiltration hidden inside TLS/HTTPS traffic**, without decrypting payloads, across **Linux, Windows, and Cloud environments**.

