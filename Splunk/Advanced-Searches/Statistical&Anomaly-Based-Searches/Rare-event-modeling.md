# 🧬 Rare Event Modeling
## Linux • Windows • Cloud (Advanced Splunk Detection Engineering)

This document focuses on **rare event modeling**, a detection engineering technique that identifies **low-frequency, high-risk events** that often indicate **early-stage attacks, stealthy intrusions, or misuse of legitimate tools**.

Rare event modeling is especially effective against:
- Living-off-the-land attacks
- Credential abuse
- Insider threats
- APT initial access
- Cloud privilege misuse

Designed for:
- SOC Tier 2 / Tier 3 Analysts
- Threat Hunters
- Detection Engineers
- Splunk Mastery – Advanced Searches

---

## 🎯 Objectives
- Identify security-relevant rare events
- Detect early attacker behavior
- Model normal vs abnormal activity
- Reduce noise from high-volume logs
- Support proactive threat hunting

---

## 🧠 What Is Rare Event Modeling?

Rare event modeling focuses on:
- **Actions that almost never happen**
- **Combinations that are unusual**
- **Events outside historical patterns**

Unlike anomaly detection (volume-based), rare event modeling is:
- Frequency-driven
- Context-sensitive
- High signal when tuned correctly

> If an action happens once a month — it deserves attention.

---

## 🧠 Rare Event Dimensions

| Dimension | Examples |
|--------|----------|
| User | Rare actions by a user |
| Host | Unusual activity on a system |
| Command | First-seen command usage |
| Network | New destinations or ports |
| Cloud | Rare API calls or role changes |
| Time | Events at unusual hours |

---

## 🟡 FOUNDATION: IDENTIFY RARE EVENTS

### 🔍 Globally Rare Actions
```spl
index=*
| stats count by action
| where count < 5
```

Purpose:
- Identify events that almost never occur
- Create candidate detections

---

## 🔴 USER-CENTRIC RARE EVENT MODELING

### 👤 Rare Actions Per User
```spl
index IN (windows_logs, linux_logs)
| stats count by user action
| where count < 3
```

Purpose:
- Detect compromised users
- Identify insider misuse

---

## 🟠 HOST-CENTRIC RARE EVENT MODELING

### 🖥️ Rare Commands Per Host
```spl
index IN (windows_logs, linux_logs)
| stats count by host command
| where count < 2
```

Purpose:
- Detect targeted attacks
- Identify one-off exploitation

---

## 🔵 NETWORK RARE EVENTS

### 🌐 Rare Destination Access
```spl
index=network_logs
| stats count by src_ip dest_ip
| where count < 3
```

Purpose:
- Detect first-time C2 infrastructure
- Identify staging servers

---

## 🟣 PORT & PROTOCOL RARE EVENTS

### 🚪 Rare Port Usage
```spl
index=network_logs
| stats count by dest_port
| where count < 5 AND dest_port NOT IN (80,443,53)
```

Purpose:
- Detect backdoors and tunnels
- Identify misused services

---

## ☁️ CLOUD RARE EVENT MODELING

### ☁️ Rare Cloud API Actions
```spl
index=cloud_logs
| stats count by user eventName
| where count < 2
```

Purpose:
- Detect cloud privilege escalation
- Identify misconfigurations or abuse

---

## 🔥 MULTI-DIMENSIONAL RARE EVENTS

### 🔗 Rare User + Host + Action
```spl
index IN (windows_logs, linux_logs)
| stats count by user host command
| where count < 2
```

Purpose:
- High-confidence detections
- Catch living-off-the-land attacks

---

## ⏱️ TIME-BASED RARE EVENTS

### 🌙 Off-Hours Rare Activity
```spl
index IN (windows_logs, linux_logs)
| eval hour=strftime(_time,"%H")
| search hour < 6 OR hour > 22
| stats count by user host action
| where count < 3
```

Purpose:
- Detect stealthy access
- Identify suspicious timing

---

## 🔗 RARE EVENT CORRELATION

### 🔑 Rare Event + Authentication
```spl
index IN (windows_logs, linux_logs, cloud_logs)
| table _time user host action sourceIPAddress
```

Purpose:
- Add context
- Reduce false positives

---

## 🧠 MODEL TUNING & MATURITY

Key tuning principles:
- Exclude known admin activity
- Whitelist expected rare operations
- Tune per role (server vs workstation)
- Require repeatability for alerts
- Use rare events primarily for hunting

---

## 🛡️ SOC RESPONSE & INVESTIGATION NOTES
- Validate business justification
- Check for related anomalies
- Look for clustering of rare events
- Correlate with privilege escalation
- Track rare events over time
- Escalate when rare events chain together

---

## 🧠 MITRE ATT&CK Mapping

| Technique | Description |
|---------|-------------|
| T1078 | Valid Accounts |
| T1059 | Command Execution |
| T1046 | Network Service Discovery |
| T1021 | Remote Services |
| T1071 | Command & Control |

---

## 📌 Summary
This file provides **advanced rare event modeling techniques** that enable SOC teams to identify **low-frequency, high-impact attacker behavior** across **Linux, Windows, and Cloud environments**, forming a critical layer of **proactive threat detection and hunting**.

