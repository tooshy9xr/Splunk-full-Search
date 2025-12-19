# 🎯 Outlier Detection
## Linux • Windows • Cloud (Advanced Splunk Searches)

This document focuses on **outlier detection**, a statistical technique used to identify **rare, abnormal, or unexpected events** that may indicate **compromise, misuse, or advanced attacker behavior**.

Outliers often represent:
- Initial attacker activity
- Living-off-the-land techniques
- Insider threats
- Misconfigurations
- Early-stage intrusions

Designed for:
- SOC Tier 2 / Tier 3 Analysts
- Threat Hunters
- Detection Engineers
- Splunk Mastery – Advanced Searches

---

## 🎯 Objectives
- Identify rare or abnormal behavior
- Detect stealthy and low-volume attacks
- Highlight deviations from peer behavior
- Support proactive threat hunting
- Reduce dependency on signatures

---

## 🧠 What Is an Outlier?

An outlier is an event or behavior that:
- Occurs **rarely**
- Deviates significantly from peers
- Breaks established baselines
- Appears unusual in context

Outliers are not always malicious—but **all attacks start as outliers**.

---

## 🧠 Common Outlier Dimensions

| Dimension | Examples |
|--------|----------|
| User | Rare user activity |
| Host | Unique system behavior |
| Network | Uncommon destinations or ports |
| Time | Activity outside normal hours |
| Action | First-time or rare operations |

---

## 🟡 RARE EVENT DETECTION (FOUNDATION)

### 🔍 First-Time or Rare Actions
```spl
index=*
| stats count by user action
| where count < 3
```

Purpose:
- Identify unusual behavior
- Catch early attacker actions

---

## 🔴 USER-BASED OUTLIERS

### 👤 User With Unusual Activity Volume
```spl
index IN (windows_logs, linux_logs)
| stats count AS actions by user
| eventstats avg(actions) AS avg_actions stdev(actions) AS sd_actions
| eval z_score=(actions-avg_actions)/sd_actions
| where z_score > 3
```

Purpose:
- Detect compromised or malicious users
- Identify insider threats

---

## 🟠 HOST-BASED OUTLIERS

### 🖥️ Rare Host Behavior
```spl
index IN (windows_logs, linux_logs)
| stats count by host command
| where count < 2
```

Purpose:
- Identify unusual command execution
- Detect targeted attacks

---

## 🔵 NETWORK OUTLIERS

### 🌐 Rare Destination Connections
```spl
index=network_logs
| stats count by src_ip dest_ip
| where count < 3
```

Purpose:
- Detect connections to uncommon infrastructure
- Identify early-stage C2

---

## 🟣 PORT & PROTOCOL OUTLIERS

### 🚪 Uncommon Port Usage
```spl
index=network_logs
| stats count by src_ip dest_port
| where count < 5 AND dest_port NOT IN (80,443,53)
```

Purpose:
- Identify backdoors and tunnels
- Detect misuse of internal services

---

## 🔥 TIME-BASED OUTLIERS

### ⏱️ Off-Hours Activity
```spl
index IN (windows_logs, linux_logs)
| eval hour=strftime(_time,"%H")
| search hour < 6 OR hour > 22
| stats count by user host
```

Purpose:
- Detect abnormal working-hour activity
- Identify stealthy access

---

## ☁️ CLOUD OUTLIERS

### ☁️ Rare Cloud API Actions
```spl
index=cloud_logs
| stats count by user eventName
| where count < 2
```

Purpose:
- Detect cloud privilege misuse
- Identify compromised service accounts

---

## 🔗 MULTI-DIMENSIONAL OUTLIERS

### 🔑 Rare User + Host + Action
```spl
index IN (windows_logs, linux_logs)
| stats count by user host command
| where count < 2
```

Purpose:
- Detect abnormal behavior combinations
- Catch living-off-the-land attacks

---

## ⏱️ OUTLIER TIMELINE VIEW

```spl
index=*
| sort _time
| table _time user host action metric
```

Purpose:
- Reconstruct outlier activity
- Support investigation and scoping

---

## 🛡️ SOC RESPONSE & TUNING NOTES
- Validate context before escalating
- Exclude known administrative or batch activity
- Tune thresholds per environment
- Combine outlier detection with anomaly scoring
- Prioritize repeated or clustered outliers
- Use outliers for hunting, not only alerting

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
This file provides **advanced outlier detection techniques** that help SOC teams uncover **rare, stealthy, and early-stage attacker behavior** across **Linux, Windows, and Cloud environments**, forming a critical foundation for **proactive threat hunting and advanced detection engineering**.

