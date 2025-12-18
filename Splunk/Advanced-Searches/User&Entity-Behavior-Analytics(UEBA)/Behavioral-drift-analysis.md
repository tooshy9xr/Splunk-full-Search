# 📈 Behavioral Drift Analysis  
Advanced Long-Term Behavior Deviation Detection  
(Windows • Linux • Cloud)

---

## 📁 Folder Context (Professional Description)

The **Behavioral Drift Analysis** module focuses on detecting **gradual, long-term changes in user or system behavior** that may indicate **slow-moving attacks, account compromise, insider threats, or shadow IT activity**.

Unlike sudden anomaly detection, behavioral drift identifies **progressive deviations** that occur over days, weeks, or months.

This technique is widely used in **advanced threat hunting, UEBA platforms, and mature SOC environments**.

---

## 🎯 File Objective

`Behavioral-drift-analysis.md` is designed to:
- Detect **gradual behavior changes over time**
- Identify **low-and-slow attacker activity**
- Reduce noise from one-time anomalies
- Highlight evolving misuse of valid access
- Support strategic threat hunting and risk scoring

---

## 🧩 Threat Context

Mapped to **MITRE ATT&CK**:
- T1078 – Valid Accounts  
- T1087 – Account Discovery  
- T1059 – Command Execution  
- TA0006 – Credential Access  
- TA0008 – Lateral Movement  

Attackers often:
- Slowly expand access
- Change behavior incrementally
- Avoid triggering thresholds
- Operate over long dwell times

---

## 📊 Data Sources

| Source | Description |
|------|------------|
| Authentication Logs | Login frequency and timing |
| Endpoint Logs | Commands, processes, scripts |
| Network Logs | Destinations and volume |
| Cloud IAM Logs | API usage and SaaS access |
| VPN Logs | Remote access behavior |
| Database Logs | Query patterns |

---

## 📐 Drift Baseline Methodology

Behavior is compared across:
- **Short-term window** (last 24h–7d)
- **Long-term baseline** (30–90 days)

Drift is identified when recent behavior **consistently diverges** from historical norms.

---

## 🔍 Advanced Detection Patterns (15 Scenarios)

---

### 1️⃣ Gradual Increase in Login Frequency
```spl
| timechart span=1d count by user
```
📌 Detects slow login volume growth.

---

### 2️⃣ Shift in Login Hours Over Time
```spl
| timechart span=1d avg(date_hour) by user
```
📌 Detects drifting work hours.

---

### 3️⃣ Expanding Host Access Footprint
```spl
| stats dc(host) by user
```
📌 Detects slow lateral expansion.

---

### 4️⃣ Command Usage Drift (Linux)
```spl
| timechart span=7d dc(cmd) by user
```
📌 Detects growing command diversity.

---

### 5️⃣ PowerShell Cmdlet Drift (Windows)
```spl
| timechart span=7d dc(cmdlet) by user
```
📌 Detects advanced scripting adoption.

---

### 6️⃣ Increasing Privilege Usage
```spl
| timechart span=7d count by user admin
```
📌 Detects gradual privilege escalation.

---

### 7️⃣ Cloud Application Access Expansion
```spl
| timechart span=7d dc(AppDisplayName) by user
```
📌 Detects SaaS access creep.

---

### 8️⃣ New Network Destinations Over Time
```spl
| timechart span=7d dc(dest_ip) by user
```
📌 Detects widening communication scope.

---

### 9️⃣ VPN Usage Drift
```spl
| timechart span=7d count by user
```
📌 Detects increasing remote access reliance.

---

### 🔟 Data Transfer Growth Trend
```spl
| timechart span=7d sum(bytes) by user
```
📌 Detects potential slow exfiltration.

---

### 1️⃣1️⃣ Gradual Authentication Method Changes
```spl
| timechart span=7d dc(auth_method) by user
```
📌 Detects evolving login techniques.

---

### 1️⃣2️⃣ Database Query Pattern Drift
```spl
| timechart span=7d dc(query_type) by user
```
📌 Detects changing data access behavior.

---

### 1️⃣3️⃣ Off-Hours Activity Creep
```spl
| timechart span=7d count by user
```
📌 Detects expansion into off-hours.

---

### 1️⃣4️⃣ Rare Actions Becoming Frequent
```spl
| stats count by user action
```
📌 Detects normalization of risky behavior.

---

### 1️⃣5️⃣ Cross-Domain Activity Expansion
```spl
| stats dc(domain) by user
```
📌 Detects movement across environments.

---

## 🧠 Behavioral Indicators Summary
- Slowly increasing activity levels
- Expanding system and network access
- Growing privilege usage
- Increased off-hours operations
- Cloud and data access creep

---

## 🛡️ Response & Mitigation
- Review behavioral change with business context
- Apply adaptive authentication controls
- Re-baseline after verified role changes
- Monitor for correlated alerts
- Escalate persistent drift patterns

---

## 📌 Final Summary

This module provides **deep, long-term behavioral visibility** across:
- 🪟 Windows
- 🐧 Linux
- ☁️ Cloud environments

It is a **critical advanced detection capability** for identifying **low-and-slow threats, insider risk, and evolving account compromise**.


