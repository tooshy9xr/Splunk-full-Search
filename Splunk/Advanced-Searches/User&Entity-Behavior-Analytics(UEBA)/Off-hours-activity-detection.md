# 🌙 Off-Hours Activity Detection  
Advanced Time-Based Behavioral Analytics  
(Windows • Linux • Cloud)

---

## 📁 Folder Context (Professional Description)

The **Off-Hours Activity Detection** module identifies **user and system actions occurring outside normal business hours**.  
This technique is widely used in **advanced threat hunting, UEBA, and SOC operations** to detect **stealthy attacker activity** that avoids peak hours.

Attackers commonly operate:
- Late at night
- On weekends
- During holidays
to reduce the chance of detection.

---

## 🎯 File Objective

`Off-hours-activity-detection.md` is designed to:
- Detect **authentication and activity outside baselines**
- Correlate **time-based anomalies** across platforms
- Reduce false positives using user-specific baselines
- Identify **post-compromise behavior**
- Support advanced SOC workflows

---

## 🧩 Threat Context

Mapped to **MITRE ATT&CK**:
- T1078 – Valid Accounts  
- T1059 – Command Execution  
- T1021 – Remote Services  
- TA0006 – Credential Access  

---

## 📊 Data Sources

| Source | Description |
|------|------------|
| Authentication Logs | Login timestamps |
| Endpoint Logs | Process & command execution |
| Network Logs | Session initiation times |
| Cloud IAM Logs | SaaS and API access |
| VPN Logs | Remote access sessions |
| Database Logs | Query execution time |

---

## ⏱️ Baseline Definition

Typical baseline examples:
- 🕘 Business Hours: **08:00 – 18:00**
- 🗓️ Business Days: **Sunday – Thursday** (adjustable)
- 👤 User-specific schedules
- 🌍 Region-based time zones

---

## 🔍 Advanced Detection Patterns (15 Scenarios)

---

### 1️⃣ Successful Logins Outside Business Hours
```spl
index=auth action=success
| where date_hour < 8 OR date_hour > 18
```
📌 Detects logins outside defined working hours.

---

### 2️⃣ Off-Hours Admin Logins
```spl
| search admin=true
| where date_hour < 8 OR date_hour > 18
```
📌 High-risk privileged access at night.

---

### 3️⃣ Off-Hours VPN Connections
```spl
index=vpn action=connected
| where date_hour < 8 OR date_hour > 18
```
📌 Remote access during unusual times.

---

### 4️⃣ Night-Time Command Execution (Linux)
```spl
index=linux
| where date_hour < 6 OR date_hour > 22
```
📌 Potential attacker activity via shell.

---

### 5️⃣ Off-Hours PowerShell Execution (Windows)
```spl
index=windows EventID=4688 process="powershell.exe"
| where date_hour < 7 OR date_hour > 20
```
📌 Suspicious scripting activity.

---

### 6️⃣ Off-Hours Cloud API Usage
```spl
index=cloud action=success
| where date_hour < 8 OR date_hour > 18
```
📌 Unusual SaaS or cloud management access.

---

### 7️⃣ First-Time Off-Hours Activity
```spl
| stats count by user date_hour
| where count = 1
```
📌 Users never active off-hours before.

---

### 8️⃣ Off-Hours Data Transfer Spike
```spl
index=network
| stats sum(bytes) by user
| where date_hour < 8 OR date_hour > 18
```
📌 Possible data exfiltration.

---

### 9️⃣ Weekend Activity Detection
```spl
| eval day=strftime(_time,"%A")
| where day="Friday" OR day="Saturday"
```
📌 Activity during weekends.

---

### 🔟 Off-Hours Privilege Escalation
```spl
index=auth admin=true
| where date_hour < 8 OR date_hour > 18
```
📌 Elevated actions at unusual times.

---

### 1️⃣1️⃣ Off-Hours Scheduled Task Execution
```spl
index=cron OR index=windows_scheduled_tasks
| where date_hour < 8 OR date_hour > 18
```
📌 Persistence via scheduled jobs.

---

### 1️⃣2️⃣ Off-Hours Database Queries
```spl
index=db
| where date_hour < 8 OR date_hour > 18
```
📌 Unauthorized database access.

---

### 1️⃣3️⃣ Off-Hours Endpoint Configuration Changes
```spl
index=endpoint config_change=true
| where date_hour < 8 OR date_hour > 18
```
📌 Tampering attempts.

---

### 1️⃣4️⃣ Off-Hours Rare Command + Login
```spl
| transaction user maxspan=10m
```
📌 Post-login attacker behavior.

---

### 1️⃣5️⃣ Repeated Off-Hours Activity by Same User
```spl
| stats count by user
| where count > 3
```
📌 Persistent abnormal behavior.

---

## 🧠 Behavioral Indicators Summary
- Night-time or weekend access
- Off-hours admin or cloud activity
- Rare users active outside schedule
- Data transfer spikes
- Persistence mechanisms

---

## 🛡️ Response & Mitigation
- Validate user business justification
- Enforce conditional access policies
- Require MFA during off-hours
- Temporarily restrict access
- Correlate with endpoint and network activity

---

## 📌 Final Summary

This module provides **advanced time-based anomaly detection** across:
- 🪟 Windows
- 🐧 Linux
- ☁️ Cloud platforms

It is a **critical detection capability** for identifying stealthy attackers and compromised accounts operating outside normal business hours.


