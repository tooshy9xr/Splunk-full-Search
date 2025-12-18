# 🚨 Abnormal Login Behavior  
Advanced Authentication Anomaly Detection  
(Windows • Linux • Cloud)

---

## 📁 Folder Context (Professional Description)

The **Abnormal Login Behavior** module focuses on detecting **authentication activities that deviate from normal patterns**, even when credentials are valid.  
This file is part of **Advanced Searches** and is essential for identifying **account compromise, credential abuse, insider threats, and early-stage attacks**.

Unlike basic failed-login checks, this module looks for **behavioral anomalies** across time, location, frequency, method, and source.

---

## 🎯 File Objective

`Abnormal-login-behavior.md` is designed to:
- Detect **suspicious but successful logins**
- Identify **credential misuse** across environments
- Correlate login behavior across **Windows, Linux, and Cloud**
- Reduce reliance on static thresholds
- Support advanced SOC and UEBA detections

---

## 🧩 Threat Context

Mapped to **MITRE ATT&CK**:
- T1078 – Valid Accounts  
- T1110 – Brute Force (Post-success behavior)  
- T1021 – Remote Services  
- TA0006 – Credential Access  

Attackers often:
- Use correct credentials
- Log in successfully
- Blend in with normal activity
- Avoid repeated failures

---

## 📊 Data Sources

| Source | Description |
|------|------------|
| Windows Security Logs | EventID 4624, 4625 |
| Linux Auth Logs | SSH, PAM authentication |
| VPN Logs | Remote access behavior |
| Cloud IAM Logs | Azure AD, AWS IAM, GCP |
| MFA Logs | Authentication challenges |
| Proxy / Network Logs | Source validation |

---

## 🔍 Advanced Detection Patterns (15 Scenarios)

---

### 1️⃣ Login at Unusual Hours
```spl
index=auth action=success
| where date_hour < 6 OR date_hour > 22
```
📌 **Detects:** Logins outside expected working hours.

---

### 2️⃣ New Source IP for User
```spl
| stats count by user src_ip
| where count = 1
```
📌 **Detects:** First-time IP usage per user.

---

### 3️⃣ Login from New Country
```spl
| iplocation src_ip
| stats dc(Country) by user
| where dc(Country) > 1
```
📌 **Detects:** Geographic deviations.

---

### 4️⃣ Excessive Successful Logins
```spl
| stats count as success_count by user
| where success_count > 20
```
📌 **Detects:** Automation, scripts, or token abuse.

---

### 5️⃣ Multiple Hosts in Short Time
```spl
| stats dc(host) as host_count by user
| where host_count > 5
```
📌 **Detects:** Lateral movement behavior.

---

### 6️⃣ Login Without Prior Failures
```spl
index=auth
| stats count(eval(action="failure")) as failures,
        count(eval(action="success")) as successes by user
| where successes>0 AND failures=0
```
📌 **Detects:** Possible credential reuse or theft.

---

### 7️⃣ VPN Login Followed by Internal Login
```spl
index=auth
| transaction user maxspan=10m
```
📌 **Detects:** Rapid pivot after VPN access.

---

### 8️⃣ Authentication Method Change
```spl
| stats dc(auth_method) by user
| where dc(auth_method) > 1
```
📌 **Detects:** Sudden MFA, token, or API usage changes.

---

### 9️⃣ Impossible Travel Pattern
```spl
| iplocation src_ip
| stats earliest(_time) latest(_time) by user Country
```
📌 **Detects:** Physically impossible movement.

---

### 🔟 Login from TOR / Proxy IPs
```spl
| lookup tor_exit_nodes ip as src_ip OUTPUT ip as match
| where isnotnull(match)
```
📌 **Detects:** Anonymous access infrastructure.

---

### 1️⃣1️⃣ Rare Login Host
```spl
| stats count by user host
| where count < 2
```
📌 **Detects:** First-time system access.

---

### 1️⃣2️⃣ Cloud Login Outside Normal Apps
```spl
index=cloud action=success
| stats dc(AppDisplayName) by user
| where dc(AppDisplayName) > 3
```
📌 **Detects:** SaaS access drift.

---

### 1️⃣3️⃣ MFA Bypass Indicators
```spl
| search mfa_required=false
```
📌 **Detects:** Authentication without expected MFA.

---

### 1️⃣4️⃣ Concurrent Logins from Different Locations
```spl
| stats dc(src_ip) by user
| where dc(src_ip) > 3
```
📌 **Detects:** Credential sharing or compromise.

---

### 1️⃣5️⃣ Login Followed by Privilege Usage
```spl
index=auth admin=1
| stats count by user
```
📌 **Detects:** Post-compromise privilege abuse.

---

## 🧠 Behavioral Indicators Summary
- Time-of-day anomalies
- Location and IP deviations
- Method and MFA changes
- Rapid multi-host access
- Unusual login volume
- Cloud and VPN pivots

---

## 🛡️ Response & Mitigation
- Enforce step-up authentication
- Temporarily restrict account access
- Validate business justification
- Correlate with endpoint and network activity
- Reset credentials if compromise suspected

---

## 📌 Final Summary

This module enables **high-fidelity detection of abnormal login behavior** across:
- 🪟 Windows
- 🐧 Linux
- ☁️ Cloud platforms

It is a **core advanced detection capability** for SOCs, UEBA systems, and threat hunting programs.

