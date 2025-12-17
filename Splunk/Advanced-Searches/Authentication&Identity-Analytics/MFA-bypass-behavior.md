# 🔐⚡ MFA Bypass Behavior  
Advanced Detection of Multi-Factor Authentication (MFA) Evasion  
(Windows • Linux • Cloud)

---

## 📁 Folder Context (Professional Description)

The **MFA Bypass Behavior** folder focuses on detecting **techniques attackers use to circumvent multi-factor authentication**, including:
- MFA fatigue attacks
- OTP interception or replay
- Session hijacking post-MFA
- Exploitation of conditional access policies

This folder is crucial for **identity-centric threat hunting** and **advanced SOC operations**, covering **Windows, Linux, and cloud environments**.

---

## 🎯 File Objective

`MFA-bypass-behavior.md` provides **advanced SPL detection logic** to identify:
- Abnormal MFA success patterns
- Rapid MFA challenge attempts
- MFA bypass via session or token abuse
- Indicators of compromise that involve MFA circumvention

It helps analysts **catch stealthy account compromises** that evade standard MFA protections.

---

## 🧩 Threat Context

Mapped to **MITRE ATT&CK**:
- TA0006 – Credential Access  
- T1111 – Multi-Factor Authentication Interception  
- T1078 – Valid Accounts  

Attackers often:
1. Trigger repeated MFA prompts to induce approval fatigue
2. Reuse valid session tokens
3. Exploit weak conditional access policies
4. Move laterally or escalate privileges post-MFA bypass

---

## 📊 Data Sources

| Source | Description |
|--------|-------------|
| MFA Logs | Challenge and approval events from cloud and on-prem MFA |
| Authentication Logs | Successful and failed login correlating with MFA |
| VPN / Remote Access | MFA-protected login attempts |
| Cloud IAM | MFA events across SaaS platforms |
| Conditional Access | Policy enforcement events |

---

## 🔍 Advanced Detection Patterns (10+ Scenarios)

---

### 1️⃣ Repeated MFA Prompts (MFA Fatigue)
```spl
index=mfa action=challenge
| stats count by user
| where count > 5
```
**Detects:** Potential fatigue attacks targeting a user.

---

### 2️⃣ MFA Success Immediately After Multiple Challenges
```spl
index=mfa
| stats values(action) as actions by user
| search "challenge","challenge","success"
```
**Detects:** Attackers exploiting user approval after repeated prompts.

---

### 3️⃣ MFA Bypass via Trusted Device
```spl
index=mfa
| search device_trusted=1 AND action=success
```
**Detects:** Approval without user intent, possibly compromised device.

---

### 4️⃣ MFA Token Replay Detection
```spl
index=mfa OR index=auth
| transaction user maxspan=10m
| search event="success" AND repeated_token=1
```
**Detects:** Same token used multiple times unusually fast.

---

### 5️⃣ Off-Hours MFA Success
```spl
index=mfa action=success
| where date_hour < 7 OR date_hour > 20
```
**Detects:** MFA approvals outside normal business hours.

---

### 6️⃣ Multiple Geolocations During MFA
```spl
index=mfa action=success
| iplocation src_ip
| stats dc(Country) as countries by user
| where countries > 1
```
**Detects:** Impossible travel combined with MFA success.

---

### 7️⃣ Cloud Conditional Access Bypass
```spl
index=cloud condition_access action=allow
| stats count by user, device, location
| where unusual_combination=1
```
**Detects:** Circumvention of conditional access rules.

---

### 8️⃣ MFA Approval from New Devices
```spl
index=mfa action=success
| search device_status="new"
```
**Detects:** Potential session hijacking or attacker device.

---

### 9️⃣ High-Risk Application MFA Bypass
```spl
index=cloud action=success
| search AppDisplayName IN ("AdminPortal","FinanceApp")
| stats count by user
```
**Detects:** MFA bypass on sensitive SaaS apps.

---

### 🔟 Sequential MFA Failure Then Success
```spl
index=mfa
| transaction user maxspan=10m
| search action="failure" AND action="success"
```
**Detects:** Attackers succeeding after multiple failures.

---

### 1️⃣1️⃣ Rare IP MFA Success
```spl
index=mfa action=success
| stats count by user src_ip
| where count < 2
```
**Detects:** MFA approval from previously unseen IPs.

---

## 🧠 Behavioral Indicators
- Rapid repeated MFA challenges  
- Success following unusual failure patterns  
- MFA approvals outside normal work hours or regions  
- New devices or IPs associated with MFA success  
- Sensitive application MFA bypass attempts  

---

## 🛡️ Response & Mitigation
- Force credential reset for affected accounts  
- Investigate source IP and device for compromise  
- Review conditional access policies  
- Enable MFA approval notifications for end-users  
- Correlate MFA events with authentication and endpoint logs  

---

## 📌 Summary

This file provides **advanced SPL searches for detecting MFA bypass behaviors** across:
- 🪟 Windows
- 🐧 Linux
- ☁️ Cloud environments

It enables SOC teams to **identify stealthy account compromises** even when MFA is implemented.

