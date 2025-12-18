# 🔁 Persistence Technique Detection  
Advanced Post-Compromise Persistence Analytics  
(Windows • Linux • Cloud)

---

## 📁 Folder Context (Professional Description)

The **Persistence Technique Detection** module focuses on identifying **mechanisms attackers use to maintain long-term access** after initial compromise.  
Persistence techniques are designed to **survive reboots, credential resets, and partial cleanup efforts**, making them a critical detection area for advanced SOCs.

This module emphasizes **behavioral and configuration-based detection**, not just static indicators.

---

## 🎯 File Objective

`Persistence-technique-detection.md` is designed to:
- Detect **unauthorized persistence mechanisms**
- Identify **registry, scheduled task, service, and startup abuse**
- Correlate persistence actions with prior compromise indicators
- Support threat hunting and incident response
- Reduce dwell time of attackers

---

## 🧩 Threat Context

Mapped to **MITRE ATT&CK**:
- TA0003 – Persistence  
- T1053 – Scheduled Task / Job  
- T1547 – Boot or Logon Autostart  
- T1543 – Create or Modify System Process  
- T1098 – Account Manipulation  

Attackers often:
- Use legitimate system features
- Create stealthy persistence hooks
- Combine multiple persistence methods
- Hide in scheduled or rarely audited locations

---

## 📊 Data Sources

| Source | Description |
|------|------------|
| Windows Security Logs | Services, tasks, registry |
| Sysmon | Startup & process creation |
| Linux Audit Logs | Cron, systemd |
| Cloud IAM Logs | Account & key persistence |
| Endpoint EDR | Startup artifacts |
| Configuration Logs | System changes |

---

## 🔍 Advanced Detection Patterns (20 Scenarios)

---

## 🪟 Windows Persistence

### 1️⃣ New Scheduled Task Creation
```spl
EventID=4698
```
📌 Scheduled task used for re-execution.

---

### 2️⃣ Registry Run Key Modification
```spl
registry_path="*\\Run"
```
📌 Auto-start registry abuse.

---

### 3️⃣ New Windows Service Installed
```spl
EventID=7045
```
📌 Service-based persistence.

---

### 4️⃣ Startup Folder Execution
```spl
process_path="*\\Startup\\*"
```
📌 Logon-triggered execution.

---

### 5️⃣ WMI Event Subscription
```spl
process="wmic.exe"
```
📌 Fileless persistence.

---

---

## 🐧 Linux Persistence

### 6️⃣ New Cron Job Creation
```spl
sourcetype=cron action=created
```
📌 Scheduled persistence.

---

### 7️⃣ Systemd Service Modification
```spl
process="systemctl"
```
📌 Persistent services.

---

### 8️⃣ Bash Profile Modification
```spl
file IN (".bashrc",".profile",".bash_profile")
```
📌 User-level persistence.

---

### 9️⃣ SSH Authorized Keys Change
```spl
file="authorized_keys"
```
📌 Persistent remote access.

---

### 🔟 SUID Binary Creation
```spl
permissions="*s*"
```
📌 Privilege-based persistence.

---

---

## ☁️ Cloud Persistence

### 1️⃣1️⃣ New IAM User or Role Creation
```spl
action=CreateUser OR action=CreateRole
```
📌 Identity persistence.

---

### 1️⃣2️⃣ Access Key Creation
```spl
action=CreateAccessKey
```
📌 Long-term API access.

---

### 1️⃣3️⃣ Cloud VM Startup Script Modification
```spl
startup_script=*
```
📌 Execution on boot.

---

### 1️⃣4️⃣ New OAuth / App Registration
```spl
action=AddApplication
```
📌 SaaS persistence.

---

### 1️⃣5️⃣ Cloud Function Deployment
```spl
action=CreateFunction
```
📌 Serverless persistence.

---

---

## 🔗 Cross-Platform Indicators

### 1️⃣6️⃣ Persistence After Login
```spl
| transaction user maxspan=15m
```
📌 Post-compromise setup.

---

### 1️⃣7️⃣ Persistence from Temp Directories
```spl
process_path IN ("*\\Temp\\*","*/tmp/*")
```
📌 Untrusted locations.

---

### 1️⃣8️⃣ Rare Persistence Mechanism
```spl
| stats count by user action
| where count < 2
```
📌 Behavioral anomaly.

---

### 1️⃣9️⃣ Persistence by Non-Admin User
```spl
admin=false
```
📌 Privilege misuse.

---

### 2️⃣0️⃣ Multiple Persistence Methods Used
```spl
| stats dc(persistence_type) by host
| where dc(persistence_type) > 1
```
📌 Defense-in-depth bypass.

---

## 🧠 Behavioral Indicators Summary
- Startup and auto-run modifications
- Scheduled execution mechanisms
- Service and daemon abuse
- Identity and credential persistence
- Fileless persistence techniques

---

## 🛡️ Response & Mitigation
- Remove unauthorized persistence mechanisms
- Rotate credentials and keys
- Reimage compromised hosts if needed
- Monitor persistence locations continuously
- Correlate with initial access and C2 activity

---

## 📌 Final Summary

This module provides **comprehensive detection of persistence techniques** across:
- 🪟 Windows
- 🐧 Linux
- ☁️ Cloud environments

It is a **critical advanced detection capability** for eliminating attacker footholds and reducing dwell time.

