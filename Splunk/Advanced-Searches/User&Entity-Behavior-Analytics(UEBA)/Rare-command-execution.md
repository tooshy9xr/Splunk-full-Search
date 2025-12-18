# 🧨 Rare Command Execution  
Advanced Command-Line Anomaly Detection  
(Windows • Linux • Cloud)

---

## 📁 Folder Context (Professional Description)

The **Rare Command Execution** module focuses on detecting **commands that are executed infrequently or for the first time** by a user, host, or across the environment.  
This technique is a **high-signal behavioral detection** used in advanced threat hunting, UEBA, and post-compromise analysis.

Attackers often rely on **native system commands (LOLBins)** that blend in with normal activity but appear **rare in historical baselines**.

---

## 🎯 File Objective

`Rare-command-execution.md` is designed to:
- Identify **first-time or low-frequency commands**
- Detect **living-off-the-land (LOLBin) abuse**
- Highlight **post-authentication attacker activity**
- Reduce false positives using behavioral rarity
- Support advanced SOC investigations

---

## 🧩 Threat Context

Mapped to **MITRE ATT&CK**:
- T1059 – Command and Scripting Interpreter  
- T1106 – Native API  
- T1082 – System Information Discovery  
- TA0002 – Execution  

Attackers often:
- Use built-in tools (`cmd.exe`, `powershell`, `bash`)
- Execute recon commands rarely used by users
- Avoid dropping binaries
- Chain commands after initial access

---

## 📊 Data Sources

| Source | Description |
|------|------------|
| Windows Security Logs | EventID 4688 |
| Sysmon | Process creation |
| Linux Audit / Bash Logs | Command history |
| EDR Logs | Process execution |
| Cloud Workload Logs | VM command execution |
| PowerShell Logs | Script block logging |

---

## 🔍 Advanced Detection Patterns (15 Scenarios)

---

### 1️⃣ First-Time Command Per User
```spl
| stats count by user command
| where count = 1
```
📌 **Detects:** Commands never executed before by a user.

---

### 2️⃣ Rare Command Across Environment
```spl
| stats count by command
| where count < 5
```
📌 **Detects:** Globally rare commands.

---

### 3️⃣ Rare Admin Command by Non-Admin
```spl
| search admin=false
| stats count by user command
| where count < 3
```
📌 **Detects:** Privilege abuse attempts.

---

### 4️⃣ LOLBins Executed Infrequently (Windows)
```spl
| search process IN ("powershell.exe","cmd.exe","wmic.exe","certutil.exe")
| stats count by user process
| where count < 3
```
📌 **Detects:** Living-off-the-land abuse.

---

### 5️⃣ Reconnaissance Commands (Linux)
```spl
| search cmd IN ("whoami","id","uname","ifconfig","netstat")
| stats count by user cmd
| where count < 2
```
📌 **Detects:** Early attacker recon.

---

### 6️⃣ Script Interpreters Rare Usage
```spl
| search process IN ("python","perl","ruby","node")
| stats count by user process
| where count < 2
```
📌 **Detects:** Script-based payload execution.

---

### 7️⃣ Rare Command with Network Connection
```spl
| transaction process
```
📌 **Detects:** Command execution followed by outbound traffic.

---

### 8️⃣ Rare Command Executed from Temp Paths
```spl
| search process_path IN ("*\\Temp\\*","*/tmp/*")
```
📌 **Detects:** Suspicious execution locations.

---

### 9️⃣ Encoded or Obfuscated Commands
```spl
| search command="*base64*" OR command="*-enc*"
```
📌 **Detects:** Obfuscation attempts.

---

### 🔟 Rare Command After Login
```spl
| transaction user maxspan=5m
```
📌 **Detects:** Post-authentication attacker actions.

---

### 1️⃣1️⃣ Rare Commands Across Multiple Hosts
```spl
| stats dc(host) by command
| where dc(host) > 3
```
📌 **Detects:** Lateral movement automation.

---

### 1️⃣2️⃣ Rare Cloud VM Command Execution
```spl
index=cloud_vm
| stats count by user command
| where count < 2
```
📌 **Detects:** Abuse of cloud compute instances.

---

### 1️⃣3️⃣ Rare PowerShell Cmdlets
```spl
| stats count by user cmdlet
| where count < 2
```
📌 **Detects:** Advanced PowerShell misuse.

---

### 1️⃣4️⃣ Rare Commands with Elevated Privileges
```spl
| search integrity_level="High"
| stats count by user command
```
📌 **Detects:** Privilege escalation behavior.

---

### 1️⃣5️⃣ Rare Command Chaining
```spl
| search command="*&&*" OR command="*;*"
```
📌 **Detects:** Complex attacker execution chains.

---

## 🧠 Behavioral Indicators Summary
- First-time or low-frequency commands
- LOLBins and native tool abuse
- Reconnaissance activity
- Obfuscated or encoded execution
- Rare commands combined with privilege or network use

---

## 🛡️ Response & Mitigation
- Validate business justification
- Investigate parent processes
- Correlate with login and network activity
- Restrict interpreter usage
- Apply application control policies

---

## 📌 Final Summary

This module delivers **high-fidelity detection of rare command execution** across:
- 🪟 Windows
- 🐧 Linux
- ☁️ Cloud workloads

It is a **cornerstone technique for advanced threat hunting, UEBA, and post-compromise detection**.
