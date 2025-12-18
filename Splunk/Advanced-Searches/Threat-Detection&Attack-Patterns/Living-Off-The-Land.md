# 🧬 Living Off The Land (LOTL) Detection  
Advanced Native Tool Abuse Analytics  
(Windows • Linux • Cloud)

---

## 📁 Folder Context (Professional Description)

The **Living Off The Land (LOTL)** module detects **attacker abuse of legitimate, built-in system tools** instead of deploying custom malware.  
This technique is widely used by **advanced threat actors** to evade antivirus, reduce forensic artifacts, and blend into normal administrative activity.

LOTL is a **core execution and post-exploitation technique** in modern attacks.

---

## 🎯 File Objective

`Living-Off-The-Land.md` is designed to:
- Detect abuse of **native OS utilities and binaries**
- Identify **low-noise attacker activity**
- Correlate execution, privilege, and network behavior
- Support advanced threat hunting and IR workflows
- Reduce false positives using behavioral context

---

## 🧩 Threat Context

Mapped to **MITRE ATT&CK**:
- T1059 – Command and Scripting Interpreter  
- T1106 – Native API  
- T1218 – Signed Binary Proxy Execution  
- TA0002 – Execution  
- TA0008 – Lateral Movement  

Attackers often:
- Avoid dropping malware
- Abuse trusted binaries (LOLBins)
- Execute encoded or chained commands
- Blend with admin behavior

---

## 📊 Data Sources

| Source | Description |
|------|------------|
| Windows Security Logs | EventID 4688 |
| Sysmon | Process creation |
| Linux Audit Logs | Bash, sudo, auditd |
| PowerShell Logs | Script block logging |
| Cloud VM Logs | Remote command execution |
| EDR Telemetry | Process ancestry |

---

## 🔍 Advanced Detection Patterns (18 Scenarios)

---

### 🪟 Windows LOLBins

### 1️⃣ PowerShell Abuse
```spl
process="powershell.exe"
```
📌 Encoded, hidden, or network-enabled execution.

---

### 2️⃣ Certutil File Download
```spl
process="certutil.exe" command="*-urlcache*"
```
📌 Payload retrieval using trusted binary.

---

### 3️⃣ WMIC Remote Execution
```spl
process="wmic.exe"
```
📌 Lateral movement via WMI.

---

### 4️⃣ Rundll32 Execution
```spl
process="rundll32.exe"
```
📌 DLL-based execution abuse.

---

### 5️⃣ Mshta Script Execution
```spl
process="mshta.exe"
```
📌 HTML/JS-based malware execution.

---

### 🐧 Linux LOLBins

### 6️⃣ Curl / Wget Payload Download
```spl
process IN ("curl","wget")
```
📌 External payload retrieval.

---

### 7️⃣ Bash Reverse Shell Patterns
```spl
command="*/dev/tcp/*"
```
📌 Interactive shell backdoors.

---

### 8️⃣ Sudo Abuse
```spl
process="sudo"
```
📌 Privilege escalation attempts.

---

### 9️⃣ Base64 Encoded Commands
```spl
command="*base64*"
```
📌 Obfuscation techniques.

---

### ☁️ Cloud & Cross-Platform

### 🔟 Cloud VM Command Execution
```spl
index=cloud_vm action=execute
```
📌 Abuse of cloud management channels.

---

### 1️⃣1️⃣ LOLBins + Network Connections
```spl
| transaction process maxspan=2m
```
📌 Execution followed by outbound traffic.

---

### 1️⃣2️⃣ LOLBins from Temp Directories
```spl
process_path IN ("*\\Temp\\*","*/tmp/*")
```
📌 Suspicious execution paths.

---

### 1️⃣3️⃣ LOLBins by Non-Admin Users
```spl
admin=false
```
📌 Unusual privilege context.

---

### 1️⃣4️⃣ LOLBins After Login
```spl
| transaction user maxspan=5m
```
📌 Post-authentication attacker behavior.

---

### 1️⃣5️⃣ Rare LOLBin Usage
```spl
| stats count by user process
| where count < 3
```
📌 Behavioral rarity.

---

### 1️⃣6️⃣ Chained LOLBin Execution
```spl
command="*&&*" OR command="*;*"
```
📌 Complex execution logic.

---

### 1️⃣7️⃣ Encoded PowerShell
```spl
command="*-enc*"
```
📌 Obfuscation and evasion.

---

### 1️⃣8️⃣ LOLBins Used for Persistence
```spl
process IN ("schtasks.exe","crontab")
```
📌 Scheduled task abuse.

---

## 🧠 Behavioral Indicators Summary
- Native binary execution
- Obfuscated or encoded commands
- Network activity after execution
- Unusual execution paths
- Privilege context mismatch
- Cross-host or cloud abuse

---

## 🛡️ Response & Mitigation
- Investigate parent-child process chains
- Block unnecessary LOLBins
- Enforce script execution policies
- Apply application control
- Correlate with authentication events

---

## 📌 Final Summary

This module provides **high-confidence detection of Living-Off-The-Land abuse** across:
- 🪟 Windows
- 🐧 Linux
- ☁️ Cloud environments

It is a **critical advanced detection capability** for modern SOCs and threat hunters.

