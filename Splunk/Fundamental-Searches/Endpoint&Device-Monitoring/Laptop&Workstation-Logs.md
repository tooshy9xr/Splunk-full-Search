# 💻🖥️ Laptop & Workstation Logs Monitoring  
Fundamental Searches for Endpoint Activity  
(Windows • Linux • macOS)

This file focuses on **monitoring laptop and workstation logs** across **end-user endpoints**, using **basic searches** suitable for the *Fundamental Searches* level.  
Endpoint log monitoring is essential for detecting **malware activity, user abuse, misconfigurations, data leakage, and early-stage attacks**.

---

## 🎯 Purpose
- Monitor **user activity on endpoints**
- Detect **malicious processes and scripts**
- Track **authentication and privilege usage**
- Identify **policy violations and misconfigurations**
- Support SOC investigations and endpoint incident response

---

## 🖥️ Platforms Covered

### 🪟 Windows Workstations
- Windows Event Logs (Security, System, Application)
- PowerShell logs
- Defender / EDR logs

### 🐧 Linux Workstations
- Syslog / journalctl
- Authentication logs
- Process and audit logs

### 🍎 macOS Laptops
- Unified logs
- Authentication and system logs
- Endpoint security logs

---

## 📂 Common Log Sources
- OS security and system logs
- Endpoint Detection & Response (EDR)
- Antivirus and anti-malware logs
- Application execution logs
- USB and peripheral logs

---

## 🧾 Sample Logs

### 🪟 Windows – User Login
```
2025-03-09 09:01:22 EventID=4624 User=john.doe LogonType=2
```

### 🪟 Windows – PowerShell Execution
```
2025-03-09 09:03:10 EventID=4104 ScriptBlock="Invoke-WebRequest http://malicious.site"
```

### 🐧 Linux – SSH Login
```
Mar 09 09:05:33 laptop01 sshd[1234]: Accepted password for alice from 10.0.0.15
```

### 🍎 macOS – Application Launch
```
2025-03-09 09:07:11 process=Terminal user=bob action=launch
```

---

## 🔍 Fundamental Search Examples

### 👤 User Logins
```spl
| search EventID=4624 OR "Accepted password"
| table _time user host source_ip
```

### 🧨 Suspicious Script Execution
```spl
| search ScriptBlock="*Invoke-WebRequest*" OR command="*curl*"
```

### 🧠 New or Rare Processes
```spl
| stats count by process
| where count < 2
```

### 🔌 USB Device Usage
```spl
| search EventID=2003 OR "USB device"
```

---

## 🚨 Detection Scenarios

### 🕵️ Suspicious User Activity
```spl
| search LogonType=10 OR LogonType=3
```

### 🧨 Malware or Living-off-the-Land Activity
```spl
| search process IN ("powershell.exe","cmd.exe","bash","python")
```

### ⚠️ Privilege Abuse
```spl
| search user IN ("admin","root") AND process!="approved_app"
```

---

## 🛡️ Mitigation & Response
- Enforce endpoint security policies
- Monitor PowerShell and script execution
- Restrict admin privileges
- Isolate compromised endpoints
- Correlate endpoint activity with network logs

---

## 📌 Summary
This file provides **fundamental monitoring of laptop and workstation logs** across:
- 🪟 Windows
- 🐧 Linux
- 🍎 macOS

It helps detect **endpoint-based threats, user abuse, and malware activity**.
