# ✏️ File Modifications Monitoring (Windows & Linux)
Fundamental Searches for File Change Events

This file focuses on **monitoring file modifications** across **Windows and Linux systems**, using **basic searches** suitable for the *Fundamental Searches* level.  
Monitoring file changes helps detect **unauthorized edits, malware activity, configuration drift, and insider threats**.

---

## 🎯 Purpose
- Track **changes to critical system and application files**
- Detect **unauthorized or suspicious file modifications**
- Monitor **configuration changes**
- Support SOC investigations and auditing
- Enable proactive alerting

---

## 🖥️ Platforms Covered
- 🪟 Windows Servers & Workstations
- 🐧 Linux Servers & Endpoints
- ☁️ Cloud Storage Systems (optional logs)

---

## 📂 Common Log Sources

### 🪟 Windows
- Security Event Log  
  - EventID **4663** (Object Access)  
  - EventID **4656** (Handle Requested)  
- File system auditing logs
- PowerShell logs for file edits
- Application logs for configuration changes

### 🐧 Linux
- `/var/log/audit/audit.log` (auditd)
- `/var/log/syslog`
- File monitoring tools (`inotify`, `auditd`)
- Application-specific logs

---

## 🧾 Sample Logs

### 🪟 Windows – File Modified
```
2025-02-12 17:01:22 WIN-SRV01 EventID=4663 User=john.doe File=C:\Sensitive\report.xlsx Operation=Write
```

### 🪟 Windows – Handle Requested Before Modification
```
2025-02-12 17:03:10 WIN-SRV01 EventID=4656 User=john.doe File=C:\Sensitive\report.xlsx Operation=Write
```

### 🐧 Linux – File Modification via Auditd
```
Feb 12 17:10:33 server01 audit[1234]: PATH=/home/alice/confidential.txt OP=write USER=alice
```

### 🐧 Linux – Application Log
```
Feb 12 17:12:11 server01 app_log: File /etc/nginx/nginx.conf modified by process nginx
```

---

## 🔍 Fundamental Search Examples

### ✏️ File Modification Events
```spl
(EventID=4663 OR EventID=4656 OR "write") 
| table _time host user file process operation
```

### 🔎 Unauthorized or Sensitive File Modifications
```spl
| search file IN ("C:\\Sensitive\\*", "/home/*/confidential*", "/etc/nginx/*")
```

### 👤 User-Specific File Modifications
```spl
| stats count by user file
```

---

## 🚨 Detection Scenarios

### 🔁 Multiple Modifications by One User
```spl
| stats count by user
| where count > 10
```

### 🧨 Modifications to Critical System Files
```spl
| search file IN ("C:\\Windows\\System32\\*", "/etc/passwd", "/etc/ssh/sshd_config")
```

### 🌍 Modifications from Unusual Source
```spl
| search src_ip!=10.0.0.0/8
```

---

## 🛡️ Mitigation & Response
- Enable file system auditing
- Restrict write permissions to critical files
- Alert on critical or suspicious modifications
- Review modification history regularly
- Restore files from trusted backups if compromised

---

## 📌 Summary
This file provides **fundamental file modification monitoring** for:
- Windows file system auditing
- Linux auditd and inotify monitoring
- Detection of unauthorized or suspicious changes


