# ⚡ Executable Launches Monitoring (Windows & Linux)
Fundamental Searches for Process and Executable Activity

This file focuses on **monitoring executable launches** across **Windows and Linux systems**, using **basic searches** suitable for the *Fundamental Searches* level.  
Monitoring executable launches helps detect **malware execution, unauthorized applications, privilege escalation, and suspicious activity**.

---

## 🎯 Purpose
- Track **new process creation**
- Detect **suspicious or unauthorized executables**
- Monitor **system and application activity**
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
- Security Event Log (EventID **4688** – New Process Creation)  
- Sysmon logs  
- Application logs  
- Task Scheduler logs  

### 🐧 Linux
- `/var/log/syslog`  
- Audit logs (`auditd`)  
- Process accounting (`acct`)  
- Application logs  

---

## 🧾 Sample Logs

### 🪟 Windows – Executable Launch
```
2025-02-12 20:01:22 WIN-SRV01 EventID=4688 User=john.doe NewProcessName=C:\Windows\System32\notepad.exe
```

### 🪟 Windows – Suspicious Executable
```
2025-02-12 20:03:10 WIN-SRV01 EventID=4688 User=alice NewProcessName=C:\Temp\malware.exe
```

### 🐧 Linux – Executable Launch
```
Feb 12 20:05:33 server01 audit[1234]: USER=alice CMD=/usr/local/bin/cleanup.sh
```

### 🐧 Linux – Suspicious Executable
```
Feb 12 20:07:11 server01 audit[5678]: USER=root CMD=/tmp/malware
```

---

## 🔍 Fundamental Search Examples

### ⚡ New Executable Launches
```spl
EventID=4688 OR "CMD"
| table _time host user NewProcessName process
```

### 🔎 Suspicious Executables
```spl
| search NewProcessName IN ("C:\\Temp\\*", "/tmp/*", "*malware*")
```

### 👤 User-Specific Executable Monitoring
```spl
| stats count by user NewProcessName
```

---

## 🚨 Detection Scenarios

### 🔁 Multiple Executables Launched by One User
```spl
| stats count by user
| where count > 5
```

### 🧨 Executables from Temporary Directories
```spl
| search NewProcessName IN ("C:\\Temp\\*", "/tmp/*")
```

### ⚡ Privilege Escalation Indicators
```spl
| search NewProcessName IN ("C:\\Windows\\System32\\cmd.exe", "/bin/sudo")
```

---

## 🛡️ Mitigation & Response
- Restrict execution paths for sensitive directories
- Monitor high-risk users and processes
- Alert on executables from unusual locations
- Validate and sandbox unknown executables
- Investigate repeated or suspicious process launches

---

## 📌 Summary
This file provides **fundamental executable launch monitoring** for:
- Windows process creation and Sysmon logs
- Linux audit and process logs
- Detection of unauthorized or malicious executable activity

