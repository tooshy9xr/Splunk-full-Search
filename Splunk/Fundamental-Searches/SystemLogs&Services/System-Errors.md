# ⚠️ System Errors (Windows & Linux)
Fundamental Searches for OS-Level Errors & Failures

This file focuses on **detecting system-level errors** across **Windows and Linux environments**, using **basic searches** suitable for the *Fundamental Searches* level.  
System errors often indicate **hardware issues, misconfigurations, crashes, or security-related failures**.

---

## 🎯 Purpose
- Monitor **critical OS errors**
- Detect **service and driver failures**
- Identify **kernel and hardware issues**
- Track **application crashes**
- Support operational troubleshooting and SOC investigations

---

## 🖥️ Platforms Covered
- 🪟 Windows Servers & Workstations
- 🐧 Linux Servers & Endpoints
- ☁️ Virtual Machines & Cloud Hosts

---

## 📂 Common Log Sources

### 🪟 Windows
- System Event Log  
  - EventID **41** (Kernel Power)
  - EventID **1001** (BugCheck)
  - EventID **6008** (Unexpected shutdown)
- Application Event Log

### 🐧 Linux
- `/var/log/syslog`
- `/var/log/messages`
- `dmesg`
- Kernel logs

---

## 🧾 Sample Logs

### 🪟 Windows – System Crash
```
2025-02-12 11:01:22 EventID=41 Source=Kernel-Power Host=WIN-SRV01 UnexpectedShutdown
```

### 🪟 Windows – Application Crash
```
2025-02-12 11:05:44 EventID=1000 Application=svchost.exe FaultingModule=ntdll.dll
```

---

### 🐧 Linux – Kernel Error
```
Feb 12 11:11:33 server01 kernel: BUG: unable to handle kernel NULL pointer dereference
```

### 🐧 Linux – Service Failure
```
Feb 12 11:14:21 server01 systemd[1]: nginx.service failed with result 'exit-code'
```

---

## 🔍 Fundamental Search Examples

### ⚠️ Critical System Errors
```spl
(EventID=41 OR EventID=1001 OR "kernel error")
```

### 🧨 Application Crashes
```spl
(EventID=1000) OR ("segfault")
```

### 🔄 Service Failures
```spl
(systemd "failed") OR (EventID=7031)
```

---

## 🚨 Detection Scenarios

### 💥 Repeated System Crashes
```spl
(EventID=41)
| stats count by host
| where count > 2
```

### 🔁 Frequent Service Restarts
```spl
(systemd "failed")
| stats count by service host
| where count > 3
```

### 🖥️ Hardware Error Indicators
```spl
("I/O error" OR "disk error" OR "memory error")
```

---

## 🛡️ Mitigation & Response
- Review system and hardware logs
- Patch OS and drivers
- Monitor disk and memory health
- Restart or isolate failing services
- Escalate persistent kernel errors

---

## 📌 Summary
This file provides **fundamental system error monitoring** for:
- Windows OS and application errors
- Linux kernel and service failures
- Stability and reliability analysis
