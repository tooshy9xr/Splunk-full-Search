# ⚙️🖥️ System Configuration Changes  
Fundamental Searches for Host Configuration Modifications  
(Windows • Linux • macOS)

This file focuses on **monitoring system configuration changes** across **endpoints and servers**, using **basic searches** suitable for the *Fundamental Searches* level.  
Configuration change monitoring is critical for detecting **unauthorized modifications, persistence techniques, misconfigurations, and privilege abuse**.

---

## 🎯 Purpose
- Track **OS and system configuration changes**
- Detect **unauthorized registry, file, or service modifications**
- Monitor **startup and persistence mechanisms**
- Identify **security control tampering**
- Support SOC investigations and system integrity monitoring

---

## 🖥️ Platforms Covered

### 🪟 Windows
- Registry modification events
- Group Policy changes
- Service and startup configuration logs
- Windows Security & System Event Logs

### 🐧 Linux
- Configuration file changes (`/etc`)
- Systemd service modifications
- Auditd configuration events

### 🍎 macOS
- System preference and profile changes
- LaunchAgents & LaunchDaemons modifications
- Unified system logs

---

## 📂 Common Log Sources
- OS security and system logs
- Audit frameworks (auditd, Windows Auditing)
- Configuration management logs
- Endpoint Detection & Response (EDR)

---

## 🧾 Sample Logs

### 🪟 Windows – Registry Change
```
2025-03-13 13:01:22 EventID=4657 RegistryKey=HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

### 🪟 Windows – Service Configuration Change
```
2025-03-13 13:03:10 EventID=7040 ServiceName=RemoteRegistry StartType=Auto
```

### 🐧 Linux – System Config File Modified
```
Mar 13 13:05:33 host01 auditd: FILE=/etc/ssh/sshd_config action=modified
```

### 🍎 macOS – LaunchDaemon Added
```
2025-03-13 13:07:11 user=root path=/Library/LaunchDaemons/com.backdoor.plist
```

---

## 🔍 Fundamental Search Examples

### ⚙️ Configuration Changes
```spl
| search EventID=4657 OR "modified" OR "LaunchDaemon"
| table _time user host object action
```

### 🚨 Startup & Persistence Changes
```spl
| search "RunKey" OR "LaunchAgent" OR "cron"
```

### 👤 Changes by Non-Admin Users
```spl
| search user!="admin" AND action="modified"
```

### 🔁 Frequent Configuration Modifications
```spl
| stats count by user object
| where count > 5
```

---

## 🚨 Detection Scenarios

### 🧨 Security Control Tampering
```spl
| search object IN ("firewall","antivirus","defender","audit")
```

### ⚠️ Changes Outside Maintenance Window
```spl
| where date_hour < 8 OR date_hour > 18
```

### 🕵️ Rare or Unknown Configuration Changes
```spl
| stats count by object
| where count < 2
```

---

## 🛡️ Mitigation & Response
- Restrict configuration change permissions
- Enable file and registry auditing
- Implement configuration baselines
- Alert on unauthorized modifications
- Roll back changes using backups or snapshots

---

## 📌 Summary
This file provides **fundamental monitoring of system configuration changes** across:
- 🪟 Windows
- 🐧 Linux
- 🍎 macOS

It helps detect **unauthorized system changes, persistence techniques, and misconfigurations**.


