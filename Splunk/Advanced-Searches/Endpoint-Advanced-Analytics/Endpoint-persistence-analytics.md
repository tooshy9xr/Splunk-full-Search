# 🔒 Endpoint Persistence Analytics
## Endpoint Advanced Analytics (Windows • Linux • macOS)

This document focuses on **endpoint persistence analytics**, detecting techniques attackers use to **maintain long-term access** to compromised systems across reboots, logouts, and updates.

Persistence is a core post-exploitation objective and is commonly combined with:
- Credential theft
- Privilege escalation
- Lateral movement
- Data exfiltration

Designed for:
- SOC Tier 2 / Tier 3 Analysts
- Endpoint Security Engineers
- Threat Hunters
- Detection Engineers
- Splunk Mastery – Advanced Searches

---

## 🎯 Objectives
- Detect common and stealthy persistence mechanisms
- Identify abuse of OS-native auto-start features
- Correlate persistence with execution chains
- Reduce false positives via context and rarity
- Support rapid containment and remediation

---

## 🧠 What Is Endpoint Persistence?

Endpoint persistence includes any method that:
- Re-executes malicious code automatically
- Survives system restarts or user logins
- Blends into legitimate OS mechanisms
- Is difficult to notice without behavioral context

> If attackers get back in after reboot — persistence succeeded.

---

## 🧠 Common Persistence Categories

| Category | Examples |
|--------|----------|
| Startup Items | Registry Run keys, Login Items |
| Services & Daemons | Windows services, systemd |
| Scheduled Tasks | Task Scheduler, cron |
| WMI & Event Triggers | WMI event consumers |
| Boot & Kernel | Drivers, kernel modules |
| Script-Based | PowerShell profiles, shell rc files |

---

## 🟡 BASELINE PERSISTENCE BEHAVIOR

### 🔍 Normal Auto-Start Artifacts
```spl
index=endpoint_logs
| stats count by host persistence_type
```

Purpose:
- Understand expected persistence mechanisms
- Identify anomalies later

---

## 🔴 WINDOWS PERSISTENCE DETECTIONS

### 🧾 Registry Run Keys
```spl
index=endpoint_logs
| search persistence_type="registry_run"
| table _time host user registry_path value_name value_data
```

Purpose:
- Detect auto-start malware
- Identify suspicious startup entries

---

### ⚙️ Suspicious Windows Services
```spl
index=endpoint_logs
| search persistence_type="service"
| search service_start_type="auto"
| table _time host service_name service_path user
```

Purpose:
- Detect malicious services
- Identify masquerading binaries

---

### ⏰ Scheduled Task Abuse
```spl
index=endpoint_logs
| search persistence_type="scheduled_task"
| table _time host task_name task_action user
```

Purpose:
- Detect stealthy re-execution
- Identify time- or event-based persistence

---

## 🔵 LINUX PERSISTENCE DETECTIONS

### 🐧 systemd Service Creation
```spl
index=endpoint_logs
| search persistence_type="systemd"
| table _time host service_name service_path user
```

Purpose:
- Detect malicious daemons
- Identify unauthorized service installs

---

### ⏱️ Cron Job Abuse
```spl
index=endpoint_logs
| search persistence_type="cron"
| table _time host user cron_entry
```

Purpose:
- Detect recurring malicious execution
- Identify stealthy scheduled persistence

---

### 🧪 Shell Profile Abuse
```spl
index=endpoint_logs
| search persistence_type="shell_profile"
| table _time host user file_path
```

Purpose:
- Detect login-triggered script execution
- Identify fileless persistence

---

## 🟣 macOS PERSISTENCE DETECTIONS

### 🍎 LaunchAgents & LaunchDaemons
```spl
index=endpoint_logs
| search persistence_type IN ("launch_agent","launch_daemon")
| table _time host plist_path program_args user
```

Purpose:
- Detect macOS auto-start abuse
- Identify hidden background execution

---

### 🔐 Login Items Abuse
```spl
index=endpoint_logs
| search persistence_type="login_item"
| table _time host user item_path
```

Purpose:
- Detect user-level persistence
- Identify credential-based re-entry

---

## 🔥 RARE OR FIRST-SEEN PERSISTENCE

### 🎯 Uncommon Persistence Artifacts
```spl
index=endpoint_logs
| stats count by persistence_type artifact_path
| where count < 3
```

Purpose:
- Detect rare or novel persistence
- Catch targeted attacks

---

## 🔗 PERSISTENCE + EXECUTION CHAIN CORRELATION

### 🧬 Persistence After Script or LOLBin Execution
```spl
index=endpoint_logs
| table _time host user parent_process process_name persistence_type artifact_path
```

Purpose:
- Tie persistence to execution origin
- Increase confidence of maliciousness

---

## 🔗 PERSISTENCE + NETWORK CORRELATION

### 🌐 Auto-Start Process Contacting Network
```spl
index IN (endpoint_logs, network_logs)
| table _time host process_name dest_ip dest_port
```

Purpose:
- Detect persistent C2 connections
- Confirm active compromise

---

## ⏱️ PERSISTENCE TIMELINE

```spl
index=endpoint_logs
| sort _time
| table _time host user persistence_type artifact_path process_name
```

Purpose:
- Reconstruct persistence setup sequence
- Support forensic investigations

---

## 🛡️ SOC RESPONSE & ENDPOINT IR NOTES
- Isolate affected host
- Remove persistence artifacts safely
- Validate binary integrity and signatures
- Reset credentials used on the host
- Hunt for lateral movement
- Monitor system post-cleanup for re-creation

---

## 🧠 MITRE ATT&CK Mapping

| Technique | Description |
|---------|-------------|
| T1547 | Boot or Logon Autostart Execution |
| T1053 | Scheduled Task/Job |
| T1543 | Create or Modify System Process |
| T1546 | Event Triggered Execution |
| T1059 | Command and Scripting Interpreter |

---

## 📌 Summary
This file provides **advanced endpoint persistence analytics** that enable SOC and endpoint security teams to detect **long-term attacker footholds** by monitoring **auto-start mechanisms, services, scheduled tasks, and OS-native persistence features** across **Windows, Linux, and macOS**.

Persistence is how attacks survive —  
analytics is how you remove them.

