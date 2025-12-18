# 🧩 Kill Chain Reconstruction
## Linux • Windows • Cloud (Splunk Advanced Hunting)

This document focuses on **reconstructing a full attacker kill chain** using **Splunk**, correlating events across **Linux hosts, Windows systems, and Cloud platforms (AWS, Azure, GCP)**.

It is designed for:
- SOC Analysts (Tier 2 / Tier 3)
- Threat Hunters
- Incident Responders
- Splunk Mastery – Advanced Detection & Investigation

---

## 🎯 Objectives
- Reconstruct attacker activity chronologically
- Correlate identity, endpoint, and cloud events
- Identify attack entry point and blast radius
- Validate attacker techniques across the kill chain
- Support post-incident analysis and reporting

---

## 🧠 Kill Chain Phases

| Phase | Description |
|------|------------|
| Reconnaissance | Environment discovery |
| Initial Access | First foothold |
| Execution | Malicious command execution |
| Privilege Escalation | Elevated access |
| Lateral Movement | Host-to-host spread |
| Command & Control | External communication |
| Exfiltration | Data theft |
| Impact | Destruction or disruption |

---

## ⏱️ Timeline Reconstruction (Core Technique)

### 🔗 Unified Event Timeline
```spl
index IN (linux_logs, windows_logs, cloud_logs)
| eval normalized_user=coalesce(user, Account_Name, principalEmail)
| eval normalized_host=coalesce(host, ComputerName, resource)
| sort _time
| table _time normalized_user normalized_host action eventName CommandLine sourceIPAddress
```

Purpose:
- Build a **single chronological view**
- Identify pivot points
- Trace attacker progression

---

## 🟡 RECONNAISSANCE

### 🔍 Discovery Commands (Linux & Windows)
```spl
index IN (linux_logs, windows_logs)
(command IN ("whoami","id","uname","hostname","net user","ipconfig","ifconfig"))
| stats count by user host command
```

### 🔍 Cloud Permission Enumeration
```spl
index=cloud_logs
(eventName IN ("ListBuckets","GetIamPolicy","ListRoleAssignments"))
| stats count by user sourceIPAddress
```

---

## 🔴 INITIAL ACCESS

### 🔑 Authentication Events
```spl
index IN (linux_logs, windows_logs, cloud_logs)
(message="Accepted*" OR EventCode=4624 OR eventName="ConsoleLogin")
| table _time user host sourceIPAddress
```

Goal:
- Identify **first successful access**
- Detect **credential abuse**

---

## 🟠 EXECUTION

### ▶️ Process Creation
```spl
index=windows_logs EventCode=4688
| table _time host user NewProcessName CommandLine
```

### ▶️ Linux Command Execution
```spl
index=linux_logs
| table _time host user command
```

---

## 🟣 PRIVILEGE ESCALATION

### ⬆️ Elevated Privileges
```spl
index IN (linux_logs, windows_logs)
(command="sudo*" OR EventCode=4672)
| table _time host user command Privileges
```

### ⬆️ Cloud Role Changes
```spl
index=cloud_logs
(eventName IN ("AttachUserPolicy","SetIamPolicy","AddMemberToRole"))
| table _time user target resource
```

---

## 🔵 LATERAL MOVEMENT

### 🔁 Remote Access & Tooling
```spl
index IN (linux_logs, windows_logs)
(command IN ("ssh","scp") OR CommandLine="*psexec*")
| table _time user host command CommandLine
```

---

## 🟣 COMMAND & CONTROL (C2)

### 📡 Suspicious Outbound Traffic
```spl
index IN (linux_logs, windows_logs)
(dest_port IN (4444,1337,9001))
| stats count by host dest_ip dest_port
```

### 📡 Cloud Automation Abuse
```spl
index=cloud_logs
| stats count by user userAgent
| where count > 500
```

---

## 🔥 EXFILTRATION

### 📦 Host-Based Exfiltration
```spl
index IN (linux_logs, windows_logs)
(command IN ("scp","rsync","curl","wget"))
| stats count by user host
| where count > 100
```

### 📦 Cloud Storage Exfiltration
```spl
index=cloud_logs
(eventName IN ("GetObject","Read","storage.objects.get"))
| stats count(object) AS files by user
| where files > 100
```

---

## 💣 IMPACT

### ❌ Destructive Actions
```spl
index=cloud_logs
(eventName IN ("DeleteObject","DeleteBucket","storage.objects.delete"))
| table _time user resource
```

---

## 🧠 Analyst Reconstruction Notes
- Identify **first compromise timestamp**
- Track privilege changes carefully
- Validate whether actions align with business activity
- Identify persistence mechanisms
- Estimate data loss volume
- Determine affected systems and accounts

---

## 🧠 MITRE ATT&CK Mapping

| Phase | Technique |
|------|----------|
| Reconnaissance | T1087, T1046 |
| Initial Access | T1078 |
| Execution | T1059 |
| Privilege Escalation | T1068 |
| Lateral Movement | T1021 |
| Command & Control | T1071 |
| Exfiltration | T1041 |
| Impact | T1485 |

---

## 📌 Summary
This file enables **full kill chain reconstruction** by correlating **endpoint, identity, and cloud telemetry** in Splunk, giving SOC teams **deep visibility** into attacker behavior and incident scope.

