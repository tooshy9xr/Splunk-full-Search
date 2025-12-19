# 🧬 Process Lineage Tracking
## Endpoint Advanced Analytics (Windows • Linux • macOS)

This document focuses on **process lineage tracking**, a critical endpoint detection technique that analyzes **parent–child process relationships** to uncover **malware execution, living-off-the-land attacks, privilege escalation, and post-exploitation activity**.

Process lineage answers the most important endpoint question:
> **“How did this process start?”**

Designed for:
- SOC Tier 2 / Tier 3 Analysts
- Endpoint Security Engineers
- Threat Hunters
- Detection Engineers
- Splunk Mastery – Advanced Searches

---

## 🎯 Objectives
- Track parent-child process relationships
- Detect abnormal process spawning behavior
- Identify LOLBins and abuse of native tools
- Reconstruct attack execution chains
- Support endpoint-focused incident response

---

## 🧠 What Is Process Lineage?

Process lineage describes:
- Parent process → Child process → Grandchild process
- Execution context (user, integrity level)
- Command-line inheritance
- Execution timing and sequence

Attackers often hide by:
- Launching malware from trusted processes
- Abusing scripting engines and shells
- Chaining legitimate tools together

> Malware rarely starts from nothing — it has a parent.

---

## 🧠 Common Data Sources

| Platform | Logs |
|-------|------|
| Windows | Sysmon, Security (4688), EDR |
| Linux | auditd, syslog, EDR |
| macOS | Unified Logs, EDR |

Assume normalized fields:
- `process_name`
- `parent_process`
- `command_line`
- `user`
- `host`
- `process_id`
- `parent_process_id`

---

## 🟡 BASELINE NORMAL PROCESS LINEAGE

### 🔍 Common Parent → Child Relationships
```spl
index=endpoint_logs
| stats count by parent_process process_name
```

Purpose:
- Establish expected execution chains
- Identify unusual relationships later

---

## 🔴 SUSPICIOUS PARENT → CHILD SPAWNS

### 🚨 Office Apps Spawning Scripts
```spl
index=endpoint_logs
| search parent_process IN ("winword.exe","excel.exe","powerpnt.exe")
| search process_name IN ("powershell.exe","cmd.exe","wscript.exe","cscript.exe")
| table _time host user parent_process process_name command_line
```

Purpose:
- Detect macro-based malware
- Identify initial access vectors

---

## 🟠 SCRIPTING ENGINE ABUSE

### 🧪 PowerShell Spawned by Unusual Parents
```spl
index=endpoint_logs
| search process_name="powershell.exe"
| search parent_process NOT IN ("explorer.exe","services.exe","taskeng.exe")
| table _time host user parent_process command_line
```

Purpose:
- Detect living-off-the-land abuse
- Identify fileless malware

---

## 🔵 CHAINED LOLBIN EXECUTION

### 🔗 Multi-Step Execution Chains
```spl
index=endpoint_logs
| stats values(process_name) AS chain by process_id parent_process_id host
```

Purpose:
- Identify complex attack chains
- Detect stealthy post-exploitation behavior

---

## 🟣 PRIVILEGE ESCALATION INDICATORS

### ⬆️ High-Privilege Processes from User Context
```spl
index=endpoint_logs
| search integrity_level="High"
| search parent_process IN ("cmd.exe","powershell.exe")
| table _time host user parent_process process_name
```

Purpose:
- Detect privilege escalation attempts
- Identify UAC bypass techniques

---

## 🔥 RARE PROCESS LINEAGE (OUTLIERS)

### 🧬 Uncommon Parent–Child Relationships
```spl
index=endpoint_logs
| stats count by parent_process process_name
| where count < 3
```

Purpose:
- Detect rare or first-seen execution paths
- Identify early-stage attacks

---

## 🧠 PROCESS LINEAGE + COMMAND LINE CONTEXT

### 🔍 Suspicious Command-Line Inheritance
```spl
index=endpoint_logs
| search process_name="powershell.exe"
| search command_line="*-enc*" OR command_line="*-nop*"
| table _time host user parent_process command_line
```

Purpose:
- Detect obfuscated execution
- Identify malware payload delivery

---

## 🔗 PROCESS LINEAGE CORRELATION

### 🔑 Endpoint + Network Follow-On Activity
```spl
index IN (endpoint_logs, network_logs)
| table _time host user process_name dest_ip dest_port
```

Purpose:
- Confirm execution led to C2 or exfiltration
- Increase detection confidence

---

## ⏱️ PROCESS LINEAGE TIMELINE

```spl
index=endpoint_logs
| sort _time
| table _time host user parent_process process_name command_line
```

Purpose:
- Reconstruct execution flow
- Support forensic investigation

---

## 🛡️ SOC RESPONSE & ENDPOINT IR NOTES
- Isolate affected host immediately
- Collect full process tree from EDR
- Retrieve executed binaries or scripts
- Inspect persistence mechanisms
- Check lateral movement attempts
- Reset credentials used in execution context

---

## 🧠 MITRE ATT&CK Mapping

| Technique | Description |
|---------|-------------|
| T1059 | Command and Scripting Interpreter |
| T1204 | User Execution |
| T1055 | Process Injection |
| T1548 | Abuse Elevation Control Mechanism |
| T1021 | Remote Services |

---

## 📌 Summary
This file provides **advanced process lineage tracking techniques** that enable SOC and endpoint security teams to uncover **malware execution, LOLBin abuse, privilege escalation, and post-exploitation activity** by analyzing **how processes are spawned and chained together** across endpoint platforms.

Process lineage is not optional —  
it is **foundational to endpoint threat detection**.

