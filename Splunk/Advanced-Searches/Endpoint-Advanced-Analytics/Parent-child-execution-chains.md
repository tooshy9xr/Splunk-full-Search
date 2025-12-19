# 🔗 Parent–Child Execution Chains
## Endpoint Advanced Analytics (Windows • Linux • macOS)

This document focuses on **parent–child execution chain analysis**, an advanced endpoint detection technique that examines **multi-stage process execution paths** to uncover **malware delivery, living-off-the-land (LOLBin) abuse, privilege escalation, and post-exploitation activity**.

Parent–child execution chains answer:
> **“What sequence of processes led to this action?”**

Designed for:
- SOC Tier 2 / Tier 3 Analysts
- Endpoint Security Engineers
- Threat Hunters
- Detection Engineers
- Splunk Mastery – Advanced Searches

---

## 🎯 Objectives
- Detect malicious execution chains
- Identify abnormal process ancestry
- Expose LOLBin chaining techniques
- Reconstruct attacker execution paths
- Support endpoint incident response and forensics

---

## 🧠 What Are Parent–Child Execution Chains?

A parent–child execution chain represents:
- Parent → Child → Grandchild → Payload
- Execution order and timing
- Command-line inheritance
- Privilege and user context transitions

Attackers commonly:
- Launch scripts from trusted apps
- Chain native binaries together
- Hide payloads behind legitimate parents
- Execute multiple stages rapidly

> Attacks rarely execute in one step — **they chain**.

---

## 🧠 Common Data Sources

| Platform | Logs |
|--------|------|
| Windows | Sysmon (Event ID 1), Security 4688, EDR |
| Linux | auditd, syslog, EDR |
| macOS | Unified Logs, EDR |

Normalized fields assumed:
- `process_name`
- `parent_process`
- `command_line`
- `user`
- `host`
- `process_id`
- `parent_process_id`
- `integrity_level`

---

## 🟡 BASELINE NORMAL EXECUTION CHAINS

### 🔍 Common Parent → Child Patterns
```spl
index=endpoint_logs
| stats count by parent_process process_name
```

Purpose:
- Establish expected execution flows
- Identify abnormal chains later

---

## 🔴 HIGH-RISK EXECUTION CHAINS

### 🚨 Office → Script → Network
```spl
index=endpoint_logs
| search parent_process IN ("winword.exe","excel.exe","powerpnt.exe")
| search process_name IN ("powershell.exe","cmd.exe","wscript.exe","cscript.exe")
| table _time host user parent_process process_name command_line
```

Purpose:
- Detect macro-based malware
- Identify phishing-driven execution

---

## 🟠 LOLBIN CHAINING

### 🔗 Native Tool Chains
```spl
index=endpoint_logs
| search parent_process IN ("powershell.exe","cmd.exe","mshta.exe","rundll32.exe")
| table _time host user parent_process process_name command_line
```

Purpose:
- Detect living-off-the-land techniques
- Identify stealthy execution paths

---

## 🔵 SCRIPT → BINARY PAYLOAD CHAINS

### 🧪 Script Launching Executables
```spl
index=endpoint_logs
| search parent_process IN ("powershell.exe","wscript.exe","cscript.exe","bash","sh")
| search process_name!="powershell.exe"
| table _time host user parent_process process_name command_line
```

Purpose:
- Detect staged payload execution
- Identify malware delivery

---

## 🟣 PRIVILEGE TRANSITION CHAINS

### ⬆️ User Context → High Integrity Execution
```spl
index=endpoint_logs
| search integrity_level="High"
| search parent_process IN ("cmd.exe","powershell.exe","bash","sh")
| table _time host user parent_process process_name
```

Purpose:
- Detect privilege escalation
- Identify UAC bypass attempts

---

## 🔥 RARE OR FIRST-SEEN CHAINS

### 🧬 Uncommon Parent–Child Combinations
```spl
index=endpoint_logs
| stats count by parent_process process_name
| where count < 3
```

Purpose:
- Identify rare execution paths
- Catch early-stage attacks

---

## 🧠 COMMAND-LINE AWARE CHAIN DETECTION

### 🔍 Obfuscated or Suspicious Arguments
```spl
index=endpoint_logs
| search command_line="*-enc*" OR command_line="*-nop*" OR command_line="*base64*"
| table _time host user parent_process process_name command_line
```

Purpose:
- Detect obfuscated payload execution
- Identify malware staging

---

## 🔗 EXECUTION CHAIN + NETWORK CORRELATION

### 🌐 Process Chain Followed by Network Activity
```spl
index IN (endpoint_logs, network_logs)
| table _time host user process_name dest_ip dest_port
```

Purpose:
- Confirm execution led to C2 or exfiltration
- Increase detection confidence

---

## 🔗 EXECUTION CHAIN + FILE SYSTEM ACTIVITY

### 📂 Process Chains Writing Executables
```spl
index IN (endpoint_logs, file_logs)
| table _time host user process_name file_path action
```

Purpose:
- Detect dropper behavior
- Identify persistence preparation

---

## ⏱️ EXECUTION CHAIN TIMELINE

```spl
index=endpoint_logs
| sort _time
| table _time host user parent_process process_name command_line
```

Purpose:
- Reconstruct full execution flow
- Support forensic investigations

---

## 🛡️ SOC RESPONSE & ENDPOINT IR NOTES
- Isolate host immediately if malicious chain confirmed
- Capture full process tree from EDR
- Retrieve dropped files or scripts
- Check persistence mechanisms
- Inspect lateral movement attempts
- Reset credentials used during execution

---

## 🧠 MITRE ATT&CK Mapping

| Technique | Description |
|---------|-------------|
| T1059 | Command and Scripting Interpreter |
| T1204 | User Execution |
| T1106 | Native API |
| T1055 | Process Injection |
| T1548 | Abuse Elevation Control Mechanism |

---

## 📌 Summary
This file provides **advanced parent–child execution chain detection techniques** that enable SOC and endpoint security teams to uncover **multi-stage malware execution, LOLBin chaining, privilege escalation, and post-exploitation behavior** by analyzing **process ancestry and execution flow** across endpoints.

Execution chains expose **how attacks really happen** —  
and why single-event detection is never enough.

