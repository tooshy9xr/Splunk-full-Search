# 🧠 Memory-Based Attack Indicators
## Endpoint Advanced Analytics (Windows • Linux • macOS)

This document focuses on **memory-based attack indicators**, where attackers execute **payloads directly in memory** to evade disk-based detection, bypass antivirus, and persist stealthily during post-exploitation.

Memory-based attacks are commonly used in:
- Fileless malware
- In-memory loaders
- Cobalt Strike / Metasploit
- Credential dumping
- Reflective DLL injection
- Living-off-the-land attacks

Designed for:
- SOC Tier 2 / Tier 3 Analysts
- Endpoint Security Engineers
- Threat Hunters
- Detection Engineers
- Splunk Mastery – Advanced Searches

---

## 🎯 Objectives
- Detect in-memory execution and injection techniques
- Identify fileless and stealthy malware
- Correlate memory activity with process lineage
- Expose credential dumping and post-exploitation
- Support advanced endpoint incident response

---

## 🧠 What Are Memory-Based Attacks?

Memory-based attacks execute malicious code:
- Without writing files to disk
- Inside trusted processes
- Using legitimate APIs and interpreters
- Often encrypted or obfuscated in memory

Common techniques include:
- Process injection
- Reflective DLL loading
- PowerShell in-memory execution
- Shellcode injection
- Credential harvesting from LSASS

> If nothing touches disk, **memory is the battlefield**.

---

## 🧠 Common Data Sources

| Platform | Logs / Telemetry |
|--------|------------------|
| Windows | Sysmon, EDR, AMSI, ETW |
| Linux | auditd, ptrace logs, EDR |
| macOS | EDR, Endpoint Security Framework |

Normalized fields assumed:
- `process_name`
- `parent_process`
- `command_line`
- `user`
- `host`
- `process_id`
- `integrity_level`
- `api_call`
- `memory_action`

---

## 🟡 BASELINE NORMAL MEMORY BEHAVIOR

### 🔍 Normal API Usage by Process
```spl
index=endpoint_logs
| stats count by process_name api_call
```

Purpose:
- Understand normal memory-related API usage
- Identify suspicious deviations later

---

## 🔴 PROCESS INJECTION INDICATORS

### 💉 Suspicious Memory Injection APIs
```spl
index=endpoint_logs
| search api_call IN ("VirtualAllocEx","WriteProcessMemory","CreateRemoteProcess","NtMapViewOfSection")
| table _time host user process_name api_call target_process
```

Purpose:
- Detect process injection attempts
- Identify in-memory malware loaders

---

## 🟠 LSASS MEMORY ACCESS (CREDENTIAL DUMPING)

### 🔐 Unauthorized Access to LSASS
```spl
index=endpoint_logs
| search target_process="lsass.exe"
| search api_call IN ("MiniDumpWriteDump","ReadProcessMemory")
| table _time host user process_name api_call
```

Purpose:
- Detect credential dumping
- Identify Mimikatz-style attacks

---

## 🔵 FILELESS POWERSHELL EXECUTION

### ⚡ In-Memory PowerShell Payloads
```spl
index=endpoint_logs
| search process_name="powershell.exe"
| search command_line="*-enc*" OR command_line="*FromBase64String*" OR command_line="*Invoke-Expression*"
| table _time host user parent_process command_line
```

Purpose:
- Detect fileless execution
- Identify obfuscated payload delivery

---

## 🟣 REFLECTIVE DLL LOADING

### 🧩 DLLs Loaded Without Disk Artifacts
```spl
index=endpoint_logs
| search memory_action="LoadLibrary"
| search file_path="*\\Temp\\*" OR file_path="*\\AppData\\*"
| table _time host process_name memory_action
```

Purpose:
- Detect reflective or suspicious DLL loading
- Identify in-memory persistence

---

## 🔥 RARE MEMORY BEHAVIOR (OUTLIERS)

### 🎯 Uncommon Memory Actions per Process
```spl
index=endpoint_logs
| stats count by process_name memory_action
| where count < 3
```

Purpose:
- Detect rare or first-seen memory behavior
- Catch early-stage attacks

---

## 🔗 MEMORY ACTIVITY + PROCESS LINEAGE

### 🧬 Injection Following Script Execution
```spl
index IN (endpoint_logs)
| search api_call="WriteProcessMemory"
| table _time host user parent_process process_name target_process
```

Purpose:
- Correlate script-based loaders with injection
- Increase detection confidence

---

## 🔗 MEMORY + NETWORK CORRELATION

### 🌐 In-Memory Execution Followed by Network Traffic
```spl
index IN (endpoint_logs, network_logs)
| table _time host process_name dest_ip dest_port
```

Purpose:
- Confirm in-memory malware contacting C2
- Validate active compromise

---

## ⏱️ MEMORY ATTACK TIMELINE

```spl
index=endpoint_logs
| sort _time
| table _time host user process_name api_call target_process command_line
```

Purpose:
- Reconstruct memory-based attack sequence
- Support forensic investigations

---

## 🛡️ SOC RESPONSE & ENDPOINT IR NOTES
- Immediately isolate affected host
- Capture volatile memory if possible
- Dump suspicious processes for analysis
- Review full process lineage and command lines
- Reset credentials exposed on host
- Hunt for lateral movement indicators

---

## 🧠 MITRE ATT&CK Mapping

| Technique | Description |
|---------|-------------|
| T1055 | Process Injection |
| T1003 | OS Credential Dumping |
| T1059 | Command and Scripting Interpreter |
| T1106 | Native API |
| T1105 | Ingress Tool Transfer |

---

## 📌 Summary
This file provides **advanced memory-based attack detection techniques** that enable SOC and endpoint security teams to uncover **fileless malware, process injection, credential dumping, and stealthy post-exploitation activity** by analyzing **memory behavior, API usage, and execution context**.

Memory-based attacks leave no files —  
but they always leave **behavior**.

