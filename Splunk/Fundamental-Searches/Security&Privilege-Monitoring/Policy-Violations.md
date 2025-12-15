# 📜 Policy Violations Detection (Windows & Linux)
Fundamental Searches for Security & Usage Policy Breaches

This file focuses on **detecting policy violations** across **Windows and Linux environments**, using **basic searches** suitable for the *Fundamental Searches* level.  
Policy violations include **unauthorized software usage, forbidden actions, access misuse, and non-compliant behavior**.

---

## 🎯 Purpose
- Detect **violations of security and IT policies**
- Monitor **unauthorized applications and actions**
- Identify **risky or non-compliant user behavior**
- Support compliance audits and SOC investigations
- Enable proactive alerting

---

## 🖥️ Platforms Covered
- 🪟 Windows Servers & Workstations  
- 🐧 Linux Servers & Endpoints  
- 🌐 Network & Proxy Logs  
- ☁️ Cloud & SaaS Applications  

---

## 📂 Common Policy Violation Categories

### 🚫 Unauthorized Software
- Hacking tools
- Remote administration tools
- Torrent clients
- Crypto miners

### 🌐 Network Usage Violations
- Access to forbidden websites
- Use of anonymizers or VPNs
- Unauthorized file sharing

### 👤 Access & Privilege Violations
- Accessing restricted files
- Privilege abuse
- Policy bypass attempts

### ⚙️ System Misuse
- Disabled security controls
- Unauthorized configuration changes
- Execution from restricted directories

---

## 📂 Common Log Sources

### 🪟 Windows
- Security Event Log (EventID **4688**, **4663**)  
- Application logs  
- PowerShell logs  
- EDR / Defender logs  

### 🐧 Linux
- `auditd` logs  
- `/var/log/syslog`  
- Bash history  
- Application logs  

### 🌐 Network
- Proxy logs  
- Firewall logs  
- DNS logs  

---

## 🧾 Sample Logs

### 🪟 Windows – Unauthorized Tool Execution
```
2025-02-16 12:01:22 WIN-WS01 EventID=4688 User=alice NewProcessName=C:\Tools\nmap.exe
```

### 🐧 Linux – Forbidden Script Execution
```
Feb 16 12:03:10 server01 audit[1234]: USER=bob CMD=/tmp/crypto_miner.sh
```

### 🌐 Proxy – Blocked Website
```
2025-02-16 12:05:44 Proxy User=john URL=tor-site.onion Action=Blocked
```

---

## 🔍 Fundamental Search Examples

### 🚫 Unauthorized Executables
```spl
EventID=4688 OR "CMD"
| search NewProcessName IN ("*nmap*","*nc*","*miner*","*tor*")
```

### 🌐 Forbidden Website Access
```spl
| search URL IN ("*tor*","*proxy*","*torrent*")
```

### 👤 Restricted File Access
```spl
EventID=4663
| search File IN ("C:\\Restricted\\*","/etc/shadow")
```

---

## 🚨 Detection Scenarios

### 🔁 Repeated Policy Violations by User
```spl
| stats count by user
| where count > 3
```

### 🧨 Execution from Restricted Paths
```spl
| search NewProcessName IN ("C:\\Temp\\*", "/tmp/*")
```

### ⚠️ Security Controls Disabled
```spl
| search Action="Disabled" AND Control="Antivirus"
```

---

## 🛡️ Mitigation & Response
- Enforce application allowlisting
- Restrict execution paths
- Educate users on acceptable use policies
- Investigate repeat offenders
- Apply disciplinary or technical controls

---

## 📌 Summary
This file provides **fundamental policy violation detection** for:
- Unauthorized software and tools
- Network misuse and forbidden access
- Access and privilege policy breaches
