# 🔍 Threat Detection Patterns (Fundamental Searches)

Fundamental threat-detection patterns help identify early signs of malicious activity using simple SPL queries.  
These patterns focus on **behavior**, not specific malware, making them useful in any SOC environment.

This document provides Windows + Linux threat-detection fundamentals for:  
- Suspicious commands  
- Lateral movement  
- Privilege abuse  
- Persistence  
- Credential access  
- Anomaly behavior

---

# 1️⃣ Command-Line Abuse Patterns  
Detect execution of dangerous or abnormal commands.

---

## 🟦 Windows Examples

### PowerShell with encoded commands  
```spl
index=windows (EventCode=4104 OR EventCode=1)
| search ("-enc" OR "-EncodedCommand")
```

### PowerShell downloading remote files  
```spl
index=windows EventCode=4104
| search ("Invoke-WebRequest" OR "wget" OR "curl")
```

### Suspicious unsigned executables  
```spl
index=windows EventCode=1 Signed="false"
```

### CMD used to run system-level tools  
```spl
index=windows EventCode=1 
| search ("net user" OR "whoami /priv" OR "taskkill" OR "wmic process")
```

---

## 🟩 Linux Examples

### Reverse shell attempt  
```spl
index=linux ("bash" OR "sh") 
| search ("nc -e" OR "bash -i" OR "python -c" AND "socket")
```

### Suspicious use of curl/wget  
```spl
index=linux ("curl" OR "wget") AND ("http://" OR "https://")
```

### Privilege enumeration commands  
```spl
index=linux ("id" OR "sudo -l" OR "whoami")
```

---

# 2️⃣ Lateral Movement Patterns  
Detect attempts to move across systems.

---

## Windows  
### RDP login attempts from unusual sources  
```spl
index=windows EventCode=4625 OR EventCode=4624 
| search LogonType=10
```

### WMI execution  
```spl
index=windows EventCode=1 "wmic.exe"
```

### PsExec-like execution  
```spl
index=windows EventCode=7045 "PSEXESVC"
```

---

## Linux  
### Lateral SSH connections  
```spl
index=linux "Accepted password" OR "Accepted publickey"
| stats count by src_ip user
```

### SSH brute-force patterns  
```spl
index=linux "Failed password" 
| stats count by src_ip
```

---

# 3️⃣ Privilege Escalation Patterns  
Detect attempts to gain higher permissions.

---

## Windows  
### UAC bypass indications  
```spl
index=windows EventCode=1 
| search ("fodhelper.exe" OR "eventvwr.exe" OR "computerdefaults.exe")
```

### New admin added  
```spl
index=windows EventCode=4728 OR EventCode=4720
```

---

## Linux  
### sudo brute-force  
```spl
index=linux "sudo" AND "incorrect password"
```

### Use of privilege escalation tools  
```spl
index=linux ("pkexec" OR "sudo -i" OR "su -")
```

---

# 4️⃣ Persistence Patterns  
Detect ways malware stays in the system.

---

## Windows  
### Registry Run keys  
```spl
index=windows EventCode=4657 
| search ("Run" OR "RunOnce")
```

### Startup folder modifications  
```spl
index=windows EventCode=4663 "Startup"
```

### New scheduled tasks  
```spl
index=windows EventCode=4698
```

---

## Linux  
### Cron job creation  
```spl
index=linux "CRON" AND ("new" OR "added")
```

### New systemd service  
```spl
index=linux "systemd" AND "Created slice"
```

---

# 5️⃣ Credential Access Patterns  
Common attacker steps to steal credentials.

---

## Windows  
### Dumping LSASS  
```spl
index=windows EventCode=1 
| search ("procdump" OR "lsass" OR "comsvcs.dll")
```

### SAM/SECURITY hive access  
```spl
index=windows EventCode=4663 
| search ("SAM" OR "SYSTEM" OR "SECURITY")
```

---

## Linux  
### Reading shadow or passwd files  
```spl
index=linux ("shadow" OR "/etc/passwd") AND ("open" OR "read")
```

### Key logging activity  
```spl
index=linux "ptrace" OR "strace"
```

---

# 6️⃣ Anomaly & Behavior Patterns  
Baseline deviations useful for fundamental SOC correlation.

---

### Unusual login hours  
```spl
index=* (EventCode=4624 OR "Accepted") 
| eval hour=strftime(_time,"%H")
| stats count by user hour
```

### Excessive failed logins  
```spl
index=* ("Failed password" OR EventCode=4625)
| stats count by user src_ip
```

### Rare processes  
```spl
index=* 
| stats dc(process) by host
```

### Data exfiltration (basic)  
```spl
index=network bytes_out>50000000
```

---

# Summary  

This document includes fundamental threat-detection patterns for:
- Command-line abuse  
- Lateral movement  
- Privilege escalation  
- Persistence  
- Credential access  
- Baseline anomalies  
