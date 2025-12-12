# 🛠️ System Misconfigurations (Fundamental Searches)  
Beginner-Level Detection of OS Misconfiguration Issues in Windows & Linux

System misconfigurations are one of the most common security weaknesses in enterprise environments.  
At the **Fundamental Searches** level, the goal is to detect simple configuration issues using basic SPL.

This document provides **Windows & Linux misconfiguration detection examples** with easy-to-understand SPL queries.

---

# 1️⃣ What Are System Misconfigurations?

A system misconfiguration is any incorrect, insecure, or risky setting that weakens security.

Examples:
- Disabled antivirus or firewall  
- Wrong permissions on sensitive files  
- Stopped security services  
- Incorrect authentication settings  
- Insecure network configurations  
- Unauthorized software installed  

Misconfigurations do **not require malware**—they simply expose the system.

---

# 2️⃣ Why Detect Misconfigurations?

Misconfigurations lead to:
- Unauthorized access  
- Privilege escalation  
- Lateral movement  
- Data exposure  
- System compromise  

SOC teams monitor them because attackers frequently exploit weak configurations.

---

# 3️⃣ Windows System Misconfigurations (Fundamental-Level Detection)

Below are simple searches using basic Windows + Sysmon logs.

---

## 🟦 1. Stopped or Disabled Security Services  
Example: Firewall, AV, Defender

```spl
index=windows (EventCode=7036 OR EventCode=7040)
| search ("stopped" OR "disabled") 
| table _time host service_name State
```

---

## 🟦 2. Weak File Permissions  
Detect files changed to "Everyone:FullControl".

```spl
index=windows EventCode=4670
| search "Everyone" AND ("Full Control" OR "Write")
```

---

## 🟦 3. Administrator Group Modified  
Unauthorized privilege changes.

```spl
index=windows EventCode=4732 OR EventCode=4728
| table _time user member host
```

---

## 🟦 4. RDP Configuration Changed  
Possible remote access misconfiguration.

```spl
index=windows EventCode=4739 user_profile="*RDP*"
```

---

## 🟦 5. SMBv1 Enabled (Obsolete & Vulnerable)  
```spl
index=windows EventCode=7045 
| search ImagePath="*SMB1*"
```

---

## 🟦 6. Windows Firewall Rules Modified  
```spl
index=windows EventCode=4950 OR EventCode=4954
| table _time host rule_name action
```

---

## 🟦 7. Unsecured Startup Item Added  
Persistent misconfiguration.

```spl
index=windows EventCode=7045
| search "Run" OR "Startup"
```

---

# 4️⃣ Linux System Misconfigurations (Fundamental-Level Detection)

Uses `/var/log/auth.log`, systemd logs, and Linux audit logs.

---

## 🟩 1. Password Authentication Enabled  
Even when SSH keys are required.

```spl
index=linux "PasswordAuthentication yes"
```

---

## 🟩 2. SSH Running on Non-Standard Port  
Misconfiguration or evasion.

```spl
index=linux "sshd" AND "port" 
| search "22"=false
```

---

## 🟩 3. World-Writable Files  
```spl
index=linux "chmod 777" OR "chmod 666"
```

---

## 🟩 4. Firewall Disabled (ufw / firewalld)  
```spl
index=linux ("ufw" AND "inactive") OR ("firewalld" AND "stopped")
```

---

## 🟩 5. Unauthorized Cron Jobs  
Cron persistence.

```spl
index=linux "CRON" AND ("new" OR "added")
```

---

## 🟩 6. Root Login Allowed via SSH  
```spl
index=linux "PermitRootLogin yes"
```

---

## 🟩 7. Missing or Disabled SELinux  
```spl
index=linux "SELinux" AND ("disabled" OR "permissive")
```

---

# 5️⃣ Cross-Platform Misconfiguration Patterns

These apply to Windows & Linux:

### 🔸 Open ports not required  
### 🔸 Weak passwords  
### 🔸 Outdated software  
### 🔸 Disabled security tools  
### 🔸 Misconfigured permissions  
### 🔸 Unauthorized users or groups  

Example SPL:

```spl
index=* (port=*" OR permission=*weak*)
```

---

# 6️⃣ SOC Use Cases (Fundamental Level)

| Type | Example |
|------|---------|
| Security Services | Firewall off, AV disabled |
| Authentication | Password auth enabled, old hashing |
| Permissions | Weak ACLs / chmod 777 |
| Services | Stopped / unexpected services |
| Network | Open ports, insecure protocols |
| System | SELinux disabled, SMBv1 enabled |

These are **beginner-level** misconfigurations suitable for fundamental understanding.

---

# Summary

This document includes:
- Simple SPL searches  
- Windows + Linux misconfigurations  
- Easy detection examples  
- SOC-oriented basics  


