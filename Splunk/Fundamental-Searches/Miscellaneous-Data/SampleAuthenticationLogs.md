# 🔐 Sample Authentication Logs  
This file provides **sample Windows + Linux authentication logs** to use for testing fundamental searches, dashboards, and correlation rules.  
These samples help you simulate login success/failure, brute force attempts, remote logins, and privilege escalation scenarios.

---

# 🟦 Windows Sample Authentication Logs

Below are **Event ID–based samples** representing common authentication events.

---

## ✅ Successful Login (EventCode 4624)
```
02/12/2025 13:44:32
EventCode=4624
LogonType=10
User=Administrator
TargetDomain=CORP
Workstation=WS-001
SourceIP=192.168.1.25
Status=SUCCESS
```

## ❌ Failed Login (EventCode 4625)
```
02/12/2025 13:47:10
EventCode=4625
User=Administrator
TargetDomain=CORP
Workstation=WS-001
SourceIP=192.168.1.89
FailureReason=Unknown user name or bad password
Status=FAILED
```

## 🚨 Account Lockout (EventCode 4740)
```
02/12/2025 14:05:51
EventCode=4740
User=CORP\john.doe
LockedBy=CORP\DC01$
SourceIP=192.168.1.40
Reason=Too many failed attempts
```

## 🛂 Remote Desktop Login (EventCode 4624, LogonType=10)
```
02/12/2025 14:11:30
EventCode=4624
LogonType=10
User=CORP\it.support
SourceIP=10.0.20.55
Protocol=RDP
```

## 🛡 Privilege Logon (EventCode 4672)
```
02/12/2025 14:14:07
EventCode=4672
User=CORP\Administrator
Privileges=SeBackupPrivilege; SeRestorePrivilege
```

---

# 🟩 Linux Sample Authentication Logs

Common SSH/Local authentication events.

---

## ✅ Successful SSH Login
```
Feb 12 13:20:11 ubuntu sshd[2450]: Accepted password for root from 192.168.1.75 port 52022 ssh2
```

## ❌ Failed SSH Login
```
Feb 12 13:23:47 ubuntu sshd[2482]: Failed password for invalid user admin from 192.168.1.201 port 52440 ssh2
```

## 🚨 SSH Brute-Force Pattern
```
Feb 12 13:23:48 ubuntu sshd[2482]: Failed password for root from 10.10.10.50 port 40220 ssh2
Feb 12 13:23:49 ubuntu sshd[2482]: Failed password for root from 10.10.10.50 port 40223 ssh2
Feb 12 13:23:50 ubuntu sshd[2482]: Failed password for root from 10.10.10.50 port 40225 ssh2
```

## 🛂 SSH Public Key Login
```
Feb 12 14:03:22 ubuntu sshd[2600]: Accepted publickey for deploy from 172.16.5.21 port 51124 ssh2
```

## 🛡 Sudo Authentication Success
```
Feb 12 14:16:31 ubuntu sudo:   john : TTY=pts/2 ; PWD=/home/john ; USER=root ; COMMAND=/usr/bin/apt update
```

## ❌ Sudo Authentication Failure
```
Feb 12 14:18:44 ubuntu sudo:   john : 3 incorrect password attempts
```

---

# 🧪 Additional Testing Scenarios

## 🟣 Mixed Logs for SIEM Testing
### Multiple Failed → One Successful (Credential Stuffing)
```
Failed password for admin from 203.0.113.12
Failed password for admin from 203.0.113.12
Accepted password for admin from 203.0.113.12
```

### Login From New Country (Impossible Travel)
```
Accepted password for user1 from 192.168.1.100
Accepted password for user1 from 203.113.55.10
```

### Lateral Movement (SSH Pivot)
```
Accepted password for root from 10.0.0.5
Accepted password for root from 10.0.0.6
Accepted password for root from 10.0.0.7
```

---

# 📌 Summary

This file includes:
- Windows authentication event samples  
- Linux SSH and sudo authentication samples  
- Brute-force patterns  
- Privilege logons  
- Remote logins  
- Realistic SOC testing scenarios  

Use this for:
- Search development  
- Dashboards  
- Lookups  
- Training data  
- Detection logic validation  

