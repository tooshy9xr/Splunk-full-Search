# 🔐 Privilege Escalation Attempt Detection — Windows & Linux

A collection of Splunk searches designed to identify suspicious privilege escalation attempts, including admin elevation, sudo misuse, token manipulation, and security policy changes.

---

# 🪟 Windows — Privilege Escalation Detection

## 🔹 1. User Added to Administrators Group  
**Description:** Detects when a user is added to a privileged local group.  
**Purpose:** A common privilege escalation method.

**🔍 SPL**
```
index=windows EventCode=4732 OR EventCode=4728
| stats count by TargetUserName, MemberSid, Account_Name, Computer, _time
```

---

## 🔹 2. Token Manipulation / Impersonation Attempts  
**Description:** Detects attempts to duplicate or impersonate security tokens.  
**Purpose:** Used heavily by malware and attackers to escalate privileges.

**🔍 SPL**
```
index=windows EventCode=4624 LogonType=9
| stats count by Account_Name, Computer, IpAddress, _time
```

---

## 🔹 3. UAC Elevation (Admin Approval)  
**Description:** Captures events when processes request elevated admin privileges.  
**Purpose:** Tracks suspicious elevation attempts via UAC.

**🔍 SPL**
```
index=windows EventCode=4672
| stats count by Account_Name, Privileges, Computer, _time
```

---

## 🔹 4. Local Security Policy Modification  
**Description:** Detects changes to audit policy, privilege rights, and security settings.  
**Purpose:** Attackers modify local policy to gain or maintain elevated access.

**🔍 SPL**
```
index=windows EventCode=4719
| stats count by Account_Name, Computer, CategoryId, _time
```

---

# 🐧 Linux — Privilege Escalation Detection

## 🔹 5. Suspicious sudo Usage  
**Description:** Detects use of sudo for unfamiliar commands or by unusual users.  
**Purpose:** Tracks attempts to elevate privilege via sudo.

**🔍 SPL**
```
index=linux sourcetype=linux_secure "sudo"
| stats count by user, host, cmd, _time
```

---

## 🔹 6. Failed sudo Attempts  
**Description:** Shows failed attempts to run commands with sudo.  
**Purpose:** Indicates brute-force or unauthorized privilege escalation attempts.

**🔍 SPL**
```
index=linux sourcetype=linux_secure "sudo" "authentication failure"
| stats count by user, host, _time
```

---

## 🔹 7. Root Shell Spawned  
**Description:** Detects when a shell is launched with UID=0 (root).  
**Purpose:** Common indicator of privilege escalation success.

**🔍 SPL**
```
index=linux (uid=0 AND process IN ("bash","sh","zsh"))
| stats count by user, process, host, _time
```

---

## 🔹 8. SUID/SGID File Creation  
**Description:** Detects creation or modification of SUID/SGID binaries.  
**Purpose:** Attackers use SUID binaries to escalate privileges.

**🔍 SPL**
```
index=linux cmdline="chmod *s*"
| stats count by user, host, cmdline, _time
```

---

## 🔹 9. Privileged Capability Changes  
**Description:** Detects capability changes using `setcap`.  
**Purpose:** Malware and attackers grant elevated capabilities to binaries.

**🔍 SPL**
```
index=linux cmdline="setcap*"
| stats count by user, host, cmdline, _time
```
