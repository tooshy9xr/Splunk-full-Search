# 🔎 LDAP Queries (Windows & Linux)
Fundamental Searches for Directory Query Activity

This file focuses on **LDAP query activity** across **Windows and Linux environments**, using **basic searches** suitable for *Fundamental Searches*.  
LDAP queries are critical to monitor because they are often abused for **enumeration, privilege discovery, and reconnaissance**.

---

## 🎯 Purpose
- Monitor **LDAP search and bind activity**
- Detect **excessive enumeration**
- Identify **unauthorized or anonymous binds**
- Track **service account directory usage**
- Support SOC investigations

---

## 🖥️ Platforms Covered
- 🪟 Windows Active Directory (LDAP / LDAPS)
- 🐧 Linux LDAP Clients (OpenLDAP)
- 🔐 Applications using LDAP authentication

---

## 📂 Common Log Sources

### 🪟 Windows
- Security Event Log  
  - Event ID **4662** (Directory Service Access)  
  - Event ID **4624 / 4625** (LDAP authentication)
- Directory Service Log
- Active Directory Domain Controller logs

### 🐧 Linux
- `/var/log/auth.log`
- `/var/log/syslog`
- OpenLDAP logs (`slapd`)

---

## 🧾 Sample LDAP Logs

### 🪟 Windows – LDAP Bind Success
```
2025-02-12 09:15:21 DC01 EventID=4624 LogonType=3 User=svc_app SrcIP=192.168.1.50 AuthPackage=LDAP Status=Success
```

### 🪟 Windows – LDAP Bind Failure
```
2025-02-12 09:17:44 DC01 EventID=4625 User=guest SrcIP=203.0.113.77 AuthPackage=LDAP Status=Failed
```

### 🪟 Windows – Directory Object Access
```
2025-02-12 09:20:33 DC01 EventID=4662 User=svc_app ObjectType=User Operation=Read
```

---

### 🐧 Linux – LDAP Bind Success
```
Feb 12 09:31:11 ldap01 slapd[1121]: conn=1023 op=0 BIND dn="cn=admin,dc=example,dc=com" method=128
```

### 🐧 Linux – LDAP Bind Failure
```
Feb 12 09:33:21 ldap01 slapd[1121]: conn=1024 op=0 BIND dn="cn=guest,dc=example,dc=com" method=128 error=49
```

### 🐧 Linux – LDAP Search Query
```
Feb 12 09:35:44 ldap01 slapd[1121]: conn=1023 op=1 SRCH base="dc=example,dc=com" scope=sub filter="(objectClass=user)"
```

---

## 🔍 Fundamental Search Examples

### 🔐 LDAP Bind Activity
```spl
(AuthPackage=LDAP) OR (slapd BIND)
```

### ❌ Failed LDAP Binds
```spl
(EventID=4625 AuthPackage=LDAP) OR (slapd error=49)
```

### 🔎 LDAP Enumeration Detection
```spl
(EventID=4662) OR (slapd SRCH)
| stats count by user
| where count > 100
```

---

## 🚨 Basic Detection Use Cases

### 🔁 LDAP Enumeration / Recon
- Excessive directory reads
```spl
(EventID=4662)
| stats count by user src_ip
| where count > 500
```

### 👑 LDAP Queries by Privileged Accounts
```spl
(EventID=4662 User=admin) OR (slapd dn="cn=admin*")
```

### 🌍 LDAP Access from External IP
```spl
(AuthPackage=LDAP)
| search src_ip!=10.0.0.0/8
```

---

## 🛡️ LDAP Security Best Practices
- Disable anonymous LDAP binds
- Use LDAPS (secure LDAP)
- Monitor service account behavior
- Alert on enumeration patterns
- Limit LDAP read permissions

---

## 📌 Summary
This file provides **fundamental LDAP query visibility** across:
- 🪟 Windows Active Directory
- 🐧 Linux OpenLDAP

