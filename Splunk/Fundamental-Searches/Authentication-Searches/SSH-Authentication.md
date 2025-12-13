# 🔐 SSH Authentication (Windows & Linux)
Fundamental Searches for Secure Shell (SSH) Access Monitoring

This file covers **SSH authentication activity on both Linux and Windows systems**, focusing on **basic searches** suitable for the *Fundamental Searches* level.

---

## 🎯 Purpose
- Monitor **successful and failed SSH logins**
- Detect **brute-force attempts**
- Identify **root / administrator access**
- Track **remote access behavior**
- Provide cross-platform visibility (Linux & Windows)

---

## 🖥️ Operating Systems Covered
- 🐧 Linux / Unix (OpenSSH)
- 🪟 Windows (OpenSSH Server / Win32-OpenSSH)

---

## 📂 Common Log Locations

### 🐧 Linux
- `/var/log/auth.log` (Ubuntu / Debian)
- `/var/log/secure` (RHEL / CentOS)
- `sshd` logs

### 🪟 Windows
- Event Viewer  
  - **Applications and Services Logs**
  - **OpenSSH/Operational**
- Windows Security Log (when integrated)

---

## 🧾 Sample SSH Logs

### 🐧 Linux – Successful SSH Login
```
Feb 12 10:51:22 ubuntu01 sshd[1221]: Accepted password for mike from 203.0.113.98 port 51432 ssh2
```

### 🐧 Linux – Failed SSH Login
```
Feb 12 10:52:12 ubuntu01 sshd[1221]: Failed password for root from 203.0.113.98 port 51500 ssh2
```

### 🐧 Linux – Invalid User
```
Feb 12 10:56:33 ubuntu01 sshd[1355]: Invalid user admin from 203.0.113.77 port 50211
```

---

### 🪟 Windows – Successful SSH Login
```
2025-02-12 11:10:21 WIN-SRV01 OpenSSH EventID=4 User=john.doe SrcIP=192.168.1.55 Status=Success
```

### 🪟 Windows – Failed SSH Login
```
2025-02-12 11:12:44 WIN-SRV01 OpenSSH EventID=4 User=administrator SrcIP=203.0.113.90 Status=Failed
```

### 🪟 Windows – Key-Based Authentication
```
2025-02-12 11:15:09 WIN-SRV01 OpenSSH EventID=4 User=alice AuthMethod=PublicKey Status=Success
```

---

## 🔍 Fundamental Search Examples

### 🔐 Successful SSH Logins (Linux)
```spl
index=linux_logs sshd "Accepted"
```

### ❌ Failed SSH Logins (Linux)
```spl
index=linux_logs sshd "Failed password"
```

### 🪟 Windows SSH Logins
```spl
index=windows_logs sourcetype=WinEventLog:OpenSSH
```

### 🚨 Failed SSH on Windows
```spl
index=windows_logs sourcetype=WinEventLog:OpenSSH Status=Failed
```

---

## 🚨 Basic Detection Use Cases

### 🔁 Brute-Force Detection (Linux & Windows)
```spl
(index=linux_logs sshd "Failed") OR (index=windows_logs Status=Failed)
| stats count by src_ip
| where count > 10
```

### 👑 Root / Administrator SSH Access
```spl
(index=linux_logs sshd "root") OR (index=windows_logs User=administrator)
```

### 🌍 External SSH Access
```spl
(index=linux_logs sshd "Accepted") OR (index=windows_logs Status=Success)
| search src_ip!=10.0.0.0/8
```

---

## 🛡️ SSH Security Best Practices
- Disable root / administrator SSH login
- Use key-based authentication only
- Restrict SSH access by IP
- Monitor failed attempts continuously
- Alert on invalid user attempts
- Rotate keys regularly

---

## 📌 Summary
This file provides **fundamental SSH authentication visibility** across:
- 🐧 Linux systems
- 🪟 Windows systems
