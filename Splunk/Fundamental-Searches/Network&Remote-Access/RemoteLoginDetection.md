# 🌐 Remote Login Detection — Windows & Linux  

A collection of Splunk searches designed to detect remote login activity, including successful and failed RDP, SSH, and remote session events.

---

# 🪟 Windows — Remote Login Detection  

## 🔹 1. Successful RDP Logins  
**Description:** Detects successful Remote Desktop Protocol (RDP) logins.  
**Purpose:** Tracks legitimate or unexpected remote access activity.

**🔍 SPL**
```
index=windows EventCode=4624 LogonType=10
| stats count by Account_Name, Computer, IpAddress, _time
```

---

## 🔹 2. Failed RDP Login Attempts  
**Description:** Shows failed RDP authentication attempts.  
**Purpose:** Useful for detecting brute-force or unauthorized access attempts.

**🔍 SPL**
```
index=windows EventCode=4625 LogonType=10
| stats count by Account_Name, Computer, IpAddress, FailureReason, _time
```

---

## 🔹 3. Remote PowerShell Session  
**Description:** Detects the creation of remote PowerShell sessions.  
**Purpose:** Indicates remote admin activity or lateral movement.

**🔍 SPL**
```
index=windows EventCode=4104 CommandLine="*Enter-PSSession*" OR CommandLine="*New-PSSession*"
| stats count by User, Computer, CommandLine, _time
```

---

## 🔹 4. Network Logon (Remote Authentication)  
**Description:** Captures remote logons using network authentication.  
**Purpose:** Used for file shares, remote execution tools, and lateral movement.

**🔍 SPL**
```
index=windows EventCode=4624 LogonType=3
| stats count by Account_Name, IpAddress, WorkstationName, _time
```

---

# 🐧 Linux — Remote Login Detection  

## 🔹 5. Successful SSH Login  
**Description:** Shows successful SSH authentication attempts.  
**Purpose:** Tracks legitimate or suspicious remote access activity.

**🔍 SPL**
```
index=linux sourcetype=linux_secure "Accepted password" OR "Accepted publickey"
| rex "Accepted (?<method>\w+)"
| stats count by method, user, src, host, _time
```

---

## 🔹 6. Failed SSH Login Attempts  
**Description:** Displays failed SSH password or key login attempts.  
**Purpose:** Helps detect brute-force attacks against SSH.

**🔍 SPL**
```
index=linux sourcetype=linux_secure "Failed password"
| stats count by user, src, host, _time
```

---

## 🔹 7. SSH Sessions Opened  
**Description:** Detects when a user starts an SSH interactive session.  
**Purpose:** Tracks activity after successful remote login.

**🔍 SPL**
```
index=linux sourcetype=linux_secure "session opened"
| stats count by user, src, host, _time
```

---

## 🔹 8. Suspicious SSH From New IP  
**Description:** Flags SSH logins from IPs not seen before.  
**Purpose:** Helps detect compromised accounts used from new locations.

**🔍 SPL**
```
index=linux sourcetype=linux_secure "Accepted"
| stats earliest(_time) AS first_seen latest(_time) AS last_seen by src, user, host
| where first_seen == last_seen
```
