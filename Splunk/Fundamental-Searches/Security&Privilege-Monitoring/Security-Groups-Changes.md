# 👥 Security Groups Changes (Windows & Linux)
Fundamental Searches for Group Membership & Permission Changes

This file focuses on **monitoring changes to security groups and group memberships** across **Windows and Linux systems**, using **basic searches** suitable for the *Fundamental Searches* level.  
Security group changes are **high-risk events** often associated with **privilege escalation, insider threats, and account compromise**.

---

## 🎯 Purpose
- Detect **addition or removal of users from security groups**
- Monitor **privileged group membership changes**
- Identify **unauthorized permission escalation**
- Support SOC investigations and compliance audits
- Enable early detection of account abuse

---

## 🖥️ Platforms Covered
- 🪟 Windows Servers & Active Directory  
- 🐧 Linux Servers  
- ☁️ Identity Services (AD, LDAP, IAM)

---

## 📂 Common Group Types Monitored

### 🛡️ Privileged Groups
- Domain Admins  
- Enterprise Admins  
- Local Administrators  
- sudo / wheel group  

### 👤 Standard Security Groups
- Application access groups  
- File access groups  
- VPN / Remote access groups  

---

## 📂 Common Log Sources

### 🪟 Windows / Active Directory
- Security Event Log  
  - **4728** – User added to security-enabled global group  
  - **4729** – User removed from group  
  - **4732 / 4733** – Local group changes  
  - **4756 / 4757** – Universal group changes  

### 🐧 Linux
- `/var/log/auth.log`  
- `/var/log/secure`  
- `auditd` logs  
- `/etc/group` modification logs  

---

## 🧾 Sample Logs

### 🪟 Windows – User Added to Admin Group
```
2025-02-17 14:01:22 DC01 EventID=4728 TargetUser=john.doe Group=Domain Admins AddedBy=admin01
```

### 🪟 Windows – User Removed from Group
```
2025-02-17 14:03:10 DC01 EventID=4729 TargetUser=alice Group=IT-Support
```

### 🐧 Linux – User Added to sudo Group
```
Feb 17 14:05:33 server01 usermod[1234]: user bob added to group sudo
```

### 🐧 Linux – Group File Modified
```
Feb 17 14:07:11 server01 audit[5678]: PATH=/etc/group OP=write USER=root
```

---

## 🔍 Fundamental Search Examples

### 👥 Group Membership Changes
```spl
EventID IN (4728,4729,4732,4733,4756,4757)
| table _time host TargetUser Group AddedBy
```

### 🛡️ Privileged Group Monitoring
```spl
| search Group IN ("Domain Admins","Administrators","sudo","wheel")
```

### 👤 User-Focused Group Changes
```spl
| stats count by TargetUser Group
```

---

## 🚨 Detection Scenarios

### 🚩 Non-Admin Adding Users to Privileged Groups
```spl
| search Group="Domain Admins" AND AddedBy!="authorized_admin"
```

### 🔁 Multiple Group Changes in Short Time
```spl
| stats count by AddedBy
| where count > 3
```

### ⚠️ Linux Privilege Escalation via sudo Group
```spl
| search Group IN ("sudo","wheel")
```

---

## 🛡️ Mitigation & Response
- Restrict who can modify security groups
- Enable alerts for privileged group changes
- Review group memberships regularly
- Immediately investigate unauthorized changes
- Revoke access and reset credentials if compromised

---

## 📌 Summary
This file provides **fundamental monitoring for security group changes**, covering:
- Windows Active Directory group modifications
- Linux sudo / privilege group changes
- Detection of privilege escalation and access abuse

