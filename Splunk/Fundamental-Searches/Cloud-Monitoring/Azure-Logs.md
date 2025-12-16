# ☁️ Azure Logs Monitoring
Fundamental Searches for Microsoft Azure Activity

This file focuses on **monitoring Azure logs** using **basic searches** suitable for the *Fundamental Searches* level.  
Azure log monitoring is essential for detecting **unauthorized access, suspicious administrative actions, misconfigurations, and cloud security threats**.

---

## 🎯 Purpose
- Monitor **Azure account and resource activity**
- Detect **unauthorized or suspicious sign-ins**
- Track **role and permission changes**
- Identify **misconfigurations and risky operations**
- Support SOC investigations and cloud incident response

---

## ☁️ Azure Services Covered

### 🔐 Identity & Access
- Azure AD Sign-in Logs
- Azure AD Audit Logs
- Conditional Access events

### 🌐 Network
- Azure Network Security Group (NSG) Flow Logs
- Azure Firewall Logs
- Azure Load Balancer Logs

### 🖥️ Compute & Storage
- Azure VM activity logs
- Azure Storage account access logs
- Azure App Service logs

### 📊 Monitoring & Security
- Azure Activity Logs
- Microsoft Defender for Cloud alerts
- Azure Monitor & Log Analytics

---

## 📂 Common Log Sources

### ☁️ Azure Native Logs
- **Azure AD Sign-in Logs** – Authentication activity  
- **Azure AD Audit Logs** – Directory and role changes  
- **Azure Activity Logs** – Subscription-level operations  
- **NSG Flow Logs** – Network traffic  
- **Defender for Cloud** – Security alerts  

---

## 🧾 Sample Logs

### 🔐 Azure AD – Successful Sign-In
```
2025-02-27 11:01:22 User=john.doe@company.com App=Office365 IP=8.8.8.8 Result=Success
```

### ❌ Azure AD – Failed Sign-In
```
2025-02-27 11:03:10 User=alice@company.com IP=185.220.101.1 Result=Failure Reason=InvalidPassword
```

### 🌐 NSG Flow Log – Network Traffic
```
2025-02-27 11:05:33 SrcIP=10.1.0.5 DestIP=20.40.60.80 DestPort=443 Action=Allow
```

### 🛠 Azure Activity – Role Change
```
2025-02-27 11:07:11 Operation=Add member to role Role=GlobalAdmin InitiatedBy=john.doe
```

---

## 🔍 Fundamental Search Examples

### 🔐 Azure AD Sign-Ins
```spl
| search Result="Success"
| table _time User IP App
```

### ❌ Failed Login Attempts
```spl
| search Result="Failure"
| stats count by User IP
```

### 🌐 Suspicious Network Connections
```spl
| stats count by SrcIP DestIP DestPort
```

### 🛠 Privileged Role Changes
```spl
Operation="Add member to role"
```

---

## 🚨 Detection Scenarios

### 🔁 Multiple Failed Sign-Ins
```spl
| stats count by User
| where count > 5
```

### 🌍 Access from Unusual Countries
```spl
| iplocation IP
| search Country NOT IN ("US","CA","UK")
```

### ⚠️ High-Risk Administrative Actions
```spl
Operation IN ("Delete user","Reset password","Add member to role")
```

---

## 🛡️ Mitigation & Response
- Enforce MFA for all users and admins  
- Monitor and restrict Global Admin role assignments  
- Review Conditional Access policies  
- Investigate suspicious IPs and sign-ins  
- Enable Microsoft Defender for Cloud  

---

## 📌 Summary
This file provides **fundamental Azure log monitoring** for:
- Authentication and identity activity  
- Network traffic and resource operations  
- Detecting cloud threats and misconfigurations  

