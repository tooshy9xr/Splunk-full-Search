# ☁️ AWS Logs Monitoring
Fundamental Searches for AWS Cloud Activity

This file focuses on **monitoring AWS logs** using **basic searches** suitable for the *Fundamental Searches* level.  
AWS log monitoring is essential for detecting **misconfigurations, unauthorized access, suspicious API activity, and cloud security threats**.

---

## 🎯 Purpose
- Monitor **AWS account and resource activity**
- Detect **unauthorized or suspicious API calls**
- Track **authentication and permission changes**
- Identify **misconfigurations and security risks**
- Support SOC investigations and cloud incident response

---

## ☁️ AWS Services Covered

### 🔐 Identity & Access
- AWS CloudTrail (IAM activity)
- Console login events
- Role assumption (STS)

### 🌐 Network
- VPC Flow Logs
- Security Group changes
- NACL activity

### 🖥️ Compute & Storage
- EC2 lifecycle events
- S3 bucket access
- Lambda execution logs

### 📊 Monitoring & Security
- CloudWatch Logs
- GuardDuty findings
- AWS Config changes

---

## 📂 Common Log Sources

### ☁️ AWS Native Logs
- **CloudTrail** – API calls & account activity  
- **VPC Flow Logs** – Network traffic  
- **CloudWatch Logs** – Application & service logs  
- **S3 Access Logs** – Object-level access  
- **GuardDuty** – Threat detection findings  

---

## 🧾 Sample Logs

### 🔐 CloudTrail – Console Login
```
2025-02-26 15:01:22 eventName=ConsoleLogin userName=john.doe sourceIPAddress=8.8.8.8 responseElements=Success
```

### 🔐 CloudTrail – Failed Login
```
2025-02-26 15:03:10 eventName=ConsoleLogin userName=alice sourceIPAddress=185.220.101.1 errorMessage=Failed authentication
```

### 🌐 VPC Flow Log – Network Traffic
```
2025-02-26 15:05:33 srcaddr=10.0.1.15 dstaddr=54.239.28.85 dstport=443 action=ACCEPT
```

### 📦 S3 – Object Access
```
2025-02-26 15:07:11 bucket=my-data-bucket object=backup.zip operation=GetObject user=john.doe
```

---

## 🔍 Fundamental Search Examples

### 🔐 AWS Console Logins
```spl
eventName=ConsoleLogin
| table _time userName sourceIPAddress responseElements
```

### ❌ Failed Authentication Attempts
```spl
eventName=ConsoleLogin AND errorMessage=*
```

### 🌐 Suspicious Network Traffic
```spl
action=ACCEPT
| stats count by srcaddr dstaddr dstport
```

### 📦 Sensitive S3 Bucket Access
```spl
eventSource=s3.amazonaws.com AND eventName=GetObject
```

---

## 🚨 Detection Scenarios

### 🔁 Multiple Failed Logins
```spl
| stats count by userName
| where count > 3
```

### 🌍 AWS Access from Unusual Locations
```spl
| iplocation sourceIPAddress
| search Country NOT IN ("US","CA","UK")
```

### ⚠️ High-Risk API Calls
```spl
eventName IN ("DeleteTrail","StopLogging","PutBucketPolicy")
```

---

## 🛡️ Mitigation & Response
- Enforce MFA for all IAM users  
- Monitor and restrict privileged API actions  
- Rotate compromised access keys immediately  
- Enable GuardDuty and AWS Config  
- Apply least-privilege IAM policies  

---

## 📌 Summary
This file provides **fundamental AWS log monitoring** for:
- IAM authentication and API activity  
- Network traffic and storage access  
- Detecting cloud threats and misconfigurations  
