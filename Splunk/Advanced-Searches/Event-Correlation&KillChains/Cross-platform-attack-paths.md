# 🔗 Cross-Platform Attack Paths
## Linux • Windows • Cloud (Advanced Splunk Correlation)

This document focuses on **cross-platform attack paths**, where attackers pivot between **Windows, Linux, and Cloud environments** within a single intrusion.

It is designed to help SOC analysts **detect, correlate, and reconstruct attack paths** that span multiple platforms and identity domains.

Designed for:
- SOC Tier 2 / Tier 3 Analysts
- Threat Hunters
- Incident Responders
- Splunk Mastery – Advanced Searches

---

## 🎯 Objectives
- Identify attacker movement across platforms
- Correlate identity reuse across systems
- Detect pivot points between endpoint and cloud
- Expose hidden lateral movement paths
- Improve investigation speed and accuracy

---

## 🧠 Cross-Platform Attack Model

| Step | Platform | Description |
|------|----------|-------------|
| 1 | Windows | Initial access on workstation |
| 2 | Linux | Pivot to servers or containers |
| 3 | Cloud | IAM abuse and storage access |
| 4 | Hybrid | Persistence, exfiltration, impact |

---

## 🔑 Core Concept: Identity as the Pivot

Attackers commonly reuse:
- Usernames
- Passwords
- SSH keys
- Cloud tokens
- Service accounts

### 🔗 Identity Correlation (All Platforms)
```spl
index IN (windows_logs, linux_logs, cloud_logs)
| eval normalized_user=coalesce(user, Account_Name, principalEmail)
| stats values(index) AS platforms count by normalized_user
| where count > 1
```

Purpose:
- Identify identities active on **multiple platforms**
- Reveal credential reuse and pivoting

---

## 🟡 ATTACK PATH 1: Windows → Linux

### 🔍 Step 1 – Windows Initial Access
```spl
index=windows_logs
EventCode=4624 LogonType IN (3,10)
| table _time host Account_Name Source_Network_Address
```

### 🔍 Step 2 – Linux Access Using Same Identity
```spl
index=linux_logs
(message="Accepted password*" OR message="Accepted publickey*")
| table _time host user src_ip
```

### 🔗 Correlation – Same User, Different Platforms
```spl
index IN (windows_logs, linux_logs)
| eval normalized_user=coalesce(user, Account_Name)
| stats values(host) by normalized_user
```

---

## 🟠 ATTACK PATH 2: Endpoint → Cloud Pivot

### 🔑 Step 1 – Endpoint Credential Access
```spl
index IN (windows_logs, linux_logs)
(command IN ("whoami","id","cmdkey","vaultcmd"))
| table _time host user command
```

### 🔑 Step 2 – Cloud Authentication
```spl
index=cloud_logs
(eventName IN ("ConsoleLogin","SignInLogs","GenerateAccessToken"))
| table _time user sourceIPAddress eventName
```

---

## 🔵 ATTACK PATH 3: Cloud → Endpoint Pivot

### 🔁 Step 1 – Cloud Role Abuse
```spl
index=cloud_logs
(eventName IN ("AttachUserPolicy","SetIamPolicy","AddMemberToRole"))
| table _time user target resource
```

### 🔁 Step 2 – Endpoint Access After Cloud Changes
```spl
index IN (windows_logs, linux_logs)
(EventCode=4624 OR message="Accepted*")
| table _time host user sourceIPAddress
```

---

## 🟣 ATTACK PATH 4: Linux ↔ Cloud Storage Abuse

### 📦 Step 1 – Linux Data Staging
```spl
index=linux_logs
(command IN ("tar","zip","gzip"))
| table _time host user command
```

### 📦 Step 2 – Cloud Storage Access
```spl
index=cloud_logs
(eventName IN ("PutObject","GetObject","Read","storage.objects.get"))
| stats count(object) AS files by user
```

---

## 🔥 Cross-Platform Exfiltration

### 📤 Endpoint-Based Exfiltration
```spl
index IN (linux_logs, windows_logs)
(command IN ("scp","rsync","curl","wget"))
| stats count by user host
| where count > 100
```

### 📤 Cloud-Based Exfiltration
```spl
index=cloud_logs
(eventName IN ("GetObject","Read","storage.objects.get"))
| stats count(object) AS files_downloaded by user
| where files_downloaded > 100
```

---

## 🧠 Timeline Reconstruction (Cross-Platform)

```spl
index IN (windows_logs, linux_logs, cloud_logs)
| eval normalized_user=coalesce(user, Account_Name, principalEmail)
| eval normalized_host=coalesce(host, ComputerName, resource)
| sort _time
| table _time normalized_user normalized_host index action eventName command sourceIPAddress
```

Purpose:
- Build a **single timeline** across all environments
- Track attacker movement and pivots

---

## 🛡️ SOC Analyst Investigation Notes
- Always pivot on **identity first**
- Look for short time gaps between platforms
- Validate IP reuse across systems
- Watch for cloud access after endpoint compromise
- Review newly created roles, keys, and tokens

---

## 🧠 MITRE ATT&CK Mapping

| Technique | Description |
|---------|-------------|
| T1078 | Valid Accounts |
| T1021 | Remote Services |
| T1550 | Use of Credentials |
| T1059 | Command Execution |
| T1041 | Exfiltration |
| T1071 | Command and Control |

---

## 📌 Summary
This file provides **advanced cross-platform attack path detection**, enabling SOC teams to identify and reconstruct attacks that span **Windows, Linux, and Cloud environments**, using **identity-centric correlation and Splunk advanced searches**.

