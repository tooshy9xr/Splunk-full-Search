# ☁️🔗 Cross-Cloud Correlation
## Cloud & Hybrid Advanced Detection (AWS • Azure • GCP)

This document focuses on **cross-cloud correlation**, where attackers abuse **multiple cloud providers** (AWS, Azure, GCP) during a single intrusion by reusing **identities, infrastructure, techniques, or automation**.

Cross-cloud attacks are dangerous because:
- Visibility is often siloed per provider
- Identity reuse spans clouds
- Detection gaps exist between platforms
- Attackers exploit inconsistent controls

Designed for:
- SOC Tier 2 / Tier 3 Analysts
- Cloud Security Engineers
- Threat Hunters
- Detection Engineers
- Splunk Mastery – Advanced Searches

---

## 🎯 Objectives
- Correlate attacker activity across AWS, Azure, and GCP
- Detect identity and infrastructure reuse across clouds
- Identify coordinated multi-cloud attacks
- Reconstruct cross-cloud attack paths
- Improve cloud-wide detection coverage

---

## 🧠 What Is Cross-Cloud Correlation?

Cross-cloud correlation identifies:
- Same user or service account active in multiple clouds
- Shared IPs, regions, or tooling across providers
- Similar attack techniques executed in parallel
- Automation or scripts targeting multiple clouds
- Staged attacks that pivot between cloud platforms

> Multi-cloud is an attacker advantage unless detections are unified.

---

## 🧠 Common Cross-Cloud Attack Patterns

| Pattern | Description |
|-------|-------------|
| Identity Reuse | Same email / name across clouds |
| Token Abuse | Reused OAuth / API tokens |
| Infrastructure Reuse | Same IPs, ASNs, regions |
| Parallel IAM Abuse | Simultaneous privilege escalation |
| Coordinated Exfiltration | Data pulled from multiple clouds |

---

## 🟡 NORMALIZED CLOUD DATA MODEL

Assume logs are normalized into:
- `index=cloud_logs`

Normalized fields:
- `user`
- `eventName`
- `provider` (aws, azure, gcp)
- `resource`
- `sourceIPAddress`
- `userAgent`

---

## 🔴 IDENTITY REUSE ACROSS CLOUDS

### 👤 Same Identity Active in Multiple Clouds
```spl
index=cloud_logs
| stats dc(provider) AS cloud_count values(provider) by user
| where cloud_count > 1
```

Purpose:
- Detect identity reuse across providers
- Identify compromised users or service accounts

---

## 🟠 IAM ABUSE ACROSS CLOUDS

### 🔐 Privilege Changes in Multiple Providers
```spl
index=cloud_logs
| search eventName IN (
    "AttachUserPolicy",
    "SetIamPolicy",
    "AddMemberToRole",
    "AssignRole"
)
| stats values(provider) by user
```

Purpose:
- Detect coordinated IAM abuse
- Identify cloud-wide privilege escalation

---

## 🔵 SHARED INFRASTRUCTURE CORRELATION

### 🌐 Same Source IP Used Across Clouds
```spl
index=cloud_logs
| stats dc(provider) AS cloud_count values(provider) by sourceIPAddress
| where cloud_count > 1
```

Purpose:
- Detect attacker infrastructure reuse
- Identify centralized attack control points

---

## 🟣 USER AGENT & TOOLING REUSE

### 🤖 Identical User Agents Across Providers
```spl
index=cloud_logs
| stats dc(provider) AS cloud_count by userAgent
| where cloud_count > 1
```

Purpose:
- Detect automation or attacker tooling
- Identify scripted cross-cloud attacks

---

## 🔥 CROSS-CLOUD PRIVILEGE ESCALATION CHAINS

### 🔗 Escalation in One Cloud → Access in Another
```spl
index=cloud_logs
| sort _time
| table _time user provider eventName resource
```

Purpose:
- Reconstruct multi-cloud attack paths
- Identify pivot points between providers

---

## ☁️ CROSS-CLOUD DATA ACCESS & EXFILTRATION

### 📦 Sensitive Data Access in Multiple Clouds
```spl
index=cloud_logs
| search eventName IN ("GetObject","Read","DownloadBlob","storage.objects.get")
| stats values(provider) by user
```

Purpose:
- Detect coordinated data theft
- Identify full-scope compromise

---

## 🔗 CROSS-CLOUD + THREAT INTEL CORRELATION

### 🧠 Known Malicious Infrastructure Used Across Clouds
```spl
index=cloud_logs
| lookup threat_intel ioc_value AS sourceIPAddress OUTPUT threat_level
| where isnotnull(threat_level)
```

Purpose:
- Increase confidence using external intel
- Identify known attacker infrastructure

---

## ⏱️ CROSS-CLOUD ATTACK TIMELINE

```spl
index=cloud_logs
| sort _time
| table _time user provider eventName resource sourceIPAddress
```

Purpose:
- Visualize attacker activity across clouds
- Support coordinated incident response

---

## 🛡️ SOC RESPONSE & MULTI-CLOUD IR NOTES
- Treat cross-cloud identity abuse as high severity
- Revoke credentials across all providers
- Review IAM trust relationships and federation
- Rotate API keys and tokens globally
- Align logging and retention across clouds
- Coordinate response with cloud owners

---

## 🧠 MITRE ATT&CK Mapping

| Technique | Description |
|---------|-------------|
| T1078 | Valid Accounts |
| T1098 | Account Manipulation |
| T1087 | Account Discovery |
| T1530 | Data from Cloud Storage |
| T1071 | Command & Control |

---

## 📌 Summary
This file provides **advanced cross-cloud correlation techniques** that enable SOC and cloud security teams to detect **coordinated attacks spanning AWS, Azure, and GCP**, breaking down visibility silos and restoring defender advantage in **multi-cloud environments**.

