# 📡 Command & Control (C2) Behavior Detection  
Advanced Post-Compromise Communication Analytics  
(Windows • Linux • Cloud)

---

## 📁 Folder Context (Professional Description)

The **Command & Control (C2) Behavior** module focuses on detecting **malicious communication channels** established by compromised systems to attacker-controlled infrastructure.  
Rather than relying on known IPs or domains only, this module emphasizes **behavioral indicators** such as beaconing, protocol abuse, timing patterns, and anomalous network usage.

C2 detection is a **critical phase in the attack lifecycle**, occurring after initial compromise and before major impact.

---

## 🎯 File Objective

`Command&Control(C2)behavior.md` is designed to:
- Detect **post-exploitation attacker communications**
- Identify **beaconing and callback patterns**
- Uncover **covert and encrypted C2 channels**
- Correlate endpoint, network, and cloud telemetry
- Support advanced threat hunting and IR response

---

## 🧩 Threat Context

Mapped to **MITRE ATT&CK**:
- T1071 – Application Layer Protocol  
- T1095 – Non-Application Layer Protocol  
- T1105 – Ingress Tool Transfer  
- T1571 – Non-Standard Port  
- TA0011 – Command and Control  

Attackers often:
- Establish persistent outbound connections
- Use common protocols (HTTP, HTTPS, DNS)
- Encrypt traffic to evade inspection
- Mimic legitimate application behavior

---

## 📊 Data Sources

| Source | Description |
|------|------------|
| Network Traffic Logs | Firewall, proxy, IDS |
| DNS Logs | Query patterns & domains |
| Endpoint EDR Logs | Process-network linkage |
| Web Proxy Logs | URL & user-agent analysis |
| Cloud Logs | VM and workload egress |
| Threat Intel Feeds | Known C2 indicators |

---

## 🔗 C2 Lifecycle Overview

1️⃣ Initial Callback  
2️⃣ Beaconing & Heartbeat  
3️⃣ Tasking & Response  
4️⃣ Payload Download / Upload  
5️⃣ Persistence & Fallback Channels  

---

## 🔍 Advanced Detection Patterns (18 Scenarios)

---

## 🌐 Network-Based C2 Indicators

### 1️⃣ Periodic Beaconing (Fixed Intervals)
```spl
| timechart span=5m count by dest_ip
```
📌 Regular, low-volume callbacks.

---

### 2️⃣ Low-Volume, Long-Lived Connections
```spl
| stats sum(bytes) avg(duration) by dest_ip
```
📌 Silent but persistent communication.

---

### 3️⃣ Rare External Destinations
```spl
| stats count by dest_ip
| where count < 3
```
📌 Previously unseen endpoints.

---

### 4️⃣ Non-Standard Port Usage
```spl
| search dest_port NOT IN (80,443,53)
```
📌 Custom or tunneled C2 channels.

---

### 5️⃣ High Entropy Payloads
```spl
| stats avg(payload_entropy) by dest_ip
```
📌 Encrypted or obfuscated traffic.

---

## 🧠 DNS-Based C2 Indicators

### 6️⃣ DGA-Like Domain Patterns
```spl
| eval domain_len=len(query)
| where domain_len > 25
```
📌 Algorithmically generated domains.

---

### 7️⃣ Excessive NXDOMAIN Responses
```spl
| stats count by src_ip response
```
📌 Domain cycling behavior.

---

### 8️⃣ Unusual DNS Record Types
```spl
| search record_type IN ("TXT","NULL","AAAA")
```
📌 Data exfiltration via DNS.

---

### 9️⃣ High-Frequency DNS Queries
```spl
| stats count by src_ip query
| where count > 100
```
📌 Beaconing over DNS.

---

## 🪟 Endpoint-Based C2 Indicators

### 🔟 Suspicious Process with Network Traffic
```spl
| search process!="chrome.exe" AND bytes_out>0
```
📌 Non-browser processes communicating externally.

---

### 1️⃣1️⃣ LOLBins with Network Activity
```spl
process IN ("powershell.exe","curl","wget","certutil.exe")
```
📌 Living-off-the-land C2.

---

### 1️⃣2️⃣ Network Activity After Login
```spl
| transaction user maxspan=10m
```
📌 Post-compromise callback.

---

### 1️⃣3️⃣ Network Activity from Temp Paths
```spl
process_path IN ("*\\Temp\\*","*/tmp/*")
```
📌 Malware staging locations.

---

## ☁️ Cloud & Cross-Environment C2

### 1️⃣4️⃣ Cloud VM Unexpected Egress
```spl
index=cloud_network direction=outbound
```
📌 Compromised workloads.

---

### 1️⃣5️⃣ API-Based C2 Behavior
```spl
auth_method="token"
```
📌 Abuse of cloud APIs for control.

---

### 1️⃣6️⃣ Traffic to Newly Registered Domains
```spl
| lookup newly_registered_domains domain as dest_domain
```
📌 Fast-flux infrastructure.

---

### 1️⃣7️⃣ User-Agent Anomalies
```spl
| stats count by user_agent
| where count < 2
```
📌 Custom malware clients.

---

### 1️⃣8️⃣ Fallback C2 Channel Detection
```spl
| stats dc(protocol) by src_ip
| where dc(protocol) > 2
```
📌 Multiple communication methods.

---

## 🧠 Behavioral Indicators Summary
- Periodic beaconing
- Rare or new destinations
- Encrypted low-volume traffic
- DNS abuse and DGA behavior
- LOLBins with network access
- Cloud workload egress anomalies

---

## 🛡️ Response & Mitigation
- Block identified C2 endpoints immediately
- Isolate affected hosts or workloads
- Rotate compromised credentials
- Perform full memory and disk analysis
- Hunt for lateral movement and payloads

---

## 📌 Final Summary

This module delivers **advanced behavioral detection of Command & Control activity** across:
- 🪟 Windows
- 🐧 Linux
- ☁️ Cloud environments

By focusing on **communication behavior rather than static indicators**, SOC teams can **detect stealthy C2 channels and disrupt attacker control early**.


