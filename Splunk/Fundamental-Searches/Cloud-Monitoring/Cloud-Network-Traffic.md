# ☁️🌐 Cloud Network Traffic Monitoring
Fundamental Searches for Cloud Network Activity

This file focuses on **monitoring network traffic in cloud environments** across **AWS, Azure, and GCP**, using **basic searches** suitable for the *Fundamental Searches* level.  
Cloud network traffic monitoring is essential for detecting **lateral movement, data exfiltration, misconfigurations, and external attacks**.

---

## 🎯 Purpose
- Monitor **ingress and egress network traffic**  
- Detect **suspicious connections and abnormal patterns**  
- Identify **unauthorized open ports and exposed services**  
- Track **internal lateral movement**  
- Support SOC investigations and cloud incident response  

---

## ☁️ Cloud Platforms Covered

### 🟠 AWS
- VPC Flow Logs  
- Security Group & NACL activity  

### 🔵 Azure
- NSG Flow Logs  
- Azure Firewall logs  

### 🟢 GCP
- VPC Flow Logs  
- Firewall rule logs  

---

## 📂 Common Log Sources
- **AWS VPC Flow Logs** – Network traffic records  
- **Azure NSG Flow Logs** – Allowed/denied connections  
- **Azure Firewall Logs** – Application & network rules  
- **GCP VPC Flow Logs** – VM network activity  

---

## 🧾 Sample Logs

### 🌐 AWS – VPC Flow Log
```
2025-03-03 12:01:22 srcaddr=10.0.1.5 dstaddr=34.120.10.8 dstport=443 action=ACCEPT bytes=2048
```

### 🌐 Azure – NSG Flow Log
```
2025-03-03 12:03:10 SrcIP=10.2.0.10 DestIP=52.168.1.20 DestPort=3389 Action=Allow
```

### 🌐 GCP – VPC Flow Log
```
2025-03-03 12:05:33 src_ip=10.128.0.5 dest_ip=8.8.8.8 dest_port=53 action=ALLOW
```

---

## 🔍 Fundamental Search Examples

### 📊 High Volume Egress Traffic
```spl
| stats sum(bytes) by srcaddr destaddr
| where sum(bytes) > 1000000
```

### 🚪 Connections to Sensitive Ports
```spl
| search destport IN (22,3389,445,3306)
```

### 🌍 External Network Connections
```spl
| search srcaddr IN (10.0.0.0/8) AND destaddr NOT IN (10.0.0.0/8)
```

---

## 🚨 Detection Scenarios

### 🧨 Data Exfiltration Indicators
```spl
| stats sum(bytes) by srcaddr
| where sum(bytes) > threshold
```

### ⚠️ Open Management Ports to Internet
```spl
| search destport IN (22,3389) AND action=ACCEPT
```

### 🔁 Lateral Movement in Cloud Network
```spl
| stats dc(destaddr) as hosts by srcaddr
| where hosts > 5
```

---

## 🛡️ Mitigation & Response
- Restrict exposed services and management ports  
- Apply least-privilege security group rules  
- Monitor and alert on unusual traffic patterns  
- Correlate network logs with IAM and endpoint logs  
- Implement network segmentation  

---

## 📌 Summary
This file provides **fundamental cloud network traffic monitoring** for:
- AWS, Azure, and GCP environments  
- Detecting suspicious connections and data exfiltration  
- Improving cloud network security visibility  
