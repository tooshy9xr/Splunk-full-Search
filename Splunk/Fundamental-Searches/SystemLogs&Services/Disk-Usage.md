# 💽 Disk Usage Monitoring (Windows & Linux)
Fundamental Searches for Storage & Disk Anomalies

This file focuses on **monitoring disk usage and storage behavior** across **Windows and Linux systems**, using **basic searches** suitable for the *Fundamental Searches* level.  
Disk anomalies often indicate **misconfiguration, malware activity, log flooding, or system failure risks**.

---

## 🎯 Purpose
- Monitor **disk space utilization**
- Detect **rapid disk consumption**
- Identify **low disk space conditions**
- Spot **suspicious file growth**
- Support operational and security investigations

---

## 🖥️ Platforms Covered
- 🪟 Windows Servers & Workstations
- 🐧 Linux Servers & Endpoints
- ☁️ Virtual & Cloud Instances

---

## 📂 Common Log Sources

### 🪟 Windows
- Windows Performance Counters
- Event Viewer (System)
- WMI metrics

### 🐧 Linux
- `/var/log/syslog`
- `/var/log/messages`
- `df`, `du` output logs
- Node exporter / agent logs

---

## 🧾 Sample Logs

### 🪟 Windows – Disk Space Warning
```
2025-02-12 10:21:44 Host=WIN-SRV01 Disk=C: FreeSpace=8% Total=500GB
```

### 🪟 Windows – Rapid Disk Growth
```
2025-02-12 10:23:10 Host=WIN-SRV01 Disk=C: UsedSpace=92% GrowthRate=+15%/10m
```

---

### 🐧 Linux – Disk Usage Snapshot
```
Feb 12 10:31:22 server01 df -h / Used=88% Available=12%
```

### 🐧 Linux – Partition Full
```
Feb 12 10:33:55 server01 kernel: EXT4-fs warning: disk nearly full on /var
```

---

## 🔍 Fundamental Search Examples

### 💽 Current Disk Usage
```spl
(Disk=*) 
| table _time host Disk UsedSpace FreeSpace
```

### 🚨 Low Disk Space Detection
```spl
FreeSpace < 10
```

### 📈 Rapid Disk Consumption
```spl
| sort _time
| streamstats current=f last(UsedSpace) as prev by host Disk
| eval growth=UsedSpace-prev
| where growth > 10
```

---

## 🚨 Detection Scenarios

### ⚠️ Disk Almost Full
```spl
FreeSpace < 5
```

### 🧨 Disk Exhaustion by Logs
```spl
(source="/var/log/*")
| stats sum(bytes) by host
```

### ☁️ Cloud VM Storage Risk
```spl
| stats avg(UsedSpace) by host
| where avg > 80
```

---

## 🛡️ Mitigation & Response
- Clean old logs
- Rotate logs properly
- Expand disk capacity
- Identify abnormal file growth
- Alert before disk exhaustion

---

## 📌 Summary
This file provides **fundamental disk usage visibility** for:
- Windows disk and volume monitoring
- Linux filesystem utilization
- Operational health and anomaly detection


