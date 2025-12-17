# 🔌🖨️ Peripheral Device Monitoring  
Fundamental Searches for External Device Activity  
(Windows • Linux • macOS)

This file focuses on **monitoring peripheral and external device activity** across **endpoints**, using **basic searches** suitable for the *Fundamental Searches* level.  
Peripheral monitoring is critical for detecting **data exfiltration, unauthorized devices, malware delivery, and policy violations**.

---

## 🎯 Purpose
- Monitor **USB, external storage, and peripheral usage**
- Detect **unauthorized or unknown devices**
- Track **device insertion and removal events**
- Identify **potential data leakage or malware delivery**
- Support SOC investigations and endpoint security monitoring

---

## 🖥️ Platforms Covered

### 🪟 Windows
- USB & Plug-and-Play logs
- Windows Security & System Event Logs
- Defender / EDR device control logs

### 🐧 Linux
- Syslog / journalctl
- udev and kernel logs
- Audit framework logs

### 🍎 macOS
- Unified logs
- USB and hardware subsystem logs
- Endpoint security events

---

## 📂 Common Log Sources
- OS device and hardware logs
- Endpoint Detection & Response (EDR)
- Device control and DLP logs
- Kernel and driver logs

---

## 🧾 Sample Logs

### 🪟 Windows – USB Device Inserted
```
2025-03-10 10:01:22 EventID=2003 Device=USBSTOR\\Disk&Ven_SanDisk
```

### 🪟 Windows – USB Device Removed
```
2025-03-10 10:03:10 EventID=2102 Device=USBSTOR\\Disk&Ven_SanDisk
```

### 🐧 Linux – USB Storage Detected
```
Mar 10 10:05:33 laptop01 kernel: usb 2-1: new high-speed USB device detected
```

### 🍎 macOS – External Device Connected
```
2025-03-10 10:07:11 subsystem=USB user=alice action=device_connected
```

---

## 🔍 Fundamental Search Examples

### 🔌 All Peripheral Device Events
```spl
| search Device=* OR "USB"
| table _time user host Device action
```

### 🚫 Unauthorized USB Devices
```spl
| search Device NOT IN ("ApprovedVendor1","ApprovedVendor2")
```

### 🔁 Frequent Device Insertions
```spl
| stats count by user Device
| where count > 5
```

### 📦 USB Storage Usage
```spl
| search Device="USBSTOR*"
```

---

## 🚨 Detection Scenarios

### 🧨 Data Exfiltration via USB
```spl
| search action="write" AND Device="USBSTOR*"
```

### ⚠️ Device Usage Outside Business Hours
```spl
| where date_hour < 8 OR date_hour > 18
```

### 🕵️ Unknown or Rare Devices
```spl
| stats count by Device
| where count < 2
```

---

## 🛡️ Mitigation & Response
- Enforce USB and device control policies
- Block unauthorized storage devices
- Enable DLP for removable media
- Alert on unusual peripheral usage
- Investigate endpoints with suspicious device activity

---

## 📌 Summary
This file provides **fundamental monitoring of peripheral device activity** across:
- 🪟 Windows
- 🐧 Linux
- 🍎 macOS

It helps detect **unauthorized devices, data leakage, and malware delivery risks**.


