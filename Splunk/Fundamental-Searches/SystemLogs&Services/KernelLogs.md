# 🐧 Kernel Logs (Linux)
Fundamental Searches for Linux Kernel Events

This file focuses on **monitoring Linux kernel logs**, using **basic searches** suitable for the *Fundamental Searches* level.  
Kernel logs are critical for **detecting hardware issues, driver failures, system crashes, and suspicious activity at the OS level**.

---

## 🎯 Purpose
- Track **kernel errors and warnings**
- Detect **hardware failures**
- Monitor **driver and module issues**
- Identify **security-relevant kernel messages**
- Support SOC and operational troubleshooting

---

## 🖥️ Platforms Covered
- 🐧 Linux Servers & Endpoints
- ☁️ Virtual Linux Machines

---

## 📂 Common Log Sources
- `/var/log/kern.log`
- `/var/log/messages`
- `dmesg`
- Systemd journal (`journalctl -k`)

---

## 🧾 Sample Logs

### ⚠️ Kernel Error
```
Feb 12 12:01:22 server01 kernel: BUG: unable to handle kernel NULL pointer dereference
```

### ⚠️ Module Failure
```
Feb 12 12:03:11 server01 kernel: device eth0: failed to initialize driver
```

### ⚠️ OOM (Out of Memory)
```
Feb 12 12:05:44 server01 kernel: Out of memory: Kill process 2134 (apache2) score 512 or sacrifice child
```

### ⚠️ Disk I/O Error
```
Feb 12 12:07:22 server01 kernel: EXT4-fs error (device sda1): ext4_journal_check_start: Detected aborted journal
```

---

## 🔍 Fundamental Search Examples

### ⚠️ Kernel Errors & Warnings
```spl
index=linux_logs sourcetype=kern.log "error" OR "warning" OR "BUG"
```

### 🐧 Out of Memory Events
```spl
index=linux_logs sourcetype=kern.log "Out of memory"
```

### 🖥️ Disk / File System Kernel Errors
```spl
index=linux_logs sourcetype=kern.log "EXT4-fs error" OR "I/O error"
```

---

## 🚨 Detection Scenarios

### 💥 Critical Kernel Errors
- Track repeated kernel panics or BUG messages
```spl
index=linux_logs sourcetype=kern.log "BUG"
| stats count by host
| where count > 1
```

### 🔄 Driver / Module Failures
```spl
index=linux_logs sourcetype=kern.log "failed to initialize driver"
```

### 🛡️ Hardware Issues
- Disk, memory, or network driver errors
```spl
index=linux_logs sourcetype=kern.log "I/O error" OR "segfault"
```

---

## 🛡️ Mitigation & Response
- Review hardware health (disk, memory)
- Patch kernel and drivers
- Restart affected services or modules
- Monitor for repeated failures
- Escalate persistent kernel panics

---

## 📌 Summary
This file provides **fundamental kernel log monitoring** for:
- Linux OS stability
- Hardware and driver error detection
- Security-relevant kernel events

