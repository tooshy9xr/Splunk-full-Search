# ⏰ Cron Job Monitoring (Linux)
Fundamental Searches for Scheduled Task Activity

This file focuses on **monitoring cron jobs and scheduled tasks** on **Linux systems**, using **basic searches** suitable for the *Fundamental Searches* level.  
Monitoring cron jobs is critical for **detecting unauthorized scripts, persistence mechanisms, and misconfigured automated tasks**.

---

## 🎯 Purpose
- Track **cron job creation, modification, and execution**
- Detect **unauthorized or suspicious scheduled tasks**
- Identify **potential malware or persistence activity**
- Support SOC investigations and operational monitoring
- Enable proactive alerting

---

## 🖥️ Platforms Covered
- 🐧 Linux Servers & Endpoints
- ☁️ Cloud-hosted Linux VMs

---

## 📂 Common Log Sources
- `/var/log/cron`
- `/var/log/syslog`
- User-specific crontab (`crontab -l`)
- `/etc/cron.*` directories
- Application logs that schedule tasks

---

## 🧾 Sample Logs

### 🐧 Cron Job Execution
```
Feb 12 18:01:22 server01 CRON[1234]: (root) CMD (/usr/local/bin/backup.sh)
```

### 🐧 Cron Job Creation / Modification
```
Feb 12 18:03:10 server01 crontab[5678]: (alice) REPLACE /var/spool/cron/alice
```

### 🐧 Unauthorized Cron Execution
```
Feb 12 18:05:33 server01 CRON[9012]: (unknown) CMD (/tmp/malicious.sh)
```

---

## 🔍 Fundamental Search Examples

### ⏰ Cron Job Executions
```spl
index=linux_logs sourcetype=cron OR sourcetype=syslog
| table _time host user command
```

### 🔎 Unauthorized or Suspicious Jobs
```spl
| search command IN ("/tmp/*", "/var/tmp/*") OR user="unknown"
```

### 👤 User-Specific Cron Activity
```spl
| stats count by user command
```

---

## 🚨 Detection Scenarios

### 🔁 Multiple Executions of Suspicious Scripts
```spl
| stats count by command host
| where count > 5
```

### 🧨 Cron Jobs Created by Non-Admin Users
```spl
| search user!="root"
```

### 🌍 Jobs Executed from Temporary Directories
```spl
| search command IN ("/tmp/*", "/var/tmp/*")
```

---

## 🛡️ Mitigation & Response
- Restrict crontab access to authorized users
- Alert on creation of jobs in temporary directories
- Monitor high-frequency or unknown cron executions
- Validate scripts and commands being scheduled
- Remove unauthorized cron jobs immediately

---

## 📌 Summary
This file provides **fundamental cron job monitoring** for:
- Linux scheduled tasks and cron jobs
- Detection of unauthorized or suspicious task executions
- Operational and security visibility

