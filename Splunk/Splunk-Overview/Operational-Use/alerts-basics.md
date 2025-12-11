# 🚨 Alerts Basics — Splunk Overview  
Foundations, Alert Types, Trigger Conditions, Actions, and Best Practices

Alerts in Splunk automate detection of critical events by monitoring searches and notifying teams when specific conditions occur.

They are used heavily in:
- Security Operations (SOC)  
- Incident Response  
- IT Operations & Monitoring  
- Compliance & Reporting  

---

# 1️⃣ What Are Splunk Alerts?

A **Splunk alert** is a scheduled search that triggers an action when the search results meet a defined condition.

Alerts help with:
- Detecting security threats in real-time  
- Monitoring system failures or anomalies  
- Identifying performance degradation  
- Sending notifications or taking automated actions  

Alerts can run:
- **Real-time**  
- **Scheduled (every X minutes/hours)**  

---

# 2️⃣ Types of Alerts

## ⭐ Real-time Alerts
Triggered immediately when search results meet conditions.

Used for:
- Brute-force attacks  
- Privilege escalation  
- Malware detection  
- Critical system failures  

---

## ⭐ Scheduled Alerts
Run on intervals (e.g., every 5 minutes).

Used for:
- Failed service restarts  
- Login trends  
- Traffic volume thresholds  
- Daily/weekly compliance reports  

---

# 3️⃣ Alert Trigger Conditions

Alerts are triggered based on:

## ✔ Number of results  
Example: Trigger alert when failed logins exceed 5
```spl
index=auth action=failure
| stats count
| where count > 5
```

---

## ✔ Specific field value  
Example: Trigger when CPU > 90%
```spl
index=os_metrics cpu_percent>90
```

---

## ✔ Custom SPL evaluation  
```spl
| eval is_suspicious=if(bytes_out > bytes_in*10, 1, 0)
| search is_suspicious=1
```

---

## ✔ Time-based behavior  
Example: Trigger alert when error events increase by 300% compared to normal.
```spl
| timechart count
| delta count as diff
| where diff > 300
```

---

# 4️⃣ Alert Actions

When an alert triggers, Splunk can:

## 🔔 Notifications
- Email  
- Slack  
- Microsoft Teams  
- Webhook  

---

## ⚙️ Automated Actions
- Run a script  
- Make a REST API call  
- Trigger SOAR automation  
- Send data to external systems  

---

## 📝 Output Actions
- Log event into index  
- Create a ticket in ServiceNow / Jira  
- Output results to lookup file  

---

# 5️⃣ Alert Severity Levels

Common severity categories:

| Level | Meaning |
|-------|---------|
| **Informational** | No action needed, for visibility only |
| **Low** | Minor anomaly, track behavior |
| **Medium** | Potential issue, requires analysis |
| **High** | Action needed soon |
| **Critical** | Immediate response required |

---

# 6️⃣ Alert Throttling

Alert throttling (suppressing duplicate alerts) prevents alert fatigue.

Example: Throttle for 30 minutes:
- Do not retrigger on same user  
- Do not retrigger on same IP  

```spl
Throttle:
Field: user
Duration: 30m
```

Useful for:
- Brute-force detection  
- Repeated failures  
- Host-based alerts  

---

# 7️⃣ Alert Scheduling

Common schedules:

- Every 1 minute — critical security  
- Every 5 minutes — authentication  
- Every 15 minutes — system health  
- Every hour — traffic trends  
- Daily — inventory or compliance reports  

---

# 8️⃣ Alert Configuration

Example alert definition (.conf file):
```
[failed_logins]
search = index=auth action=failure | stats count by user
cron_schedule = */5 * * * *
alert_type = number_of_results
alert_threshold = 5
alert_comparator = greater than
actions = email
action.email.to = soc-team@example.com
```

---

# 9️⃣ Best Practices

### ✔ Use throttling to prevent noise  
### ✔ Standardize naming: `ALERT - <category> - <description>`  
### ✔ Document all alerts in GitHub  
### ✔ Test alerts before enabling  
### ✔ Disable unused or noisy alerts  
### ✔ Never use heavy searches in real-time alerts  
### ✔ Use indexed fields or tstats when possible  
### ✔ Apply severity levels consistently  

---

# 🔟 Examples of Essential Alerts

## Authentication
- Brute force login attempts  
- Login from new location  
- Multiple failed logins  

## Network
- High outbound traffic  
- Port scanning behavior  
- DNS tunneling detection  

## Endpoint
- New admin account creation  
- Malware process execution  
- Suspicious PowerShell commands  

## OS Monitoring
- High CPU over time  
- Disk space < 10%  
- Critical service stopped  

---

# Summary

Splunk alerts:
- Continuously monitor events  
- Trigger when conditions match  
- Notify or automate responses  
- Are essential for SOC and IT operations  
- Must be tuned to reduce noise  


