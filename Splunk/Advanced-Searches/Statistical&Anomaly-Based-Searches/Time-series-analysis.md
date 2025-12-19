# ⏱️ Time-Series Analysis
## Linux • Windows • Cloud (Advanced Splunk Detection Engineering)

This document focuses on **time-series analysis**, a powerful detection technique used to identify **behavioral changes over time**, including **spikes, drops, trends, and periodic patterns** that often indicate **attacks, automation, or misuse**.

Time-series analysis is essential for detecting:
- Beaconing and C2 activity
- Data exfiltration
- Lateral movement
- Account compromise
- Cloud abuse
- Low-and-slow attacks

Designed for:
- SOC Tier 2 / Tier 3 Analysts
- Threat Hunters
- Detection Engineers
- Splunk Mastery – Advanced Searches

---

## 🎯 Objectives
- Detect behavioral changes over time
- Identify spikes, trends, and periodicity
- Correlate time-based anomalies with attacks
- Support proactive threat hunting
- Enable detection of stealthy intrusions

---

## 🧠 What Is Time-Series Analysis?

Time-series analysis examines **how events evolve over time**, rather than looking at events in isolation.

It answers questions like:
- *What changed?*
- *When did it change?*
- *How fast did it change?*
- *Is the change recurring or periodic?*

> Attacks often reveal themselves through **timing**, not volume alone.

---

## 🧠 Time-Series Signals

| Signal | Description |
|------|------------|
| Spikes | Sudden increases in activity |
| Drops | Unexpected decreases |
| Trends | Gradual growth or decline |
| Periodicity | Repeating patterns |
| Seasonality | Time-of-day or day-of-week behavior |

---

## 🟡 FOUNDATION: TIME BUCKETING

### 🔍 Aggregate Events Over Time
```spl
index=*
| bucket _time span=5m
| stats count AS events by _time
```

Purpose:
- Convert raw events into time series
- Enable statistical analysis

---

## 🔴 SPIKE DETECTION

### 📈 Sudden Increase in Activity
```spl
index=network_logs
| bucket _time span=5m
| stats count AS events by src_ip _time
| eventstats avg(events) AS avg_events stdev(events) AS sd_events by src_ip
| where events > avg_events + (3*sd_events)
```

Purpose:
- Detect scanning, brute force, or automation
- Identify sudden attacker activity

---

## 🟠 DROP DETECTION

### 📉 Sudden Decrease in Activity
```spl
index=network_logs
| bucket _time span=5m
| stats count AS events by src_ip _time
| eventstats avg(events) AS avg_events stdev(events) AS sd_events by src_ip
| where events < avg_events - (3*sd_events)
```

Purpose:
- Detect evasion or service disruption
- Identify attacker suppression tactics

---

## 🔵 TREND ANALYSIS

### 📊 Gradual Increase Over Time
```spl
index=network_logs
| bucket _time span=1h
| stats count AS events by src_ip _time
| sort src_ip _time
```

Purpose:
- Detect slow data exfiltration
- Identify creeping lateral movement

---

## 🟣 PERIODICITY DETECTION

### 🔁 Repeating Time Intervals (Beaconing)
```spl
index=network_logs
| sort _time
| streamstats window=2 last(_time) AS prev_time by src_ip dest_ip
| eval interval=_time-prev_time
| stats avg(interval) AS avg_interval stdev(interval) AS sd_interval count by src_ip dest_ip
| where count > 20 AND sd_interval < 5
```

Purpose:
- Detect beaconing and automated callbacks
- Identify C2 communication

---

## 🔥 TIME-SERIES USER BEHAVIOR

### 👤 Abnormal User Activity Over Time
```spl
index IN (windows_logs, linux_logs)
| bucket _time span=1h
| stats count AS actions by user _time
| eventstats avg(actions) AS avg_actions stdev(actions) AS sd_actions by user
| where actions > avg_actions + (3*sd_actions)
```

Purpose:
- Detect compromised accounts
- Identify insider threats

---

## ☁️ CLOUD TIME-SERIES ANALYSIS

### ☁️ Abnormal API Call Trends
```spl
index=cloud_logs
| bucket _time span=5m
| stats count AS api_calls by user _time
| eventstats avg(api_calls) AS avg_calls stdev(api_calls) AS sd_calls by user
| where api_calls > avg_calls + (3*sd_calls)
```

Purpose:
- Detect cloud automation abuse
- Identify compromised service accounts

---

## 🔗 MULTI-SIGNAL TIME CORRELATION

### 🔑 Time-Based Correlation Across Sources
```spl
index IN (network_logs, windows_logs, linux_logs, cloud_logs)
| bucket _time span=5m
| table _time user host src_ip dest_ip action
```

Purpose:
- Correlate spikes across telemetry
- Reconstruct attack progression

---

## ⏱️ TIME-SERIES TIMELINE VIEW

```spl
index=*
| sort _time
| table _time user host action metric
```

Purpose:
- Visualize attacker behavior evolution
- Support incident reconstruction

---

## 🛡️ SOC RESPONSE & TUNING NOTES
- Tune time windows per use case
- Account for business hours and seasonality
- Combine with baselines and outlier detection
- Avoid alerting on single spikes
- Look for sustained or repeating patterns
- Use time-series analysis for hunting and detection

---

## 🧠 MITRE ATT&CK Mapping

| Technique | Description |
|---------|-------------|
| T1071 | Command & Control |
| T1041 | Exfiltration |
| T1046 | Network Service Discovery |
| T1078 | Valid Accounts |
| T1059 | Command Execution |

---

## 📌 Summary
This file provides **advanced time-series analysis techniques** that enable SOC teams to detect **behavioral changes, periodic activity, and stealthy attacks** across **Linux, Windows, and Cloud environments**, making it a critical component of **modern detection engineering and threat hunting**.

