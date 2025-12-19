# 🚫 Threshold-less Detection
## Linux • Windows • Cloud (Advanced Splunk Detection Engineering)

This document focuses on **threshold-less detection**, an advanced detection engineering approach that **does not rely on static thresholds** (e.g., count > 100).  
Instead, it detects threats using **relative behavior, peer comparison, baselines, rarity, and trends**.

Threshold-less detection is critical for identifying:
- Low-and-slow attacks
- Living-off-the-land techniques
- Insider threats
- APT activity
- Cloud and identity abuse
- Stealthy post-exploitation behavior

Designed for:
- SOC Tier 2 / Tier 3 Analysts
- Threat Hunters
- Detection Engineers
- Splunk Mastery – Advanced Searches

---

## 🎯 Objectives
- Detect malicious behavior without hard thresholds
- Reduce false positives caused by static limits
- Identify subtle attacker activity
- Adapt detections automatically to environment size
- Improve detection maturity and resilience

---

## 🧠 Why Threshold-less Detection?

Static thresholds fail when:
- Environments grow or shrink
- Attackers stay below limits
- Behavior varies by role
- Cloud workloads auto-scale

Threshold-less detection focuses on:
- **Deviation**
- **Rarity**
- **Relative comparison**
- **Behavioral change**

> If something behaves differently than its peers — it deserves attention.

---

## 🧠 Core Threshold-less Techniques

| Technique | Description |
|--------|-------------|
| Baseline Deviation | Compare current vs historical behavior |
| Peer Group Analysis | Compare entity vs similar entities |
| Outlier Detection | Identify rare behavior |
| Trend Change | Detect behavioral shifts over time |
| Combination Rarity | Rare multi-attribute behavior |

---

## 🟡 BASELINE DEVIATION (NO STATIC LIMITS)

### 🔍 Deviation From Historical Behavior
```spl
index=network_logs
| stats avg(bytes) AS baseline_bytes by src_ip
| join src_ip [
    search index=network_logs
    | stats sum(bytes) AS current_bytes by src_ip
]
| eval deviation_ratio=current_bytes/baseline_bytes
| where deviation_ratio > 3
```

Purpose:
- Detect abnormal data movement
- Baseline automatically adapts per host

---

## 🔴 PEER GROUP ANALYSIS

### 👥 Entity vs Peer Comparison
```spl
index=windows_logs
| stats count AS actions by user
| eventstats avg(actions) AS peer_avg stdev(actions) AS peer_sd
| eval deviation=(actions-peer_avg)/peer_sd
| where deviation > 3
```

Purpose:
- Detect users behaving differently than peers
- Identify compromised or malicious insiders

---

## 🟠 RARITY-BASED DETECTION

### 🧬 Rare Actions Without Thresholds
```spl
index=cloud_logs
| stats count by eventName
| eventstats max(count) AS max_count
| eval rarity_score=max_count/count
| where rarity_score > 10
```

Purpose:
- Detect uncommon cloud actions
- Highlight high-risk API usage

---

## 🔵 TREND-CHANGE DETECTION

### 📈 Behavioral Shift Over Time
```spl
index=network_logs
| bucket _time span=1h
| stats count AS events by src_ip _time
| sort src_ip _time
| streamstats window=5 avg(events) AS rolling_avg by src_ip
| eval change_ratio=events/rolling_avg
| where change_ratio > 3
```

Purpose:
- Detect sudden behavioral changes
- Identify emerging attacks

---

## 🟣 COMBINATION RARITY (HIGH-FIDELITY)

### 🔗 Rare User + Host + Action
```spl
index IN (windows_logs, linux_logs)
| stats count by user host command
| eventstats avg(count) AS avg_count
| eval rarity=avg_count/count
| where rarity > 10
```

Purpose:
- Catch living-off-the-land attacks
- High signal, low noise detection

---

## ☁️ CLOUD THRESHOLD-LESS DETECTION

### ☁️ Abnormal API Usage Patterns
```spl
index=cloud_logs
| stats count AS api_calls by user
| eventstats avg(api_calls) AS avg_calls stdev(api_calls) AS sd_calls
| eval deviation=(api_calls-avg_calls)/sd_calls
| where deviation > 3
```

Purpose:
- Detect compromised service accounts
- Identify automation abuse

---

## 🔗 CROSS-SIGNAL CORRELATION

### 🔑 Weak Signals Combined (No Thresholds)
```spl
index IN (network_logs, windows_logs, linux_logs)
| table _time user host src_ip dest_ip action
```

Purpose:
- Combine low-confidence signals
- Detect attacks missed by single-rule alerts

---

## ⏱️ THRESHOLD-LESS TIMELINE VIEW

```spl
index=*
| sort _time
| table _time user host action metric deviation_score
```

Purpose:
- Visualize behavioral deviation over time
- Support investigation and response

---

## 🛡️ SOC RESPONSE & TUNING NOTES
- Prefer deviation over absolute values
- Tune peer groups carefully (role, asset type)
- Combine multiple weak signals
- Avoid alerting on single deviations
- Track persistence of abnormal behavior
- Use threshold-less detections for hunting and high-confidence alerts

---

## 🧠 MITRE ATT&CK Mapping

| Technique | Description |
|---------|-------------|
| T1078 | Valid Accounts |
| T1059 | Command Execution |
| T1041 | Exfiltration |
| T1071 | Command & Control |
| T1021 | Remote Services |

---

## 📌 Summary
This file provides **advanced threshold-less detection techniques** that enable SOC teams to detect **stealthy, adaptive, and low-volume attacks** across **Linux, Windows, and Cloud environments**, without relying on fragile static thresholds—making detections **more resilient, scalable, and attacker-resistant**.

