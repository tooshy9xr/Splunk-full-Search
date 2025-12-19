# ♻️ IOC Lifecycle Monitoring
## Threat Intelligence & IOC Enrichment (Advanced Splunk Detection Engineering)

This document focuses on **monitoring the full lifecycle of Indicators of Compromise (IOCs)**—from **ingestion and validation**, through **active detection**, to **expiration, decay, and retirement**.

IOC lifecycle monitoring ensures that detections remain:
- Relevant
- Accurate
- Timely
- Low-noise

Without lifecycle management, IOC-based detections quickly become **stale, noisy, and misleading**.

Designed for:
- SOC Tier 2 / Tier 3 Analysts
- Threat Intelligence Teams
- Detection Engineers
- Incident Responders
- Splunk Mastery – Advanced Searches

---

## 🎯 Objectives
- Track IOC freshness and relevance
- Detect active IOC hits in the environment
- Reduce false positives from stale IOCs
- Prioritize high-risk, recently active indicators
- Support intelligence-driven detection maturity

---

## 🧠 What Is the IOC Lifecycle?

An IOC typically moves through these stages:

| Stage | Description |
|-----|-------------|
| Ingestion | IOC collected from internal or external feeds |
| Validation | Confidence, source, and relevance assessed |
| Active | IOC actively matched in telemetry |
| Aging | IOC becomes less reliable over time |
| Expiration | IOC no longer considered actionable |
| Retirement | IOC removed from detection logic |

> IOCs have **half-lives** — context decays even if indicators don’t.

---

## 🧠 Assumed IOC Data Model

Assume threat intelligence is stored in:
- `index=threat_intel`
- Fields:
  - `ioc_value`
  - `ioc_type` (ip, domain, hash, url)
  - `threat_level`
  - `confidence`
  - `source`
  - `first_seen`
  - `last_seen`

---

## 🟡 IOC INGESTION & INVENTORY

### 📥 Active IOC Inventory
```spl
index=threat_intel
| stats count by ioc_type source
```

Purpose:
- Understand IOC coverage
- Track feed contributions

---

## 🔴 IOC ACTIVITY MONITORING

### 🚨 IOCs Actively Seen in Environment
```spl
index=*
| lookup threat_intel ioc_value AS indicator OUTPUT threat_level confidence last_seen
| where isnotnull(threat_level)
```

Purpose:
- Detect live threats
- Identify ongoing compromise

---

## 🟠 IOC AGE & FRESHNESS ANALYSIS

### ⏳ Identify Stale IOCs
```spl
index=threat_intel
| eval age_days=(now()-last_seen)/86400
| where age_days > 30
| table ioc_value ioc_type source age_days
```

Purpose:
- Identify indicators past useful lifetime
- Reduce false positives

---

## 🔵 IOC DECAY SCORING

### 📉 Apply Time-Based Confidence Decay
```spl
index=threat_intel
| eval age_days=(now()-last_seen)/86400
| eval decay_score=confidence-(age_days*0.5)
| where decay_score < 30
```

Purpose:
- Dynamically reduce IOC priority
- Automate aging logic

---

## 🟣 IOC REACTIVATION DETECTION

### 🔁 Old IOC Seen Again
```spl
index=*
| lookup threat_intel ioc_value AS indicator OUTPUT last_seen
| eval age_days=(now()-last_seen)/86400
| where age_days > 60
```

Purpose:
- Detect resurfacing infrastructure
- Identify reused attacker resources

---

## 🔥 MULTI-HIT IOC PRIORITIZATION

### 🔗 Repeated IOC Matches
```spl
index=*
| lookup threat_intel ioc_value AS indicator OUTPUT threat_level
| stats count by indicator threat_level
| where count > 5
```

Purpose:
- Identify high-risk, active indicators
- Escalate investigation priority

---

## ☁️ CLOUD IOC LIFECYCLE MONITORING

### ☁️ Cloud IOCs Actively Observed
```spl
index=cloud_logs
| lookup threat_intel ioc_value AS sourceIPAddress OUTPUT threat_level confidence
| where isnotnull(threat_level)
```

Purpose:
- Track cloud-specific threat activity
- Detect attacker infrastructure reuse

---

## 🔗 IOC + BEHAVIOR CORRELATION

### 🧠 IOC Hits With Anomalous Behavior
```spl
index IN (network_logs, windows_logs, linux_logs)
| lookup threat_intel ioc_value AS dest_ip OUTPUT threat_level
| where isnotnull(threat_level)
| table _time user host dest_ip action
```

Purpose:
- Increase detection confidence
- Avoid IOC-only false positives

---

## ⏱️ IOC LIFECYCLE TIMELINE

```spl
index=threat_intel
| sort first_seen
| table ioc_value ioc_type source first_seen last_seen threat_level confidence
```

Purpose:
- Track IOC lifespan
- Support intelligence reporting

---

## 🛡️ SOC & THREAT INTEL OPERATIONS NOTES
- Prioritize fresh, high-confidence IOCs
- Expire indicators automatically after defined periods
- Track false positives and feed quality
- Use IOC hits as **context**, not sole evidence
- Combine IOC alerts with anomaly-based detections
- Share reactivated IOCs with intelligence partners

---

## 🧠 MITRE ATT&CK Mapping

| Technique | Description |
|---------|-------------|
| T1071 | Command & Control |
| T1105 | Ingress Tool Transfer |
| T1041 | Exfiltration |
| T1588 | Obtain Capabilities |
| T1595 | Active Scanning |

---

## 📌 Summary
This file provides **advanced IOC lifecycle monitoring techniques** that enable SOC and Threat Intelligence teams to **maintain high-fidelity detections**, reduce **noise from stale indicators**, and ensure **IOC-based alerts remain actionable, timely, and context-aware** throughout the indicator’s lifecycle.

