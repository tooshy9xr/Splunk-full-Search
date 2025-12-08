# 🌟 Service Start/Stop — Windows & Linux

A beginner‑friendly list of Splunk searches to monitor service start and stop activity on Windows and Linux systems. Each search includes a short description, purpose, and ready‑to‑use SPL query.

---

## 🖥️ Windows Service Monitoring

🔹 **1. Service Start Events**

**Description:** Shows events where Windows services were started.

**Purpose:** Helps track expected and unexpected service activations.

```spl
index=windows sourcetype=WinEventLog:System EventCode=7036 "service entered the running state"
```

---

🔹 **2. Service Stop Events**

**Description:** Displays events where Windows services were stopped.

**Purpose:** Detects shutdown of critical services.

```spl
index=windows sourcetype=WinEventLog:System EventCode=7036 "service entered the stopped state"
```

---

🔹 **3. Service State Changes by Service Name**

**Description:** Groups service start/stop events by service name.

**Purpose:** Helps identify services frequently started or stopped.

```spl
index=windows sourcetype=WinEventLog:System EventCode=7036 | stats count by Service_Name
```

---

🔹 **4. Service Activity per Hour**

**Description:** Shows hourly service state changes.

**Purpose:** Useful for spotting unusual activity spikes.

```spl
index=windows sourcetype=WinEventLog:System EventCode=7036 | timechart span=1h count
```

---

## 🐧 Linux Service Monitoring

🔹 **1. Service Start Events**

**Description:** Displays events where Linux services were started (systemd).

**Purpose:** Monitors activation of important services.

```spl
index=linux sourcetype=linux_syslog "Started" "service"
```

---

🔹 **2. Service Stop Events**

**Description:** Shows events where Linux services were stopped.

**Purpose:** Helps detect unexpected service interruptions.

```spl
index=linux sourcetype=linux_syslog "Stopped" "service"
```

---

🔹 **3. Service Changes by Name**

**Description:** Counts start/stop events grouped by service.

**Purpose:** Identifies services with frequent state changes.

```spl
index=linux sourcetype=linux_syslog ("Started" OR "Stopped") | stats count by service
```

---

🔹 **4. Service Activity per Hour**

**Description:** Shows service start/stop events aggregated hourly.

**Purpose:** Detects anomalies in service behavior.

```spl
index=linux sourcetype=linux_syslog ("Started" OR "Stopped") | timechart span=1h count
```
