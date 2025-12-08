# 🌟 Account Lockouts — Windows & Linux

A beginner-friendly list of Splunk searches to monitor account lockout activity on Windows and Linux systems. Each search includes a short description, purpose, and ready-to-use SPL query.

---

## 🖥️ Windows Account Lockouts

🔹 **1. Basic Account Lockout Events**

**Description:** Shows events where Windows accounts were locked due to failed login attempts.

**Purpose:** Helps detect brute‑force attacks or repeated failed authentication.

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4740
```

---

🔹 **2. Locked-Out Accounts by Username**

**Description:** Groups lockout events by the affected user.

**Purpose:** Identifies which user accounts are being targeted.

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4740 | stats count by TargetUserName
```

---

🔹 **3. Lockouts by Source IP**

**Description:** Displays the source IPs that caused the lockout.

**Purpose:** Helps track attackers or misconfigured systems.

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4740 | stats count by SourceNetworkAddress
```

---

🔹 **4. Account Lockouts per Hour**

**Description:** Shows hourly trends of account lockout events.

**Purpose:** Detects spikes or ongoing attack attempts.

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4740 | timechart span=1h count
```

---

## 🐧 Linux Account Lockouts

🔹 **1. Basic Lockout Events (Fail2Ban, PAM)**

**Description:** Displays Linux account lockouts from PAM or Fail2Ban.

**Purpose:** Helps detect authentication failures leading to lockouts.

```spl
index=linux sourcetype=linux_secure ("pam_tally" OR "pam_faillock" OR "fail2ban") "locked"
```

---

🔹 **2. Locked-Out Users**

**Description:** Groups lockout events by username.

**Purpose:** Identifies which accounts are being targeted.

```spl
index=linux sourcetype=linux_secure "locked" | stats count by user
```

---

🔹 **3. Lockouts by Source IP**

**Description:** Shows the source IPs responsible for failed login attempts leading to lockouts.

**Purpose:** Useful for identifying attackers or automated scans.

```spl
index=linux sourcetype=linux_secure "locked" | stats count by src_ip
```

---

🔹 **4. Lockouts per Hour**

**Description:** Time-based visualization of Linux account lockouts.

**Purpose:** Helps detect brute-force waves or misconfigurations.

```spl
index=linux sourcetype=linux_secure "locked" | timechart span=1h count
```
