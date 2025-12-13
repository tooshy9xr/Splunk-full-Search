# 🌟 Easy Windows Authentication Searches — Splunk

A clean, structured, and beginner-friendly list of simple Splunk searches for Windows authentication events.
Each search includes a short explanation, purpose, and the SPL query.

---

🔹 **1. Basic Successful Windows Logins**

**Description:** Displays all successful login events on Windows machines with timestamp, username, and source IP.

**Purpose:** Provides a quick view of who logged in, when, and from where.

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4624
```

---

🔹 **2. Count Successful Windows Logins by User**

**Description:** Counts how many successful logins each user has on Windows systems.

**Purpose:** Helps identify the most active accounts or unusual login spikes.

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4624 | stats count by Account_Name
```

---

🔹 **3. Count Successful Logins by Source IP**

**Description:** Shows how many logins came from each IP address on Windows hosts.

**Purpose:** Useful for spotting repeated logins from a single IP or unfamiliar sources.

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4624 | stats count by IpAddress
```

---

🔹 **4. Last Successful Login Per User**

**Description:** Returns the latest successful login time for each Windows user.

**Purpose:** Good for tracking user activity and verifying expected login behavior.

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4624 | stats latest(_time) by Account_Name
```

---

🔹 **5. Failed Windows Login Attempts**

**Description:** Displays failed login attempts on Windows machines.

**Purpose:** Helps identify potential brute force attacks or misconfigured accounts.

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625
```

---

🔹 **6. Successful Logins per Hour**

**Description:** Simple time-based chart showing hourly successful Windows logins.

**Purpose:** Helps visualize login activity peaks or unusual patterns.

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4624 | timechart span=1h count
```
