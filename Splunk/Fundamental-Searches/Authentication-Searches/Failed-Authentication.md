# 🌟 Easy Failed Authentication Searches — Splunk

A clean, structured, and beginner-friendly list of simple Splunk searches for failed authentication events on Windows and Linux.
Each search includes a short explanation, purpose, and the SPL query.

---

## ❌ Windows Failed Logins

🔹 **1. Basic Failed Windows Logins**

**Description:** Displays all failed login attempts on Windows machines.

**Purpose:** Identifies unsuccessful login attempts for monitoring or investigation.

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625
```

---

🔹 **2. Count Failed Logins by User**

**Description:** Shows how many failed login attempts each Windows user has.

**Purpose:** Helps detect accounts under attack or misused accounts.

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625 | stats count by Account_Name
```

---

🔹 **3. Count Failed Logins by Source IP**

**Description:** Shows how many failed logins came from each IP address.

**Purpose:** Useful for spotting repeated attacks from a single IP or suspicious sources.

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625 | stats count by IpAddress
```

---

🔹 **4. Failed Logins per Hour**

**Description:** Time-based chart showing hourly failed logins.

**Purpose:** Helps visualize failed login peaks or unusual patterns.

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625 | timechart span=1h count
```

---

🔹 **5. Failed Logins by Domain**

**Description:** Counts failed login attempts grouped by domain.

**Purpose:** Useful in multi-domain environments to identify targeted domains.

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625 | stats count by Domain
```

---

🔹 **6. Failed Logins by Workstation**

**Description:** Displays failed login attempts per workstation.

**Purpose:** Helps identify compromised machines or problem hosts.

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625 | stats count by Workstation_Name
```

---

🔹 **7. Failed Login Details with Reason**

**Description:** Shows failed login attempts along with the failure reason.

**Purpose:** Helps in understanding why logins failed (bad password, account locked, etc.).

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625 | table _time Account_Name IpAddress Failure_Reason
```

---

## ❌ Linux Failed Logins

🔹 **1. Basic Failed Linux Logins**

**Description:** Displays all failed login attempts on Linux machines.

**Purpose:** Identifies unsuccessful login attempts for monitoring or investigation.

**🔍 SPL:**

```spl
index=linux sourcetype=linux_secure action=failure
```

---

🔹 **2. Count Failed Logins by User**

**Description:** Shows how many failed login attempts each Linux user has.

**Purpose:** Helps detect accounts under attack or misused accounts.

**🔍 SPL:**

```spl
index=linux sourcetype=linux_secure action=failure | stats count by user
```

---

🔹 **3. Count Failed Logins by Source IP**

**Description:** Shows how many failed logins came from each IP address.

**Purpose:** Useful for spotting repeated attacks from a single IP or suspicious sources.

**🔍 SPL:**

```spl
index=linux sourcetype=linux_secure action=failure | stats count by src_ip
```

---

🔹 **4. Failed Logins per Hour**

**Description:** Time-based chart showing hourly failed logins.

**Purpose:** Helps visualize failed login peaks or unusual patterns.

**🔍 SPL:**

```spl
index=linux sourcetype=linux_secure action=failure | timechart span=1h count
```

---

🔹 **5. Failed Logins by Terminal**

**Description:** Displays failed login attempts per terminal (tty).

**Purpose:** Helps identify suspicious activity per access point.

**🔍 SPL:**

```spl
index=linux sourcetype=linux_secure action=failure | stats count by tty
```

---

🔹 **6. Failed Logins by User Group**

**Description:** Shows failed attempts grouped by user group.

**Purpose:** Useful to identify targeted groups or privileges under attack.

**🔍 SPL:**

```spl
index=linux sourcetype=linux_secure action=failure | stats count by user_group
```

---

🔹 **7. Failed Login Details with Reason**

**Description:** Displays failed login attempts with reason (bad password, locked account, etc.).

**Purpose:** Helps analyze cause of failures for security response.

**🔍 SPL:**

```spl
index=linux sourcetype=linux_secure action=failure | table _time user src_ip reason
```
