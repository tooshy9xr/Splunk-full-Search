# 🌟 Admin Privilege Changes — Windows

A beginner-friendly list of Splunk searches to monitor administrative privilege changes on Windows systems. Each search includes a short description, purpose, and SPL query.

---

🔹 **1. Basic Admin Privilege Change**

**Description:** Displays events where users were added or removed from administrative groups.

**Purpose:** Helps detect changes to privileged accounts.

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4728 OR EventCode=4732 OR EventCode=4756
```

---

🔹 **2. Privilege Changes by User**

**Description:** Counts administrative privilege changes initiated by each user.

**Purpose:** Identifies which users are modifying privileges.

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4728 OR EventCode=4732 | stats count by Subject_User_Name
```

---

🔹 **3. Users Added to Admin Group**

**Description:** Shows which users were added to administrative groups.

**Purpose:** Monitors newly privileged accounts.

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4728 OR EventCode=4732 | table _time Subject_User_Name Member_Name Group_Name
```

---

🔹 **4. Users Removed from Admin Group**

**Description:** Displays users removed from administrative groups.

**Purpose:** Detects removal of privileges which might indicate policy violations or attacks.

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4729 OR EventCode=4733 | table _time Subject_User_Name Member_Name Group_Name
```

---

🔹 **5. Privilege Changes per Hour**

**Description:** Time-based chart showing administrative privilege changes per hour.

**Purpose:** Helps identify unusual spikes in privilege changes.

**🔍 SPL:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4728 OR EventCode=4732 OR EventCode=4729 OR EventCode=4733 | timechart span=1h count
```
