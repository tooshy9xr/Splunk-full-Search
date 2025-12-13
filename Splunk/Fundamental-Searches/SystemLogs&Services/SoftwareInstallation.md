# 🌟 Software Installation — Windows & Linux

A beginner-friendly list of Splunk searches to monitor software installation activity on Windows and Linux systems. Each search includes a short description, purpose, and ready-to-use SPL query.

---

## 🖥️ Windows Software Installation

🔹 **1. Installed Software Events**

**Description:** Shows events where new software was installed on Windows.

**Purpose:** Helps monitor legitimate and unauthorized software installations.

```spl
index=windows sourcetype=WinEventLog:Security EventCode=11707
```

---

🔹 **2. Failed Software Installation**

**Description:** Displays failed Windows software installation attempts.

**Purpose:** Useful for troubleshooting or detecting suspicious behavior.

```spl
index=windows sourcetype=WinEventLog:Security EventCode=11708
```

---

🔹 **3. Installed Software by User**

**Description:** Groups software installation events by initiating user.

**Purpose:** Shows which users are installing applications.

```spl
index=windows sourcetype=WinEventLog:Security EventCode=11707 | stats count by User
```

---

🔹 **4. Installation Activity per Hour**

**Description:** Displays software installations over time.

**Purpose:** Helps detect unusual installation spikes.

```spl
index=windows sourcetype=WinEventLog:Security EventCode=11707 | timechart span=1h count
```

---

## 🐧 Linux Software Installation

🔹 **1. Installed Packages (APT — Ubuntu/Debian)**

**Description:** Shows logs for installed software packages via APT.

**Purpose:** Tracks legitimate and potentially unwanted installations.

```spl
index=linux sourcetype=linux_syslog "install " "apt"
```

---

🔹 **2. Installed Packages (YUM/DNF — RHEL/CentOS)**

**Description:** Displays installed packages using yum or dnf.

**Purpose:** Monitors installation activity on RHEL-based systems.

```spl
index=linux sourcetype=linux_syslog ("Installed:" OR "installed") ("yum" OR "dnf")
```

---

🔹 **3. Software Installation by User**

**Description:** Counts installation commands executed by each user.

**Purpose:** Identifies which users are performing installation actions.

```spl
index=linux sourcetype=linux_secure (command="*apt*" OR command="*yum*" OR command="*dnf*") | stats count by user
```

---

🔹 **4. Installation Activity per Hour**

**Description:** Shows time-based installation events.

**Purpose:** Detects unusual installation patterns.

```spl
index=linux sourcetype=linux_syslog ("install" OR "Installed") | timechart span=1h count
```
