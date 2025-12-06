# 🌟 Easy Authentication Searches — Splunk

A clean, structured, and beginner-friendly list of simple Splunk searches for successful authentication events.  
Each search includes a short explanation, purpose, and the SPL query.

---

## 🔹 1. Basic Successful Logins  
**Description:** Displays all successful login events with timestamp, username, and source IP.  
**Purpose:** Provides a quick view of who logged in, when, and from where.

🔍 [SPL](Susccessful-login/Basic-Successful-Logins.spl)

## 🔹 2. Count Successful Logins by User

Description: Counts how many successful logins each user has.<br>
Purpose: Helps identify the most active accounts or unusual login spikes.

🔍 [SPL](Susccessful-login/Count-Successful-Logins-Use.spl)


## 🔹 3. Count Successful Logins by Source IP

Description: Shows how many logins came from each IP address.<br>
Purpose: Useful for spotting repeated logins from a single IP or unfamiliar sources.

🔍 [SPL](Susccessful-login/Count-Successful-Login-SourceIP.spl)

## 🔹 4. Last Successful Login Per User

Description: Returns the latest (most recent) successful login time for each user.<br>
Purpose: Good for tracking user activity and verifying expected login behavior.

🔍 [SPL](Susccessful-login/LastSuccessfulLogin.spl)

## 🔹 5. Successful Logins per Hour

Description: Simple time-based chart showing hourly successful logins.<br>
Purpose: Helps visualize login activity peaks or unusual patterns.

🔍 [SPL](Susccessful-login/Successful-Logins-Hour.spl)


