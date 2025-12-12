# 🔗 Security Event Correlation (Fundamental Concept)  
Understanding Basic Correlation Ideas for Beginners

Event correlation at the *fundamental search level* focuses on connecting simple log events to identify suspicious activity using **basic SPL**, without advanced frameworks, data models, or ES correlation rules.

This guide covers the **intro-level version** suitable for *Fundamental Searches*.

---

# 1️⃣ What Is Basic Event Correlation?

Fundamental correlation =  
**Combine 2–3 related events using simple SPL (stats, join, transaction) to understand behavior.**

Examples:
- Failed logins + successful login  
- Suspicious process + network connection  
- User login + password reset  
- File modification + service restart  

These are *simple correlations*, not multi-stage or ES-level rules.

---

# 2️⃣ Why We Use Simple Correlation

At the fundamental level, correlation helps with:

- Understanding relationships between logs  
- Detecting simple suspicious patterns  
- Training on how events connect  
- Building foundation before advanced detection  

---

# 3️⃣ Basic SPL Commands Used for Correlation

### ✔ `stats`  
Group data by fields.
```spl
| stats count by user src_ip
```

### ✔ `transaction`  
Combine events into one timeline.
```spl
| transaction user maxspan=5m
```

### ✔ `join`  
Merge two datasets.
```spl
| join user [ search index=os EventCode=4624 ]
```

### ✔ `where`  
Filter based on conditions.
```spl
| where count > 5
```

These commands are the foundation for simple correlations.

---

# 4️⃣ Basic Correlation Examples (Fundamentals Level)

## 🔐 **1. Failed Login + Successful Login**
Detect possible compromised account.
```spl
index=auth
(user=* AND action=failure) OR (action=success)
| transaction user maxspan=10m
| search action="failure" AND action="success"
```

---

## 🧑‍💻 **2. Process Created + Network Connection**
Basic endpoint lateral movement check.
```spl
(index=os_process) OR (index=network)
| transaction host maxspan=2m
| search process_name=* AND dest_ip=*
```

---

## 📝 **3. File Modified + Service Restart**
Simple persistence check.
```spl
(index=file_monitor) OR (index=os)
| transaction host maxspan=5m
| search "service restart" AND "file modified"
```

---

## 🔐 **4. Privilege Change + Login**
Beginner-level privilege escalation pattern.
```spl
index=auth OR index=os
| transaction user maxspan=3m
| search action="login" AND "privilege change"
```

---

# 5️⃣ Common Use Cases (Beginner / Fundamental Level)

| Category | Example |
|---------|---------|
| Authentication | Failed → Success chain |
| System | File change → Service restart |
| Endpoint | Process → Network |
| User Monitoring | Login → Password reset |
| File Activity | Creation → Execution |
| Network | DNS → Connection |
| Basic Threat | Suspicious command → Logoff |

---

# 6️⃣ Simple Correlation Best Practices (For Fundamentals)

- Keep searches lightweight  
- Use indexed fields  
- Avoid heavy `join` unless necessary  
- Use `transaction` only for small datasets  
- Keep time windows short (1–10 min)  
- Document behavior clearly  
- Understand *why* events are connected  

---

# Summary

This version of **Security Event Correlation** is designed specifically for your **Fundamental Searches** folder:  
- No advanced threat models  
- No ES correlation rules  
- Simple SPL-only logic  
- Beginner-friendly event pairing  


