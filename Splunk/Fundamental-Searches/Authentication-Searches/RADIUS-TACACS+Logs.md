# 🔐 RADIUS & TACACS+ Logs (Windows & Linux)
Fundamental Searches for Network Authentication & Authorization

This file focuses on **RADIUS and TACACS+ authentication, authorization, and accounting (AAA) logs** across **Windows and Linux environments**, using **basic searches** suitable for *Fundamental Searches*.  
These protocols are widely used for **network device access (routers, switches, firewalls, VPNs)**.

---

## 🎯 Purpose
- Monitor **successful and failed device authentications**
- Detect **brute-force and password spraying**
- Track **privileged network access**
- Identify **unusual source IPs or devices**
- Support SOC and network security investigations

---

## 🖥️ Platforms & Devices Covered
- 🪟 Windows (NPS – Network Policy Server)
- 🐧 Linux (FreeRADIUS)
- 🌐 Network Devices  
  - Cisco (IOS / ASA / NX-OS)  
  - Juniper  
  - Palo Alto  
  - Fortinet  

---

## 📂 Common Log Sources

### 🪟 Windows
- NPS Logs  
- Windows Security Event Log  
- IAS / RADIUS accounting logs

### 🐧 Linux
- `/var/log/radius/radius.log`
- `/var/log/freeradius/radius.log`
- `/var/log/syslog`

---

## 🧾 Sample Logs

### 🪟 Windows – RADIUS Authentication Success
```
2025-02-12 08:55:21 NPS EventID=6272 User=netadmin ClientIP=192.168.1.10 Device=Firewall01 Status=Granted
```

### 🪟 Windows – RADIUS Authentication Failure
```
2025-02-12 08:57:44 NPS EventID=6273 User=guest ClientIP=203.0.113.77 Device=Switch05 Reason=BadCredentials
```

---

### 🐧 Linux – FreeRADIUS Authentication Success
```
Feb 12 09:11:22 radius01 freeradius[2211]: Login OK: [admin] (from client router01 port 0 cli 192.168.1.1)
```

### 🐧 Linux – FreeRADIUS Authentication Failure
```
Feb 12 09:13:55 radius01 freeradius[2211]: Login incorrect: [guest] (from client switch02 port 12 cli 203.0.113.90)
```

---

### 🌐 TACACS+ – Device Login Success
```
2025-02-12 09:21:11 tacacs01 User=netadmin Device=Router01 SrcIP=192.168.1.20 Action=Login Status=Success
```

### 🌐 TACACS+ – Command Authorization
```
2025-02-12 09:22:33 tacacs01 User=netadmin Device=Router01 Command="show running-config" Status=Allowed
```

### 🌐 TACACS+ – Command Denied
```
2025-02-12 09:24:11 tacacs01 User=guest Device=Switch01 Command="reload" Status=Denied
```

---

## 🔍 Fundamental Search Examples

### 🔐 Successful AAA Authentication
```spl
(Status=Granted) OR ("Login OK")
```

### ❌ Failed AAA Authentication
```spl
(EventID=6273) OR ("Login incorrect")
```

### 👑 Privileged Network Access
```spl
(User=admin OR User=netadmin)
```

---

## 🚨 Basic Detection Use Cases

### 🔁 Brute-Force Attempts
```spl
(Status=Denied OR "Login incorrect")
| stats count by src_ip
| where count > 10
```

### 🌍 Device Access from External IP
```spl
(ClientIP!=10.0.0.0/8)
```

### 🧑‍💻 Unauthorized Command Execution
```spl
(Command="reload" OR Command="write erase")
```

---

## 🛡️ AAA Security Best Practices
- Enforce MFA for network device access
- Monitor failed authentication spikes
- Restrict admin access by IP
- Log all TACACS+ commands
- Review accounting logs regularly

---

## 📌 Summary
This file provides **fundamental AAA monitoring** for:
- RADIUS authentication & accounting
- TACACS+ device access & command execution
- Windows NPS and Linux FreeRADIUS

