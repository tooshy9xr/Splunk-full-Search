# 🔐 VPN Authentication (Windows & Linux)
Fundamental Searches for VPN Login and Remote Access Monitoring

This file focuses on **VPN authentication activity across Windows and Linux environments**, using **basic searches** suitable for *Fundamental Searches*.

---

## 🎯 Purpose
- Monitor **successful and failed VPN logins**
- Detect **brute-force and password spraying**
- Identify **unusual locations and IP addresses**
- Track **remote access behavior**
- Support SOC triage and investigations

---

## 🖥️ Platforms & VPN Types Covered
- 🪟 Windows VPN (RAS / RRAS / Always On VPN)
- 🐧 Linux VPN (OpenVPN / StrongSwan / WireGuard)
- 🔐 Commercial VPNs (AnyConnect, FortiClient, GlobalProtect – log-style examples)

---

## 📂 Common Log Sources

### 🪟 Windows
- Security Event Log  
  - Event IDs: 4624, 4625 (authentication)
- RAS / VPN logs
- Vendor-specific VPN client logs

### 🐧 Linux
- `/var/log/auth.log`
- `/var/log/syslog`
- VPN service logs (`openvpn`, `strongswan`, `wg`)

---

## 🧾 Sample VPN Logs

### 🪟 Windows – Successful VPN Login
```
2025-02-12 09:55:21 WIN-RRAS01 EventID=20225 User=john.doe SrcIP=203.0.113.45 VPNType=IKEv2 Status=Success
```

### 🪟 Windows – Failed VPN Login
```
2025-02-12 09:57:11 WIN-RRAS01 EventID=20227 User=administrator SrcIP=203.0.113.77 Status=Failed Reason=BadCredentials
```

---

### 🐧 Linux – OpenVPN Successful Login
```
Feb 12 10:11:45 vpn01 openvpn[1442]: Peer Connection Initiated with [AF_INET]203.0.113.98:51432 user=mike
```

### 🐧 Linux – OpenVPN Failed Login
```
Feb 12 10:13:21 vpn01 openvpn[1442]: AUTH_FAILED user=admin src_ip=203.0.113.98
```

### 🐧 Linux – WireGuard Connection
```
Feb 12 10:18:55 vpn01 wg-quick[901]: Interface wg0 peer connected user=alice src_ip=192.168.1.55
```

---

## 🔍 Fundamental Search Examples

### 🔐 Successful VPN Logins
```spl
(index=windows_logs VPNType=*) OR (index=linux_logs openvpn "Peer Connection Initiated")
```

### ❌ Failed VPN Logins
```spl
(index=windows_logs Status=Failed) OR (index=linux_logs "AUTH_FAILED")
```

### 🌍 VPN Logins from External IPs
```spl
(index=windows_logs VPNType=*) OR (index=linux_logs openvpn)
| search src_ip!=10.0.0.0/8
```

---

## 🚨 Basic Detection Use Cases

### 🔁 VPN Brute Force Detection
```spl
(index=windows_logs Status=Failed) OR (index=linux_logs "AUTH_FAILED")
| stats count by src_ip
| where count > 10
```

### 🌎 VPN Login from Unusual Country
```spl
(index=windows_logs VPNType=*) OR (index=linux_logs openvpn)
| iplocation src_ip
| search Country!="YourCountry"
```

### 👑 Admin VPN Access
```spl
(index=windows_logs User=administrator) OR (index=linux_logs user=root)
```

---

## 🛡️ VPN Security Best Practices
- Enforce MFA for VPN access
- Monitor failed login spikes
- Restrict admin VPN access
- Alert on new or unusual source IPs
- Review VPN access regularly

---

## 📌 Summary
This file provides **fundamental VPN authentication monitoring** across:
- 🪟 Windows VPN
- 🐧 Linux VPN

