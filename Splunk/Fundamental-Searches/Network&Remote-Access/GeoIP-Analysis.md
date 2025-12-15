# 🌍 GeoIP Analysis
Fundamental Searches for Geographic Activity Monitoring

This file focuses on **analyzing IP-based geographic locations (GeoIP)** across **network, VPN, proxy, and endpoint logs**, using **basic searches** suitable for the *Fundamental Searches* level.  
GeoIP analysis helps identify **suspicious access from unusual locations, potential account compromises, and anomalous traffic patterns**.

---

## 🎯 Purpose
- Map IP addresses to geographic locations  
- Detect **logins or connections from unusual countries or regions**  
- Monitor **remote access patterns**  
- Identify **possible compromised accounts or insider threats**  
- Support SOC investigations and threat hunting  

---

## 🖥️ Platforms & Devices Covered
- 🌐 Firewalls, IDS/IPS, routers, and VPN gateways  
- 🪟 Windows Endpoints and VPN logs  
- 🐧 Linux Servers and SSH logs  
- ☁️ Cloud services and SaaS platforms  

---

## 📂 Common GeoIP Events
- VPN login locations  
- Failed and successful authentication attempts  
- Proxy and web traffic by country  
- Access to restricted resources from unexpected geolocations  

---

## 📂 Common Log Sources
- Firewall and router logs  
- VPN logs  
- Proxy and web gateway logs  
- Windows Event Logs (logons)  
- Linux auth.log and syslog  

---

## 🧾 Sample Logs

### 🌐 VPN – Login from New Country
```
2025-02-23 12:01:22 VPN-GW User=john.doe SrcIP=8.8.8.8 Geo=US Status=Connected
```

### 🪟 Windows – Login from Unexpected Location
```
2025-02-23 12:03:10 WIN-WS01 EventID=4624 User=alice SrcIP=185.220.101.1 Geo=RU
```

### 🐧 Linux – SSH Access from Foreign IP
```
Feb 23 12:05:33 server01 sshd[1234]: Accepted password for bob from 45.153.160.98 Geo=CN
```

### 🌐 Proxy – Web Request GeoIP
```
2025-02-23 12:07:11 ProxyServer User=alice URL=http://example.com SrcIP=203.0.113.5 Geo=FR
```

---

## 🔍 Fundamental Search Examples

### 🌍 Successful Logins by Country
```spl
| stats count by user Geo
```

### ❌ Failed Logins from Foreign IPs
```spl
EventID=4625 OR "Failed password"
| iplocation SrcIP
| search Geo!="US"
```

### ⚡ VPN Access from Unusual Locations
```spl
Status=Connected
| iplocation SrcIP
| where Geo NOT IN ("US","CA","UK")
```

---

## 🚨 Detection Scenarios

### 🔁 Multiple Countries for Same User
```spl
| stats dc(Geo) as country_count by user
| where country_count > 1
```

### 🧨 Login from High-Risk Countries
```spl
| search Geo IN ("RU","CN","IR","KP")
```

### ⚠️ Anomalous VPN or SSH Access
```spl
| search hour < 7 OR hour > 20
```

---

## 🛡️ Mitigation & Response
- Alert on logins from unexpected geolocations  
- Enforce MFA for remote access  
- Review VPN and SSH activity for anomalies  
- Block high-risk IPs if necessary  
- Correlate GeoIP anomalies with threat intelligence  

---

## 📌 Summary
This file provides **fundamental GeoIP analysis** for:
- Mapping IPs to geographic locations  
- Detecting anomalous logins and access  
- Enhancing threat detection and incident response  
