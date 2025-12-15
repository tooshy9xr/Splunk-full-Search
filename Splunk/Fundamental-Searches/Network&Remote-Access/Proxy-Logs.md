# 🌐 Proxy Logs Monitoring
Fundamental Searches for Web & Proxy Activity

This file focuses on **monitoring proxy logs** across **corporate network environments**, using **basic searches** suitable for the *Fundamental Searches* level.  
Proxy monitoring helps detect **unauthorized web activity, malware communication, and policy violations**.

---

## 🎯 Purpose
- Track **web requests and responses**
- Detect **blocked or suspicious domains**
- Monitor **user internet activity**
- Identify **malware and phishing traffic**
- Support SOC investigations and compliance monitoring

---

## 🖥️ Platforms & Devices Covered
- 🌐 Proxy Servers (Squid, Blue Coat, Zscaler, etc.)  
- 🪟 Windows Endpoints (browser proxy logs)  
- 🐧 Linux Endpoints (browser proxy logs)  
- ☁️ Cloud Proxy Services  

---

## 📂 Common Proxy Event Types
- Allowed / blocked HTTP(S) requests  
- Suspicious or malicious URL access  
- Authentication failures  
- Policy violation attempts  
- Malware or phishing communication  

---

## 📂 Common Log Sources
- Proxy server logs (Squid, Blue Coat, Zscaler)  
- Network firewall logs  
- Web filtering services  
- Endpoint proxy logs  

---

## 🧾 Sample Logs

### 🌐 Allowed Request
```
2025-02-21 10:01:22 ProxyServer User=john.doe URL=http://example.com Status=Allowed
```

### 🌐 Blocked Request
```
2025-02-21 10:03:10 ProxyServer User=alice URL=http://malicious.com Status=Blocked
```

### 🌐 Suspicious Domain Access
```
2025-02-21 10:05:33 ProxyServer User=bob URL=http://phishing-site.com Status=Allowed
```

### 🪟 Endpoint Proxy – Authentication Failure
```
2025-02-21 10:07:11 WIN-WS01 User=john.doe ProxyAuth=Failed
```

---

## 🔍 Fundamental Search Examples

### 🌐 Allowed Web Requests
```spl
Status=Allowed
| table _time user URL host
```

### ❌ Blocked or Malicious Requests
```spl
Status=Blocked OR URL IN ("*malicious*","*phishing*")
```

### 👤 User-Specific Activity
```spl
| stats count by user URL
```

### 🌍 Suspicious Domains Accessed
```spl
| search URL IN ("*login*","*verify*","*secure*")
```

---

## 🚨 Detection Scenarios

### 🔁 Multiple Blocked Requests by User
```spl
| stats count by user
| where count > 5
```

### 🧨 Access to Known Malicious Domains
```spl
| search URL IN ("malicious.com","phishing-site.com")
```

### ⚠️ High Volume of Web Requests
```spl
| stats count by user
| where count > 100
```

---

## 🛡️ Mitigation & Response
- Block known malicious domains and URLs  
- Educate users about safe web browsing  
- Alert on repeated policy violations  
- Integrate proxy logs with threat intelligence feeds  
- Investigate endpoints with suspicious activity  

---

## 📌 Summary
This file provides **fundamental proxy log monitoring** for:
- Web requests and responses
- Blocked and malicious URLs
- Detection of unauthorized internet activity

