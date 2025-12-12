# 📝 Sample Application Logs  
This file contains **sample logs from various applications** to help test Splunk searches, dashboards, and monitoring rules.  
Includes web servers, databases, middleware, and custom applications with errors, warnings, transactions, and performance events.

---

# 1. Web Server Logs (Apache / Nginx)

## ✅ Successful HTTP Request  
```
2025-02-12 10:12:11 webserver01 GET /index.html 200 512 user=guest src_ip=192.168.1.45
```

## ❌ Client Error (404 Not Found)  
```
2025-02-12 10:15:33 webserver01 GET /admin.php 404 312 user=guest src_ip=203.0.113.78
```

## ⚠️ Server Error (500 Internal Server Error)  
```
2025-02-12 10:18:47 webserver01 POST /login.php 500 0 user=john src_ip=192.168.1.55
```

## 🔁 Slow Response / Performance Warning  
```
2025-02-12 10:20:22 webserver01 GET /reports 200 10240 duration=5.2s user=alice src_ip=192.168.1.66
```

---

# 2. Database Logs (MySQL / PostgreSQL)

## ✅ Successful Query  
```
2025-02-12 11:02:33 db01 Query: SELECT * FROM employees WHERE id=123; Status=Success User=reporting
```

## ❌ Failed Query / Error  
```
2025-02-12 11:05:18 db01 Query: INSERT INTO users VALUES(NULL,'john','pass'); Error=Duplicate entry User=admin
```

## ⚠️ Slow Query Warning  
```
2025-02-12 11:07:41 db01 Query: SELECT * FROM transactions WHERE amount>10000; Duration=8.5s User=finance
```

## 🔒 Unauthorized Access Attempt  
```
2025-02-12 11:10:12 db01 User=guest Query: DROP TABLE salaries; Status=Denied
```

---

# 3. Middleware / Application Servers (Tomcat, JBoss)

## Server Startup  
```
2025-02-12 12:00:11 appserver01 INFO Starting Tomcat v9.0.75 on port 8080
```

## Deployment Event  
```
2025-02-12 12:05:33 appserver01 INFO Deployed application 'PayrollApp' by admin
```

## Application Error  
```
2025-02-12 12:15:22 appserver01 ERROR NullPointerException at PayrollController.java:45 User=john
```

## Session Timeout / Warning  
```
2025-02-12 12:18:44 appserver01 WARN Session expired for user=alice session_id=abc123
```

---

# 4. Custom Application Logs

## Transaction Processed  
```
2025-02-12 13:22:11 customapp01 INFO TransactionID=TX123456 Status=Completed User=bob Amount=1500
```

## Failed Transaction  
```
2025-02-12 13:24:41 customapp01 ERROR TransactionID=TX123457 Status=Failed Reason=InsufficientBalance User=bob
```

## High CPU / Performance Alert  
```
2025-02-12 13:30:12 customapp01 WARN CPUUsage=95% MemoryUsage=87% Host=app01
```

## Security Warning – Input Validation  
```
2025-02-12 13:33:21 customapp01 ALERT SuspiciousInput detected in field=email User=guest
```

---

# 5. Integration / API Logs

## Successful API Call  
```
2025-02-12 14:02:11 api01 POST /v1/orders Status=200 ResponseTime=0.512s User=alice
```

## API Error  
```
2025-02-12 14:05:22 api01 GET /v1/payments Status=500 ResponseTime=1.234s User=bob
```

## Authentication Failure  
```
2025-02-12 14:07:41 api01 POST /v1/login Status=401 User=guest SrcIP=203.0.113.78
```

## Rate Limit Exceeded  
```
2025-02-12 14:10:33 api01 GET /v1/products Status=429 User=client123 SrcIP=192.168.1.88
```

---

# 6. Performance & Monitoring

## High Memory Usage  
```
2025-02-12 14:21:11 appserver01 WARN MemoryUsage=92% ProcessID=4523 User=service
```

## Thread Pool Exhaustion  
```
2025-02-12 14:23:22 appserver01 WARN MaxThreadsReached ActiveThreads=200 Queue=10
```

## Disk Space Warning  
```
2025-02-12 14:25:33 appserver01 WARN DiskUsage=/var/app/logs Usage=91%
```

---

# Summary

This file includes sample logs for:

- Web server access & errors  
- Database queries & performance  
- Middleware/application server events  
- Custom application transactions  
- API logs & security events  
- System resource warnings & monitoring  
