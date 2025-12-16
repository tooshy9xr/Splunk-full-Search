# 🧩🗄️ Database Schema Changes  
Fundamental Searches for Schema Modification Activity  
(Windows • Linux • Cloud)

This file focuses on **monitoring database schema changes** across **Windows, Linux, and Cloud environments**, using **basic searches** suitable for the *Fundamental Searches* level.  
Schema change monitoring is critical for detecting **unauthorized structural changes, privilege abuse, insider threats, and destructive actions**.

---

## 🎯 Purpose
- Track **DDL operations** (CREATE, ALTER, DROP)  
- Detect **unauthorized schema modifications**  
- Monitor **changes to tables, views, indexes, and procedures**  
- Identify **potential sabotage or data integrity risks**  
- Support SOC investigations and database change auditing  

---

## 🖥️ Platforms Covered

### 🪟 Windows
- Microsoft SQL Server  
- SQL Server Audit & Error Logs  
- Windows Application Logs  

### 🐧 Linux
- MySQL / MariaDB  
- PostgreSQL  
- Oracle Database  
- Database audit and query logs  

### ☁️ Cloud
- Amazon RDS / Aurora  
- Azure SQL Database  
- Google Cloud SQL  
- Cloud database audit logs  

---

## 📂 Common Log Sources
- Database audit logs  
- Query execution logs  
- Cloud provider database audit logs  
- Application deployment logs  

---

## 🧾 Sample Logs

### 🪟 Windows – MSSQL Table Drop
```
2025-03-07 13:01:22 user=db_admin query="DROP TABLE payments;"
```

### 🐧 Linux – MySQL Schema Change
```
2025-03-07 13:03:10 user=app_user query="ALTER TABLE users ADD COLUMN is_admin BOOLEAN;"
```

### 🐧 Linux – PostgreSQL Index Creation
```
2025-03-07 13:05:33 user=admin statement="CREATE INDEX idx_email ON customers(email);"
```

### ☁️ Cloud – RDS Schema Change
```
2025-03-07 13:07:11 user=db_admin action=ALTER TABLE orders DROP COLUMN price;
```

---

## 🔍 Fundamental Search Examples

### 🧩 All Schema Changes
```spl
| search query IN ("CREATE","ALTER","DROP")
| table _time user host query
```

### 🧨 Destructive Schema Changes
```spl
| search query="*DROP TABLE*" OR query="*DROP COLUMN*"
```

### 👤 Schema Changes by Non-Admins
```spl
| search user!="db_admin"
```

### 🔁 Frequent Schema Modifications
```spl
| stats count by user
| where count > 5
```

---

## 🚨 Detection Scenarios

### ⚠️ Unauthorized Schema Changes
```spl
| search user!="db_admin" AND query IN ("DROP","ALTER")
```

### 🕵️ Schema Changes Outside Change Window
```spl
| where date_hour < 8 OR date_hour > 18
```

### 🧨 Mass Schema Deletions
```spl
| stats count by user
| where count > 3
```

---

## 🛡️ Mitigation & Response
- Restrict schema modification permissions  
- Enforce change management approvals  
- Enable database auditing and alerts  
- Review schema changes regularly  
- Maintain backups before schema updates  

---

## 📌 Summary
This file provides **fundamental monitoring of database schema changes** across:
- 🪟 Windows databases  
- 🐧 Linux databases  
- ☁️ Cloud-managed databases  

It helps detect **unauthorized structural changes and data integrity risks**.

