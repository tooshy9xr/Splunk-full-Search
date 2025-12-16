# ☁️ GCP Logs Monitoring
Fundamental Searches for Google Cloud Platform Activity

This file focuses on **monitoring Google Cloud Platform (GCP) logs** using **basic searches** suitable for the *Fundamental Searches* level.  
GCP log monitoring is critical for detecting **unauthorized access, suspicious API usage, misconfigurations, and cloud security threats**.

---

## 🎯 Purpose
- Monitor **GCP project and resource activity**
- Detect **unauthorized authentication and API calls**
- Track **IAM role and permission changes**
- Identify **misconfigurations and risky operations**
- Support SOC investigations and cloud incident response

---

## ☁️ GCP Services Covered

### 🔐 Identity & Access
- Cloud IAM audit logs
- Service account activity
- OAuth token usage

### 🌐 Network
- VPC Flow Logs
- Firewall rule changes
- Load balancer access logs

### 🖥️ Compute & Storage
- Compute Engine VM logs
- Cloud Storage access logs
- Kubernetes Engine (GKE) logs

### 📊 Monitoring & Security
- Cloud Audit Logs
- Security Command Center findings
- Cloud Logging & Monitoring

---

## 📂 Common Log Sources

### ☁️ GCP Native Logs
- **Cloud Audit Logs** – Admin, Data Access, and System Events  
- **VPC Flow Logs** – Network traffic  
- **Cloud Storage Logs** – Object-level access  
- **GKE Logs** – Container and cluster activity  
- **Security Command Center** – Security alerts  

---

## 🧾 Sample Logs

### 🔐 IAM – Successful API Call
```
2025-02-28 09:01:22 principalEmail=john@company.com methodName=google.iam.admin.v1.CreateServiceAccount
```

### ❌ IAM – Permission Denied
```
2025-02-28 09:03:10 principalEmail=alice@company.com status=PERMISSION_DENIED
```

### 🌐 VPC Flow Log – Network Traffic
```
2025-02-28 09:05:33 src_ip=10.128.0.5 dest_ip=34.102.136.180 dest_port=443 action=ALLOW
```

### 📦 Cloud Storage – Object Access
```
2025-02-28 09:07:11 bucket=my-gcp-bucket object=secrets.zip method=storage.objects.get
```

---

## 🔍 Fundamental Search Examples

### 🔐 GCP IAM Activity
```spl
| search methodName=google.iam*
| table _time principalEmail methodName
```

### ❌ Failed or Denied API Calls
```spl
| search status=PERMISSION_DENIED
| stats count by principalEmail
```

### 🌐 Suspicious Network Traffic
```spl
| stats count by src_ip dest_ip dest_port
```

### 📦 Sensitive Cloud Storage Access
```spl
| search method=storage.objects.get
```

---

## 🚨 Detection Scenarios

### 🔁 Repeated Permission Denials
```spl
| stats count by principalEmail
| where count > 5
```

### 🌍 Access from Unusual Locations
```spl
| iplocation src_ip
| search Country NOT IN ("US","CA","UK")
```

### ⚠️ High-Risk Admin Operations
```spl
methodName IN ("google.iam.admin.v1.DeleteServiceAccount","google.iam.admin.v1.SetIamPolicy")
```

---

## 🛡️ Mitigation & Response
- Enforce least-privilege IAM roles  
- Rotate compromised service account keys  
- Monitor high-risk API actions  
- Enable Security Command Center  
- Investigate suspicious network and storage access  

---

## 📌 Summary
This file provides **fundamental GCP log monitoring** for:
- IAM authentication and API activity  
- Network traffic and cloud storage access  
- Detecting cloud threats and misconfigurations  
