# 🏷️ Splunk Fields — Complete Understanding  
How Fields Work, How They Are Extracted, and Why They Matter

Splunk fields are the **core of search**, enabling filtering, analytics, dashboards, and correlations.  
Every event in Splunk contains fields, either **default metadata** or **extracted** from event data.

---

# 1️⃣ What Are Fields in Splunk?

A **field** is a key–value pair inside an event that Splunk can search, filter, and visualize.

Example event:
```
10.0.0.1 - - [15/Feb/2025] "GET /index.html" 200 532
```

Extracted fields may include:
- `client_ip=10.0.0.1`
- `method=GET`
- `status=200`
- `bytes=532`

---

# 2️⃣ Types of Splunk Fields

## 🔹 **Default (Indexed) Fields**
These exist in every event automatically:

| Field | Description |
|-------|-------------|
| `_time` | Event timestamp |
| `host` | Event source machine |
| `source` | File/log/input name |
| `sourcetype` | Type/format of data |
| `index` | Storage location |
| `_raw` | Original event text |

These fields are available **without extraction**.

---

## 🔹 **Search-Time Fields**
Extracted **when you run a search**.

Examples:
- `client_ip`
- `username`
- `status`
- `uri_path`
- `process_name`

Splunk’s **Field Extractor**, **regex**, and **lookups** help extract these.

---

## 🔹 **Runtime Fields**
Generated during search processing:

Examples:
- `eventcount`
- `linecount`
- `punct`
- Calculated fields using `eval`

---

# 3️⃣ Field Extraction Methods

Splunk uses multiple techniques to detect and extract fields.

## 🟦 1. **Automatic Field Extraction (Splunk Common Patterns)**  
Splunk automatically extracts:
- Key-value pairs (`user=john`)
- JSON fields  
- CSV fields  
- Syslog patterns  

## 🟩 2. **Props & Transforms (Advanced Extraction)**  
Configured in:
```
props.conf
transforms.conf
```

Used for:
- Complex patterns  
- Rewriting fields  
- Delimited data  
- Anonymization  

Example:
```
REGEX = user=(\w+)
FORMAT = username::$1
```

## 🟨 3. **Interactive Field Extractor (IFX)**  
GUI tool for building field extractions.

## 🟧 4. **Lookups**  
Maps external data into new fields.

Example:
```spl
| lookup geoip client_ip OUTPUT country city
```

## 🟥 5. **KV_MODE**  
Splunk’s own mechanism for auto key=value extraction.

---

# 4️⃣ Field Categories

## 🔹 Event Fields  
Extracted from raw log content.

## 🔹 Metadata Fields  
Assigned during ingestion (`host`, `source`, `sourcetype`).

## 🔹 Calculated Fields  
Created with commands:
- `eval`
- `stats`
- `rex`
- `spath`

Example:
```spl
| eval status_type = if(status>=500, "server_error", "ok")
```

## 🔹 Multi-value Fields  
Contain more than one value.

Example:
```
roles = ["admin","db","security"]
```

---

# 5️⃣ Field Discovery in Splunk UI

Splunk displays fields in:

### ➤ **Selected Fields**
Most relevant / frequently used  
(Up to 20 fields shown)

### ➤ **Interesting Fields**
Fields that appear often but are not selected

### ➤ **Available Fields (Sidebar)**
All searchable fields in the dataset

---

# 6️⃣ Managing Fields via SPL

### 🔹 Extract fields using `rex`
```spl
... | rex "user=(?<username>\w+)"
```

### 🔹 Extract JSON using `spath`
```spl
... | spath path=user.name output=username
```

### 🔹 Keep only specific fields
```spl
| fields host source status bytes
```

### 🔹 Remove fields
```spl
| fields - punct linecount
```

### 🔹 Rename fields
```spl
| rename client_ip as src_ip
```

### 🔹 Add new fields
```spl
| eval duration_sec = duration/1000
```

---

# 7️⃣ Field Normalization (CIM Compliance)

Used for SIEM, SOC, and threat hunting.

Examples of normalized fields:
- `src`, `dest`
- `user`
- `signature`
- `action`
- `severity`

Normalization enables:
- Correlation searches  
- Enterprise Security apps  
- Unified dashboards  

---

# 8️⃣ Important Field Naming Conventions

| Convention | Example | Notes |
|-----------|---------|------|
| Lowercase recommended | `src`, `dest` | Easier to search |
| Avoid spaces | `user_name`, not `user name` | Splunk treats spaces negatively |
| Use consistent prefixes | `http_*`, `dns_*` | Better grouping |
| Use CIM fields when possible | `src_ip`, `process_name` | Supports ES, ITSI |

---

# 9️⃣ Best Practices

- Use consistent naming  
- Avoid excessive calculated fields  
- Normalize fields to CIM when needed  
- Ensure sourcetypes have consistent extraction  
- Use lookups for enrichment  
- Validate fields with `fieldsummary`  
- Document custom fields in README files  

---

# 🔟 Useful SPL for Field Analysis

### 🟦 List all fields
```spl
| fieldsummary
```

### 🟩 Count occurrences of each field
```spl
| metadata type=sourcetypes
```

### 🟨 Find missing or null fields
```spl
| where isnull(user) OR user=""
```

### 🟥 Show fields per event
```spl
| table _time host source sourcetype user action status
```

---

# ✅ Summary

Splunk fields are the foundation for:
- Searching  
- Filtering  
- Dashboards  
- Alerts  
- Correlations  
- Threat hunting  

By understanding **field types, extraction, normalization, and SPL manipulation**, you can build highly optimized searches and clean, powerful datasets.

This file can be placed directly into your GitHub documentation as `fields.md`.
