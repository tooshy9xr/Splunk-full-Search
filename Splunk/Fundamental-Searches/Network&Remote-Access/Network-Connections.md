# 🌐 Failed / Successful Network Connections — Windows & Linux

Detection queries for monitoring inbound/outbound network connections, including failures, successful connections, and suspicious usage.

---

# 🪟 Windows — Network Connections

## 🔹 1. Successful Network Connections  
**Description:** Detects accepted network connections.  
**Purpose:** Useful for tracking allowed remote access or lateral movement.

**🔍 SPL**
```
index=windows EventCode=5156
| stats count by Source_Address, Source_Port, Dest_Address, Dest_Port, Protocol, Computer, _time
```

---

## 🔹 2. Blocked / Failed Network Connections  
**Description:** Firewall blocked a connection attempt.  
**Purpose:** Indicates scanning attempts or unauthorized communication.

**🔍 SPL**
```
index=windows EventCode=5157
| stats count by Source_Address, Dest_Address, Dest_Port, Process_Name, Computer, _time
```

---

## 🔹 3. RDP Connection Attempts (Success & Fail)  
**Description:** Detects RDP logins and failures.  
**Purpose:** High-risk for brute-force attacks.

**🔍 SPL**
```
index=windows (EventCode=4624 OR EventCode=4625) Logon_Type=10
| stats count by Account_Name, Workstation_Name, Source_Network_Address, EventCode, _time
```

---

## 🔹 4. Suspicious Outbound Connections  
**Description:** Connections to uncommon external IPs.  
**Purpose:** Potential data exfiltration or command-and-control.

**🔍 SPL**
```
index=windows EventCode=5156 Dest_Address!="10.*" Dest_Address!="192.168.*" Dest_Address!="172.16.*"
| stats count by Source_Address, Dest_Address, Dest_Port, Process_Name, Computer, _time
```

---

# 🐧 Linux — Network Connections

## 🔹 5. Successful Network Connections  
**Description:** Shows successful inbound/outbound connection events.  
**Purpose:** Tracks allowed communications and remote activity.

**🔍 SPL**
```
index=linux sourcetype=linux_network action=allowed
| stats count by src_ip, src_port, dest_ip, dest_port, protocol, host, _time
```

---

## 🔹 6. Failed Network Connections  
**Description:** Shows dropped or blocked connections.  
**Purpose:** Useful for detecting scans or firewall blocks.

**🔍 SPL**
```
index=linux sourcetype=linux_network action=denied
| stats count by src_ip, dest_ip, dest_port, protocol, host, _time
```

---

## 🔹 7. SSH Connection Attempts (Success & Fail)  
**Description:** Detects SSH authentication events.  
**Purpose:** Helps monitor brute-force or unauthorized remote access.

**🔍 SPL**
```
index=linux (message="Accepted password" OR message="Failed password")
| stats count by user, src_ip, host, message, _time
```

---

## 🔹 8. Suspicious External Connections  
**Description:** Outbound connections to non-internal IPs.  
**Purpose:** Detects data exfiltration or malware beaconing.

**🔍 SPL**
```
index=linux sourcetype=linux_network NOT dest_ip="10.*" NOT dest_ip="192.168.*" NOT dest_ip="172.16.*"
| stats count by src_ip, dest_ip, dest_port, process, host, _time
```
