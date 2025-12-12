# 🔐 Sample Security Logs  
This file provides realistic **security-related log samples** for SIEM testing, detection engineering, and correlation rule development.  
Includes authentication logs, authorization events, privilege escalation, account changes, file integrity alerts, AV/EDR detections, and more.

---

# 1. Authentication Events (Windows, Linux, MFA)

## Windows – Successful Logon  
```
2025-02-12 10:21:54 WIN-DC01 EventID=4624 LogonType=2 User=john.doe SrcIP=192.168.1.50 Status=Success
```

## Windows – Failed Logon  
```
2025-02-12 10:22:11 WIN-DC01 EventID=4625 User=admin SrcIP=203.0.113.90 Reason=BadPassword
```

## Windows – RDP Logon  
```
2025-02-12 10:33:41 WIN-SRV02 EventID=4624 LogonType=10 User=sara.miller SrcIP=192.168.1.55
```

## Linux – Successful SSH Login  
```
Feb 12 10:51:22 ubuntu01 sshd[1221]: Accepted password for mike from 203.0.113.98 port 51432 ssh2
```

## Linux – Failed SSH Login  
```
Feb 12 10:52:12 ubuntu01 sshd[1221]: Failed password for root from 203.0.113.98 port 51500 ssh2
```

## MFA – Challenge + Success  
```
2025-02-12 10:59:41 Duo user=john.doe action=login factor=push result=success ip=192.168.1.50
```

---

# 2. Privilege Escalation & Admin Activity

## Windows – Local Admin Added  
```
2025-02-12 11:21:44 WIN-DC01 EventID=4728 AddedMember=alice Group=Domain Admins
```

## Windows – User Granted Rights  
```
2025-02-12 11:25:33 WIN-SRV01 EventID=4670 Privilege=SeDebugPrivilege User=ITAdmin
```

## Linux – Sudo Command  
```
Feb 12 11:44:12 ubuntu01 sudo: alice : TTY=pts/2 ; COMMAND=/usr/bin/systemctl restart apache2
```

## Linux – Privilege Escalation Attempt  
```
Feb 12 11:52:19 ubuntu01 su[1550]: FAILED su for root by student
```

---

# 3. Account Lifecycle Events

## User Created  
```
2025-02-12 12:10:33 WIN-DC01 EventID=4720 UserCreated=temp_user CreatedBy=itadmin
```

## User Deleted  
```
2025-02-12 12:13:29 WIN-DC01 EventID=4726 UserDeleted=contractor1 DeletedBy=itadmin
```

## Password Reset  
```
2025-02-12 12:18:01 WIN-DC01 EventID=4724 User=jane.smith ResetBy=helpdesk1
```

## Linux – New User  
```
Feb 12 12:22:15 ubuntu01 useradd[1100]: new user: name=backupadmin uid=1002
```

---

# 4. File Integrity Monitoring (FIM)

## Unauthorized File Change  
```
2025-02-12 12:41:21 FIM Alert file=/etc/passwd user=student action=modified
```

## Sensitive File Access  
```
2025-02-12 12:44:55 FIM Alert file=C:\Finance\salary.xlsx user=guest action=read
```

## File Deleted  
```
2025-02-12 12:46:09 FIM Alert file=/var/log/auth.log action=deleted user=root
```

---

# 5. Endpoint Protection (AV / EDR)

## Malware Detected  
```
2025-02-12 13:11:55 Defender alert malware=Trojan.Generic severity=high file=C:\Users\john\temp.exe action=quarantined
```

## Ransomware Behavior Blocked  
```
2025-02-12 13:14:44 CrowdStrike alert type=ransomware_write pattern=multi-file-encryption user=sara host=WIN-SRV10
```

## Suspicious Script Execution  
```
2025-02-12 13:20:35 SentinelOne script=powershell.exe -enc JAB... user=guest action=blocked
```

## Persistence Mechanism  
```
2025-02-12 13:22:40 EDR alert registry=HKCU\Software\Microsoft\Windows\Run key=Updater.exe action=created
```

---

# 6. Security Policy & Configuration

## Firewall Rule Added  
```
2025-02-12 13:35:41 WIN-SRV02 EventID=4946 action=FirewallRuleAdded rule=Allow-All-445
```

## Audit Policy Modified  
```
2025-02-12 13:37:21 WIN-DC01 EventID=4719 Setting=System Audit ChangedBy=admin
```

## SELinux Violation  
```
Feb 12 13:39:44 centos1 setroubleshoot: SELinux is preventing nginx from read access to /root
```

---

# 7. Security Tool Alerts (SIEM, IDS, DLP, UBA)

## SIEM Correlation – Bruteforce  
```
2025-02-12 13:55:51 SIEM Alert type=BruteForce user=admin failures=25 src_ip=203.0.113.200
```

## DLP – Sensitive Data Upload  
```
2025-02-12 14:12:11 DLP Alert file=client_list.csv action=blocked user=john.doe destination=upload.io
```

## UBA – Impossible Travel  
```
2025-02-12 14:21:33 UBA Alert user=sara location1=USA location2=Russia interval=15min
```

## IDS – Lateral Movement  
```
2025-02-12 14:25:41 IDS alert signature=SMB_Lateral_Move src=10.0.0.5 dst=10.0.0.30 severity=high
```

---

# 8. High-Risk Scenarios (SOC Lab)

## Password Spraying  
```
2025-02-12 14:33:29 WIN-DC01 EventID=4625 user=employee1 SrcIP=203.0.113.45 count=100
```

## Suspicious Admin Login at Odd Hours  
```
2025-02-12 03:11:11 WIN-DC01 EventID=4624 User=ITAdmin LogonType=10 SrcIP=192.168.1.88
```

## File Encryption Surge  
```
2025-02-12 14:55:51 EDR alert crypto_activity=high files_modified=4550 user=sara
```

## DNS Tunneling  
```
2025-02-12 15:01:33 dns01 query type=TXT size=15000 name=datachunk.mysite.com
```

---

# Summary  
This file includes sample logs for:
- Authentication and authorization  
- Admin and privilege escalation activity  
- Account lifecycle events  
- File integrity alerts  
- Endpoint security/EDR detections  
- Audit policy changes  
- DLP, IDS, UBA alerts  
- High-risk security scenarios  

