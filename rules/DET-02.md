# DET-01

**Rule ID:** DET-01

**Title:** Multiple Failed Windows Logons

**Hypothesis:** Adversaries may attempt to brute force or spray credentials to gain unauthorized access to domain or local accounts. This activity will generate an unusually high volume of failed logon events (Event ID 4625) originating from a single source host within a 5-minute window.

**Data source:**
| Name | Index | Sourcetype | Source |
| --- | --- | --- | --- |
| Windows Event Log Security `4625` | `windows` | `'XmlWinEventLog'` | `'XmlWinEventLog:Security'` |


**SPL query:**

```spl
index=windows (source="XmlWinEventLog:Security" OR source="WinEventLog:Security") EventCode=4625
| eval src_ip=coalesce(IpAddress, src, "unknown")
| eval src_ip=if(src_ip="-", "unknown", src_ip)
| eval dest_host=coalesce(Computer, host)
| eval target_user=coalesce(TargetUserName, user)
| where isnotnull(target_user) AND target_user!="-"
| bin _time span=5m
| stats
    count AS failed_logons
    dc(target_user) AS unique_accounts
    values(target_user) AS targeted_users
    values(Logon_Type) AS logon_types
    BY _time, src_ip, dest_host
| where failed_logons >= 5
| sort - failed_logons
```

**Threshold:** 5

**MITRE ATT&CK mapping:** T1110.001, T1110.003

| ID | Techniques | Tactics |
| --- | --- | --- | 
| T1110.001 | Password Guessing | Credential Access (TA006) |
| T1110.003 | Password Spraying | Credential Access (TA006) | 

**Evidence path:**

