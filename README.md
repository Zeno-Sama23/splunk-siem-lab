# Splunk SIEM Detection Lab

## Overview
Splunk Enterprise deployment with custom SPL detection rules mapped to MITRE ATT&CK framework and a security monitoring dashboard.

## Stack
- Splunk Enterprise (trial)
- Windows Event Logs
- SPL (Search Processing Language)
- Custom security dataset

## Detection Rules

| Rule | EventCode | MITRE ATT&CK | Severity |
|------|-----------|-------------|----------|
| Brute Force Detection | 4625 | T1110.001 - Credential Access | Medium |
| Account Created Outside Hours | 4720 | T1136.001 - Persistence | Medium |
| Privilege Escalation Detection | 4672 | T1078.003 - Privilege Escalation | High |
| Impossible Travel Detection | 4624 | T1078 - Initial Access | High |

## Key Findings (Sample Dataset)
- **4 brute force attacks** detected from external IPs (185.220.101.50, 91.108.4.200)
- **2 suspicious accounts** created outside business hours (02:30, 23:45)
- **1 admin account** logged in from 2 different IPs simultaneously

## Skills Demonstrated
- SPL query writing and detection engineering
- Windows Event Log analysis
- MITRE ATT&CK threat mapping
- Security dashboard design
- Multi-SIEM skills (KQL + SPL)
