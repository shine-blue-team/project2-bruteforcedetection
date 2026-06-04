 Project Summary
Simulated brute force login attacks on a Windows 10 endpoint by generating repeated failed login attempts (Event ID 4625). Configured Splunk to collect Security event logs from Windows 10 via Universal Forwarder and wrote SPL detection queries to identify failed login patterns exceeding threshold within 5-minute windows. Created a real-time Splunk alert rule triggering on brute force detection and built a 4-panel dashboard visualizing attack timelines and login activity. Documented findings in a structured incident report.

 Tools & Technologies
Tool Purpose Splunk EnterpriseSIEM — log collection, detection, alerting, dashboardsSplunk Universal ForwarderForwards Windows 10 Security logs to SplunkWindows 10 VMAttack target endpointKali Linux VMSplunk server (SIEM host)Windows Event ViewerVerify Event ID 4625 locallySPL (Splunk Query Language)Detection queries and dashboards

 Lab Architecture
┌─────────────────────┐         Port 9997          ┌─────────────────────┐
│   Windows 10 VM     │ ─────────────────────────► │    Kali Linux VM    │
│                     │    (Universal Forwarder)    │                     │
│  - Generates 4625   │                             │  - Splunk Enterprise│
│  - Event Viewer     │                             │  - SIEM Dashboard   │
│  - Forwarder Agent  │                             │  - Alert Engine     │
└─────────────────────┘                             └─────────────────────┘

 Project Phases Overview
Phase Title Description Phase 
1.Environment Verification Confirm Splunk + Forwarder are running and logs flowing Phase 
2.Attack Simulation Generate 20 failed logins (Event ID 4625) on Windows 10 Phase 
3.Detection Queries  SPL queries to detect and analyse the brute force attack Phase 
4.Real-Time Alerting Configure Splunk alert to fire within 1–2 minutes of attack Phase 
5.SOC Dashboard 4-panel visual dashboard showing attack data live Phase 
6.Documentation write-up, incident report, screenshots portfolio

 Key Detection Logic
The core brute force detection query groups failed logins in 5-minute windows and assigns a risk rating:
spl index=* EventCode=4625
| bucket _time span=5m
| stats count as FailedAttempts by _time, host, Account_Name
| where FailedAttempts > 5
| eval Risk=case(
    FailedAttempts >= 20, "CRITICAL",
    FailedAttempts >= 10, "HIGH",
    FailedAttempts > 5,  "MEDIUM")
| table _time, host, Account_Name, FailedAttempts, Risk
| sort -FailedAttempts
Risk Thresholds:

🔴 CRITICAL — 20+ failed attempts
🟠 HIGH — 10–19 failed attempts
🟡 MEDIUM — 6–9 failed attempts


 Detection Results
Metric Value Failed Login Events Generated20Event ID Monitored4625 (Failed Logon)Detection Window5 minutesRisk Level TriggeredCRITICALSuccessful Logins After Attack0 (No compromise)Alert Firing TimeWithin 1–2 minutes

 Screenshots

Screenshots will be displayed in this /screenshots/ folder


 Incident Report
See docs/incident-report-template.md for the full incident report documenting the simulated attack.

 What I Learned

How Windows Security Event ID 4625 is generated and what it represents
How Splunk Universal Forwarder collects and ships logs from endpoints to SIEM
Writing SPL queries for threat detection and log analysis
Configuring real-time alerts in Splunk for continuous 24/7 monitoring
Building SOC dashboards to visualise security events
Incident documentation and reporting like a Tier 1 SOC analyst


⚠️ Disclaimer
This project was performed entirely in a controlled home lab environment using personal virtual machines. All simulated attacks were run locally (127.0.0.1) against accounts on machines owned by the author. No real systems, networks, or third parties were involved or targeted.
