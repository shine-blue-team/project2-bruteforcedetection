Splunk Alert Configuration Reference
Alert: Real-Time Brute Force Detection - Windows 10

Alert Settings
FieldValueTitleReal-Time Brute Force Detection - Windows 10 Alert TypeReal-timeTrigger ConditionPer-ResultSeverityHighActionAdd to Triggered Alerts

Base Query (saved with the alert)
splindex=* EventCode=4625
| bucket _time span=5m
| stats count as FailedAttempts by _time, host, Account_Name
| where FailedAttempts > 5

How It Works
Windows 10 generates Event ID 4625
         ↓
Universal Forwarder ships log to Kali (port 9997)
         ↓
Splunk indexes the event in real-time
         ↓
Real-time alert query runs continuously
         ↓
If FailedAttempts > 5 in any 5-min window → FIRES
         ↓
Appears in Activity → Triggered Alerts within 1–2 min

Why Real-Time vs Scheduled
TypeHow it worksDelayScheduledRuns every N minutes on a scheduleUp to schedule intervalReal-timeMonitors continuously, fires on every new match1–2 minutes max
Real-time is used here because brute force attacks can complete in under 60 seconds. A scheduled alert running every 5 minutes could miss a fast attack. Real-time ensures the alert fires as soon as the threshold is crossed.

How to View Triggered Alerts
Splunk → Activity → Triggered Alerts
Refresh this page every 30 seconds when monitoring. Each time the simulation runs and threshold is exceeded, a new entry appears here. This is the Tier 1 SOC analyst alert queue workflow.

Testing the Alert
Run the simulation on Windows 10 CMD:
cmdfor /L %i in (1,1,20) do net use \\127.0.0.1\ipc$ /user:Administrator wrongpassword123
Then monitor Activity → Triggered Alerts — alert should appear within 1–2 minutes.

Risk Thresholds Reference
ThresholdRisk LevelMeaning> 5 attempts / 5 minTriggers alertMinimum brute force indicator6–9 attempts / 5 minMEDIUMLow-rate brute force or password spray10–19 attempts / 5 minHIGHActive brute force attack20+ attempts / 5 minCRITICALAggressive brute force — immediate response needed

Event IDs Referenced
Event IDMeaningUsed For4625Failed logonBrute force detection4624Successful logonPost-attack compromise check

Alert configured in Splunk Enterprise on Kali Linux as part of SOC home lab project.
