Setup Guide — Brute Force Attack Detection using Splunk
This guide walks through all 6 phases of the project from environment setup to documentation.

Prerequisites
Requirement Details Kali Linux VM Splunk Enterprise installed at /opt/splunk Windows 10 VM Splunk Universal Forwarder installed Network Both VMs on the same network (Kali IP reachable from Windows 10)Splunk Port9997 open for forwarder → Splunk communicationSplunk Web Port8000 open on Kali for browser access

Phase 1 — Environment Verification
Step 1 — Confirm Splunk is running on Kali
Open browser on Kali and go to:
http://localhost:8000
Login with your admin credentials. You should see the Splunk home screen.
If Splunk is not running, open Kali terminal and run:
bashsudo /opt/splunk/bin/splunk start

Step 2 — Confirm Splunk Forwarder is running on Windows 10
On Windows 10:

Press Win + R, type services.msc, press Enter
Find SplunkForwarder in the list
Status must show Running

If stopped — right-click → Start
If SplunkForwarder is missing entirely, install the Universal Forwarder pointing to your Kali IP on port 9997.

Step 3 — Confirm Windows 10 logs are reaching Splunk
In Splunk on Kali → Search and Reporting. Set time range to All Time and run:
splindex=* | stats count by host | sort -count
You should see your Windows 10 machine hostname in the results with events.
If Windows 10 hostname is missing — check outputs.conf on Windows 10 is pointing to your Kali IP:9997 and that Windows 10 firewall is not blocking outbound port 9997.

Step 4 — Confirm Security logs are coming from Windows 10
Replace WIN10-HOSTNAME with your actual hostname (run hostname in Windows CMD):
spl index=* host="DESKTOP-OAIVT6V" sourcetype="WinEventLog:Security"
| head 10
If you see results — Phase 1 is complete. 

Phase 2 — Brute Force Attack Simulation
Step 1 — Understand what you are simulating
You are generating Windows Security Event ID 4625 (Failed Logon) by attempting wrong password logins repeatedly. This is safe — all attempts are against your own local machine using 127.0.0.1.

Step 2 — Open Command Prompt as Administrator on Windows 10
Right-click Start menu → Command Prompt (Administrator)

Step 3 — Run the brute force simulation
Copy and paste into CMD on Windows 10:
cmdfor /L %i in (1,1,20) do net use \\127.0.0.1\ipc$ /user:Administrator wrongpassword123
You will see this repeat 20 times — that is correct:
System error 1326 has occurred.
Logon failure: unknown user name or bad password.
Each error = one Event ID 4625 in Windows Security log.

Step 4 — Verify in Windows Event Viewer
Press Win + R → type eventvwr → press Enter
Go to: Windows Logs → Security
Press F5 to refresh
Look for 20 × Event ID 4625 at the top
Take Screenshot 1 — Event Viewer showing 20 Event ID 4625 entries.

Step 5 — Wait for Splunk to collect the logs
Wait 1–2 minutes. The Universal Forwarder sends logs to Kali every 60 seconds. Then move to Phase 3.

Phase 3 — Detection Queries in Splunk
Open Splunk on Kali → Search & Reporting → set time range to Last 15 minutes.

Query 1 — Confirm failed logins from Windows 10
splindex=* EventCode=4625
| table _time, host, Account_Name, IpAddress, Failure_Reason
| sort -_time
You should see 20 events from your Windows 10 hostname.
Take Screenshot 2.

Query 2 — Count failed logins per machine
splindex=* EventCode=4625
| stats count as "Failed Logins" by host, Account_Name
| sort -"Failed Logins"
Windows 10 should show count of 20.

Query 3 — Brute force detection with risk rating  (Main detection query)
splindex=* EventCode=4625
| bucket _time span=5m
| stats count as FailedAttempts by _time, host, Account_Name
| where FailedAttempts > 5
| eval Risk=case(
    FailedAttempts >= 20, "CRITICAL",
    FailedAttempts >= 10, "HIGH",
    FailedAttempts > 5,  "MEDIUM")
| table _time, host, Account_Name, FailedAttempts, Risk
| sort -FailedAttempts
Windows 10 should appear with 20 attempts and CRITICAL risk.
Take Screenshot 3.

Query 4 — Check if attacker succeeded after brute force
splindex=* (EventCode=4625 OR EventCode=4624)
| eval LoginType=case(
    EventCode="4625", "Failed",
    EventCode="4624", "Success")
| stats count(eval(LoginType="Failed")) as Failures,
        count(eval(LoginType="Success")) as Successes
        by host, Account_Name
| where Failures > 5 AND Successes > 0
| eval Status="COMPROMISED - Investigate Immediately"
| table host, Account_Name, Failures, Successes, Status
Expected result: no rows returned — no successful login after brute force. No compromise. ✅

Query 5 — Failed login timeline
Replace WIN10-HOSTNAME with your actual hostname:
splindex=* EventCode=4625 host="DESKTOP-OAIVT6V"
| timechart count span=1m
| rename count as "Failed Logins per Minute"
Use Line Chart visualization. You should see a sharp spike at the simulation time.

Phase 4 — Real-Time Alert Configuration
Step 1 — Run the base detection query
splindex=* EventCode=4625
| bucket _time span=5m
| stats count as FailedAttempts by _time, host, Account_Name
| where FailedAttempts > 5
Confirm it returns results from Windows 10.

Step 2 — Save as Real-Time Alert
Click Save As → Alert and enter:
FieldValueTitleReal-Time Brute Force Detection - Windows 10 Alert typeReal-timeTriggerPer-ResultSeverityHighActionAdd to Triggered Alerts
Click Save.

Step 3 — Test the alert
Run the simulation again on Windows 10 CMD:
cmdfor /L %i in (1,1,20) do net use \\127.0.0.1\ipc$ /user:Administrator wrongpassword123
Then go to Splunk → Activity → Triggered Alerts
Within 1–2 minutes you should see the alert fire.
Take Screenshot 4 — Triggered Alerts showing the alert fired.

Step 4 — Monitor the alert queue
Leave Activity → Triggered Alerts open and refresh every 30 seconds.
This is exactly how a Tier 1 SOC analyst monitors their alert queue.

Phase 5 — SOC Dashboard
Step 1 — Create a new dashboard
Dashboards → Create New Dashboard
Title:       Brute Force Attack Detection - Windows 10
Permissions: Private
Click:       Create Dashboard

Panel 1 — Failed login spike (Line Chart)
splindex=* EventCode=4625 host="DESKTOP-OAIVT6V"
| timechart count span=1m
| rename count as "Failed Logins"
Title: Failed Login Timeline - Windows 10

Panel 2 — Total failed logins (Single Value)
splindex=* EventCode=4625 host="DESKTOP-OAIVT6V"
| stats count as "Total Failed Logins"
Title: Total Failed Logins - Windows 10

Panel 3 — Brute force detection results (Statistics Table)
splindex=* EventCode=4625
| bucket _time span=5m
| stats count as FailedAttempts by _time, host, Account_Name
| where FailedAttempts > 5
| eval Risk=case(
    FailedAttempts>=20,"CRITICAL",
    FailedAttempts>=10,"HIGH",
    FailedAttempts>5,"MEDIUM")
| table _time, host, Account_Name, FailedAttempts, Risk
| sort -FailedAttempts
Title: Brute Force Detection Results

Panel 4 — Failed vs Successful logins (Bar Chart)
splindex=* (EventCode=4624 OR EventCode=4625) host="DESKTOP-OAIVT6V"
| eval LoginType=if(EventCode="4624","Successful","Failed")
| stats count by LoginType
Title: Login Activity - Windows 10

Step 6 — Save and screenshot
Click Save. Run the simulation one more time so all panels show live data.
Take Screenshot 5 — Full 4-panel dashboard with live attack data.

Phase 6 — Documentation & Portfolio
