INCIDENT REPORT

Field    Value 
Title    Brute Force Login Attack — Windows 10 Endpoint
Date     [04.06.2026]
Severity  High
Analyst   [jason]
StatusClosed — Simulation Confirmed


Summary
A brute force login attack was detected on Windows 10 machine [DESKTOP-OAIVT6V]. 20 failed login attempts (Event ID 4625) were recorded within 60 seconds against the Administrator account. The attack was detected by a Splunk SIEM real-time alert rule within 1–2 minutes of the first failed attempt. Attack was confirmed as a controlled lab simulation with no actual compromise.

Timeline
TimeEvent[14:35:00]First failed login (Event ID 4625) recorded on Windows 10[2:35]20th failed login recorded — simulation complete[HH:MM]Splunk Universal Forwarder shipped logs to Kali SIEM[HH:MM]Alert "Real-Time Brute Force Detection - Windows 10" triggered in Splunk[2:35]Analyst investigated — confirmed controlled simulation[HH:MM]Incident closed — no compromise detected

Indicators of Compromise (IOCs)
IndicatorValueSource IP 127.0.0.1 (local simulation)Target Account AdministratorTarget Machine[DESKTOP-OAIVT6V]Event IDs Observed4625 × 20Logon Type3 (Network)Time Window~60 secondsTool Usednet use command (Windows built-in)

Detection Details
Detection FieldValueSIEM PlatformSplunk Enterprise (hosted on Kali Linux)Log SourceWindows 10 Security Event Log via Universal ForwarderDetection QueryEventCode=4625 bucketed in 5-minute windows, threshold > 5Risk Rating AssignedCRITICAL (20+ attempts in 5-minute window)Alert TypeReal-time, Per-ResultAlert NameReal-Time Brute Force Detection - Windows 10

Analysis
Failed Login Pattern
Account targeted:   Administrator
Attempts made:      20
Time window:        ~60 seconds
Source address:     127.0.0.1
Failure reason:     Unknown username or bad password
Logon type:         3 (Network logon via IPC$)
Post-Attack Login Check
Query run to check if attacker succeeded after brute force:
splindex=* (EventCode=4625 OR EventCode=4624)
| eval LoginType=case(EventCode="4625","Failed",EventCode="4624","Success")
| stats count(eval(LoginType="Failed")) as Failures,
        count(eval(LoginType="Success")) as Successes
        by host, Account_Name
| where Failures > 5 AND Successes > 0
Result: No rows returned. No successful login followed the failed attempts. Account was not compromised.

Outcome
FindingResultBrute force attack detected Yes — CRITICAL riskSuccessful login after attack❌ NoAccount compromised❌ NoAlert fired in real-time Yes — within 1–2 minutesDashboard captured attack Yes — all 4 panels populated

Recommended Actions (For Real Incident)

Immediately disable the targeted account temporarily
Block source IP at the perimeter firewall and host-based firewall
Reset account password with a strong, unique credential
Enable account lockout policy — lock account after 5 failed attempts for 30 minutes
Review all successful logins (Event ID 4624) from the same account in the 24 hours around the attack window
Check for lateral movement — search for the same account authenticating to other machines
Preserve logs for forensic investigation before they are overwritten
Notify account owner and security management per IR policy


Lessons Learned

Real-time Splunk alerting successfully detected the attack within 1–2 minutes of the first failed login
Event ID 4625 + bucket-based SPL queries provide reliable brute force detection
Universal Forwarder log pipeline from Windows 10 to Kali SIEM worked end-to-end
Account lockout policy would have automatically stopped the attack after 5 attempts in a hardened environment


Report prepared as part of SOC Analyst home lab training.
