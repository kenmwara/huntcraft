# RDP-Flare (Practice)
<!-- Flag questions for the generator, as captured from the Range hunt page during the live solve (25 Nov).
     One '## section | flag | points' header per flag, then the question.
     Optional lines: 'format: ...' and 'choices: A | B | C' (choices makes it multiple choice). -->

## 1 Initial Access | Q1 - The Successful Break-In | 75
The external address that racked up a run of RDP failures then landed a successful logon.
format: xxx.xxx.xxx.xxx

## 1 Initial Access | Q2 - The Account Used | 50
Name the real account used to break in.
format: username

## 1 Initial Access | Q3 - RDP Hardening Control | 100
The Windows auth feature that forces authentication at the network layer before an RDP session, blocking brute force from reaching the login screen.
choices: Network Level Authentication | Account Lockout Policy | Windows Firewall rule | BitLocker

## 2 Execution | Q1 - What They Ran | 75
The real payload binary run about an hour after landing (not the calc.exe decoy).
format: filename

## 2 Execution | Q2 - How It Was Launched | 75
The exact command line that launched the payload - full path, full arguments.
format: the full command line

## 3 Persistence | Q1 - Staying In | 125
What the attacker registered to survive a reboot (not a scheduled task).
format: service name

## 4 Discovery | Q1 - Mapping the Host | 75
The two discovery commands about the HOST itself (not network, not accounts).
format: two commands, comma separated

## 5 Collection | Q1 - Packaged for Theft | 75
The archive zipped and staged in the attacker's temp directory, named to look routine.
format: filename

## 6 Command and Control | Q1 - Phoning Home | 100
The destination the Execution-section binary (msupdate.exe) called out to.
format: IP or domain

## 7 Exfiltration | Q1 - The Failed Handoff | 100
The IP:Port the session tried to send the archive to (attempt failed).
format: IP:Port

## 8 Judgement | Q1 - Shared Infrastructure | 100
185.92.220.87 is the C2 (port 80) and the exfil target (port 8081). What does that reuse say about the attacker's infrastructure?
format: one or two sentences of reasoning
