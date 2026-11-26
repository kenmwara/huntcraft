window.HUNTS = [
 {
  "meta": {
   "slug": "rdp-flare",
   "title": "RDP-Flare (Practice)",
   "points": 950,
   "flag_count": 11,
   "host": "slflarewinsysmo",
   "tables": [
    "RdpFlarePracticeProcess_CL",
    "RdpFlarePracticeNetwork_CL",
    "RdpFlarePracticeFile_CL",
    "RdpFlarePracticeLogon_CL"
   ],
   "tenant_id": "939e93f3-04f6-479d-82ff-345c231abb4d",
   "incident_window_utc": {
    "start": "2025-09-16T18:34:00Z",
    "end": "2025-09-18T23:56:00Z"
   },
   "workspace": {
    "name": "LAW-HuntPractice",
    "guid": "ee718ed3-9e76-4b9d-a7b5-3500446fe4f4"
   },
   "credit": "Hunt content by SancLogic / the Cyber Range threat hunt team"
  },
  "guide": {
   "hunt": "rdp-flare",
   "title": "RDP-Flare (Practice)",
   "mode": "instruction-manual",
   "note": "This leads you to each flag. Run the queries yourself in the hunt's workspace (the Open in Defender button), follow what to look for, and you will see the answer in your own results before you ever reveal it.",
   "workspace": "LAW-HuntPractice (ee718ed3-9e76-4b9d-a7b5-3500446fe4f4)",
   "orientation": {
    "title": "Before any flag: get your bearings",
    "why": "You never start by querying for the answer. You start by learning the ground: which tables hold data, over what time window, and for which host. Thirty seconds here saves you from guessing later.",
    "do": "Run this. It tells you what telemetry exists and how much.",
    "query": "union withsource=T RdpFlarePractice*_CL\n| where TimeGenerated > ago(365d)  // logs were loaded on one day; widen the window so the portal time picker cannot hide them\n| summarize Events=count(), FirstEvent=min(Timestamp), LastEvent=max(Timestamp), LoadedAt=max(TimeGenerated), Hosts=make_set(DeviceName) by T",
    "look_for": "4 rows, one per table: Logon (260 events), Process (1,799), Network (1,377) and File (4,768), all from one host, slflarewinsysmo. These are the lab's copies of the Defender tables you will meet at work: RdpFlarePracticeLogon_CL is DeviceLogonEvents, RdpFlarePracticeProcess_CL is DeviceProcessEvents, RdpFlarePracticeNetwork_CL is DeviceNetworkEvents and RdpFlarePracticeFile_CL is DeviceFileEvents (same columns, a different name). Now compare the two clocks. FirstEvent and LastEvent come from Timestamp, the real event time: 16 to 18 Sep 2025. LoadedAt comes from TimeGenerated: 29 Oct 2026 on every table, the day the lab loaded the logs. That is why every query here filters and sorts on Timestamp.",
    "gotcha": "Every row's TimeGenerated is the same (the moment the lab loaded the logs, 29 Oct 2026). The REAL attack time is in the Timestamp column, so sort and filter on Timestamp. Each query starts with a TimeGenerated line so the portal's time picker (Defender defaults to 7 days) can't hide the rows. Every time in this manual is UTC, but Defender shows your local time until you switch it, so set Defender to UTC before you start.",
    "defender_url": "https://security.microsoft.com/v2/advanced-hunting?query=H4sIAAAAAAACCn2SS0vEMBSFz9pfkWUVwYXoRiqIOroYRMT9EJ1gi7Ydms74wB%2Fvl9uMI4wMIW3uufec%2B0iWalWr4%2Bv0zmlQpYi9VK9nBZV6xPOguRaa6E0ePOier8c%2FwEhRB5rpUlPt6dt0KrAU52DXajjdsFtDPayAntM52%2BuFbIWOdaoT0H0wpyOWI1uHN5riWi9hnrhRYay7M2UH4vWps9zJ3DI66yhkrAXtODnrceNbYPVYHn1nXTUZT%2F29WnbHyaPQEjtgVTnHWqXJ3Udm17DSpGp9WcS1VlbNgLdEJ803WQX9HuKfENnjG%2F5ElmikiovfGUarsKGqkTXF2uZ4fezkbOZ38S9j%2B6ZG5i3MmDtInDSVGVawPq74r%2FJruLOMwe7yiRtJr%2BAHvOIAAGgCAAA%3D&timeRangeId=month&tid=939e93f3-04f6-479d-82ff-345c231abb4d"
   },
   "flags": [
    {
     "section": "1 Initial Access",
     "flag": "Q1 - The Successful Break-In",
     "points": 75,
     "objective": "Several external IPs have been hammering this box's RDP. Find the one that failed a lot and then actually got in.",
     "where_to_look": {
      "decision": "Go to the Logon table (RdpFlarePracticeLogon_CL).",
      "why_here": "A break-in is an authentication event: who signed in, from where, success or failure. That is logon telemetry. It is not in the Process table (that is what ran AFTER access) or the Network table (connections, not logons). The hunt briefing itself points you here, which is a good habit: read what the hunt hands you.",
      "why_not_others": "You could jump straight to Process to find malware, but you would be guessing which host activity is the attacker before you even know which account they used. Establish the entry first; everything else pivots off it."
     },
     "steps": [
      {
       "think": "Do not filter for the answer yet, you do not know the IP or the account. Instead get the whole logon picture in one view: group by action, logon type, account and source IP, and count. An overview shows you the pattern; a narrow filter hides it.",
       "query": "RdpFlarePracticeLogon_CL\n| where TimeGenerated > ago(365d)  // logs were loaded on one day; widen the window so the portal time picker cannot hide them\n| summarize Attempts=count(), First=min(Timestamp), Last=max(Timestamp) by ActionType, LogonType, AccountName, RemoteIP\n| order by Attempts desc",
       "run_it": "Run this in the workspace.",
       "look_for": "Two columns carry the whole story. LogonType: 'Network' is a remote credential check (where brute force shows up), 'RemoteInteractive' is an actual RDP desktop session. ActionType: LogonFailed vs LogonSuccess. Scan the external IPs for one that has a long run of LogonFailed AND then a LogonSuccess. In Defender this returns 113 rows, sorted by attempts.",
       "observe": "Most source IPs only ever fail, they never got in. Your eye is hunting for the single IP that failed repeatedly on one account and then succeeded on it. Also notice the 'accounts' named dwm-1, umfd-0 and similar: those are Windows internals, not people. Learn to skip them.",
       "defender_url": "https://security.microsoft.com/v2/advanced-hunting?query=H4sIAAAAAAACCnWSS0vEQBCE6%2ByvmGMEwcOiF1EQYWVhEVn2LqMJbljzIIn4wB%2Fv1z0ZXQ8SZtJdVVM93clGpXot9aKoQZXu2aOeNKlmr7RWp2dWqwfdkB3pS0Fv2sGZPmiLsiG6ZbWORk5X%2BAZdsaKfL7TQuc5Aj8GCTnkCVc19dMfsZ1hElxysctqNK2E%2BdOH62jXGTn6bhLWgHVHAtTvgerKBLOIfvLtmxq3PvVcPRBGHFu1EtptrZJdm7n7UK3HjE6v16YprNJNret6jLvHq0LVkBT2foFmiHuAm2MbvWvxMb%2FS72emkXZNlZdT7P8qgR%2BZh1dMXszltQXp0ySV%2FvUPU1L%2B3u3O3xGy8g847WfEvpH5tcuU8oVzvb7fB%2BRHXb9%2B7eUNQAgAA&timeRangeId=month&tid=939e93f3-04f6-479d-82ff-345c231abb4d"
      },
      {
       "think": "You have probably already spotted it. Confirm it the strict way: show only the successful RemoteInteractive (real RDP) logons from an external address. If one IP and one account survive this filter, that is your break-in.",
       "query": "RdpFlarePracticeLogon_CL\n| where TimeGenerated > ago(365d)  // logs were loaded on one day; widen the window so the portal time picker cannot hide them\n| where LogonType == \"RemoteInteractive\" and ActionType == \"LogonSuccess\"\n| where RemoteIP !startswith \"10.\" and RemoteIP !startswith \"192.168.\"\n| project Timestamp, ActionType, RemoteIP, AccountName\n| order by Timestamp asc",
       "run_it": "Run it.",
       "look_for": "3 rows, each with ActionType LogonSuccess (the filter kept only the logons that worked). Two have an empty RemoteIP (sessions on the box itself); only one carries an external address. Note that row's address and its time. That time should read 18:43 on 16 Sep 2025; if it shows any other hour, Defender is still on your local time (Get your bearings, step 2).",
       "observe": "This is the moment of the break-in. You are now looking straight at the attacker's source address. You found it by reasoning, not by being told.",
       "defender_url": "https://security.microsoft.com/v2/advanced-hunting?query=H4sIAAAAAAACCpWSW0vDQBCFz7O%2FYs2TQlGrKIooiKAIIqX2XdY22Kq50KSK4I%2F3m0lCLcQHWTbsnDlz5paxZip1o3dFLZVqxDdqqloLvqnuVeiFm%2BtJ11hb%2BlbQp%2Bb4jB80gZnxuuXmjkaiU3SDLrnR43d0pBMdg%2B6CBe1zAllNvXLFTs%2BwCK9RsMzN13wzPF86d%2F7COeatvZoGy0ELXgHV4pevxFpiRfSDd5e1uPX55tkDr4hCDrfGmrc5OpWsp%2Fv1fCZUVjp2wQlKNPaYwqdxB6Nup9NM9wMr8fnk3ulVi%2FdrrfM8agXTdlNxkp6aNvOOQLZh1r7hmpfNyToy3aEOtLdRx%2F%2Biz3RI%2FJDdnrpOU00Jt9ArClOfZPePNDoZ%2FsEfHQ96Kui4U7CVz%2FHBVdI2m2121m7wGZ2%2BfNZfhcIPLry%2BGfACAAA%3D&timeRangeId=month&tid=939e93f3-04f6-479d-82ff-345c231abb4d"
      }
     ],
     "reveal": {
      "type": "input",
      "format": "xxx.xxx.xxx.xxx",
      "unordered": false,
      "salt": "rdp-flare|0|",
      "check": [
       "13766a9d41729b6b4cb5100e66e4066f2710c341d0c006e98c49a9ebc2fa91bf"
      ]
     },
     "mitre": "T1110 Brute Force"
    },
    {
     "section": "1 Initial Access",
     "flag": "Q2 - The Account Used",
     "points": 50,
     "objective": "Name the real account the attacker signed in with.",
     "where_to_look": {
      "decision": "Same Logon table, but now you have a lever: the attacker IP from Q1.",
      "why_here": "You are not searching blind any more. The account is simply whoever that IP successfully logged in as. This is the heart of pivoting: an answer you already have (the IP) becomes the filter for the next one.",
      "why_not_others": "You do not need a new data source. Beginners often go hunting somewhere new for each flag; the efficient move is to re-use what you already proved."
     },
     "steps": [
      {
       "think": "Filter the logon table to the attacker's IP and successful logons. Whatever account name comes back is the compromised identity. You can even read it off the Q1 overview without a new query, but filtering makes it unambiguous.",
       "query": "RdpFlarePracticeLogon_CL\n| where TimeGenerated > ago(365d)  // logs were loaded on one day; widen the window so the portal time picker cannot hide them\n| where RemoteIP == \"159.26.106.84\" and ActionType == \"LogonSuccess\"\n| distinct AccountName, LogonType",
       "run_it": "Run it.",
       "look_for": "3 rows: one account name, seen across three logon types (Network, RemoteInteractive, Unlock).",
       "observe": "One real username. Note it is an ordinary account, not Guest or anonymous, which is why the next sections matter: the attacker now has a legitimate identity to act under.",
       "defender_url": "https://security.microsoft.com/v2/advanced-hunting?query=H4sIAAAAAAACCm2RX0vDQBDE59lPsfRJQep%2FUURBBEUQkdp3OZpgi%2BYSmhQR%2FPD%2BdpNQH%2BTYy%2B3s7OzNZaZCje71qaS1Sr2wJy3UacVe6km13omsN92R7ehHpi8tqTnfNIdZcXogcqCJ7hJd0w2Ron9XJzrXGegemOmAZUx19TYURz3HErxewSf3u9cKKt%2B6Cv4qOF7t4jY9lkFrToZq%2FafWkK3JEvoW7qoBd58fMd04JRQy3I5sOcwYVap%2F3M8Cr8PxI69numaZJjrC7aWmOsb3lOwwvhc6pWYxx%2F3dDm%2FtDud4a0J11Ni%2B%2Fqs2MP2PtKzJcJOCzjb6c%2Bj0egs6NiCdnpnjPvepbLXGOb8nVFBB%2FAEAAA%3D%3D&timeRangeId=month&tid=939e93f3-04f6-479d-82ff-345c231abb4d"
      }
     ],
     "reveal": {
      "type": "input",
      "format": "username",
      "unordered": false,
      "salt": "rdp-flare|1|",
      "check": [
       "252226dae0b4331c5a2d90b816de38f376c184e59a9af84627f32343d73ea3fc"
      ]
     },
     "mitre": "T1078 Valid Accounts"
    },
    {
     "section": "1 Initial Access",
     "flag": "Q3 - RDP Hardening Control",
     "points": 100,
     "objective": "Name the Windows feature that, if it had been on, would have blocked this brute force at the network layer, before the login screen ever appeared.",
     "where_to_look": {
      "decision": "This one is NOT in the logs. It is a knowledge and remediation flag.",
      "why_here": "Not every flag is a query. Some test whether you understand the control that closes the gap you just found. The question itself is the clue: a feature that forces authentication 'at the network level before a full remote desktop session is established.'",
      "why_not_others": "Do not waste time querying, there is no row that says 'the fix is X.' Reason from how RDP works: without pre-session authentication, anyone hitting port 3389 gets a login screen to spray against; with it, the handshake happens first and failed attempts never reach a session."
     },
     "steps": [
      {
       "think": "Walk the candidates. Account Lockout slows spraying but does not act 'at the network level before a session'. A firewall rule blocks the port entirely, it is not an authentication feature. BitLocker is disk encryption, unrelated. That leaves one choice: the feature that makes the client prove who it is (via CredSSP) before Windows ever builds a desktop session. Pick the choice that matches that description.",
       "query": "(no query, reason it out)",
       "run_it": "Pick from the choices.",
       "look_for": "The control that matches 'authenticate at the network level before the session'.",
       "observe": "Mapping a finding to its specific control is exactly what a report's Detection and Gaps sections reward. You are not just finding the attack, you are naming the fix."
      }
     ],
     "reveal": {
      "type": "multiple_choice",
      "unordered": false,
      "choices": [
       "BitLocker",
       "Windows Firewall rule",
       "Network Level Authentication",
       "Account Lockout Policy"
      ],
      "salt": "rdp-flare|2|",
      "check": [
       "da633189da7f0b8f758a4f59cade5ef9340194955b5e03559694609653288ee9"
      ]
     },
     "mitre": "T1110 Brute Force (mitigation)"
    },
    {
     "section": "2 Execution",
     "flag": "Q1 - What They Ran",
     "points": 75,
     "objective": "About an hour after getting in, the attacker ran the real payload (not the calc.exe decoy). Name the binary.",
     "where_to_look": {
      "decision": "Go to the Process table (RdpFlarePracticeProcess_CL).",
      "why_here": "'What ran' is literally a process-creation event. Now that you know the account (slflare) from Section 1, you follow that account's activity here.",
      "why_not_others": "Logon got the attacker in; it cannot tell you what they executed. That is a different table, and the pivot is the account you already proved."
     },
     "steps": [
      {
       "think": "Do not dump every process, a live Windows box runs thousands of normal ones. Cut the noise deliberately: filter to the attacker's account, the window after the login, and exclude the standard Windows / OneDrive / Brave paths. Legit system binaries live under C:\\Windows; a dropped payload usually does not, so what remains is suspicious by location.",
       "query": "RdpFlarePracticeProcess_CL\n| where TimeGenerated > ago(365d)  // logs were loaded on one day; widen the window so the portal time picker cannot hide them\n| where Timestamp > datetime(2025-09-16 19:20) and AccountName =~ \"slflare\"\n| where FolderPath !startswith \"C:\\\\Windows\" and FolderPath !has \"OneDrive\" and FolderPath !has \"BraveSoftware\"\n| project Timestamp, FileName, FolderPath, ProcessCommandLine\n| order by Timestamp asc",
       "run_it": "Run it.",
       "look_for": "An executable running from a user-writable path (C:\\Users\\Public, Temp, ProgramData) rather than C:\\Windows. That is where attackers stage tools.",
       "observe": "This query starts at 19:20 UTC, after the cmd.exe /c calc.exe decoy the flag warns about, so the decoy is not in these results. Of the 4 rows, two DismHost.exe runs from a GUID folder in Temp are Windows servicing and PhoneExperienceHost.exe is the Phone Link app. One row is left.",
       "defender_url": "https://security.microsoft.com/v2/advanced-hunting?query=H4sIAAAAAAACCpWSW0vDQBCFz7O%2FYu1TCxVvVGhFQSv1paio4IsgMUlttElKUxVB%2FO1%2BO0lr1VaQJZPZM7NnrpeKNFZPIwWaKNYFMlCoqRJkec9NKzh36qqvNb3L6VVDUP%2FG6RrvFO2ULzM0gCGG2%2BmQL9ADLHXtak8t0AaY0ybHETnHWhjjjM9jAX4lQw5nKb0twvKmffNPzMdbp5ZNiWWgOZqDNV%2BwjblNuAXwO6swrXBf65NFd2gBDBm%2BU27DKsaMJf2j%2BsK4U%2FjKqqOqC7NIde1oi6%2BlDf5t5Db9cMi2OmZrWK8yq%2FqITEKyeOY%2B1Zkx%2B2gH%2BkDWiDbSYD632pK8erweWfYT5hhYBU7rVZ6%2BE4X1q8RrzLajW87NQg8L8K%2BcVjEO0QvjOLcpnWBP9GJ5%2Fef1sW2Of3eF7wCP1x%2F1jW0fH0FCm8%2Fv3jctUkKkeN615oroHv%2B%2B4V30lFPm3LdOxFVsvz1RtSX37ODyyftaQn0CKtHPG1gDAAA%3D&timeRangeId=month&tid=939e93f3-04f6-479d-82ff-345c231abb4d"
      }
     ],
     "reveal": {
      "type": "input",
      "format": "filename",
      "unordered": false,
      "salt": "rdp-flare|3|",
      "check": [
       "19fe49cc0aa2d4511f4d68e408af0ff53de5fd46d4cc555ea7a1dc5862c16e68"
      ]
     },
     "mitre": "T1059.001 PowerShell"
    },
    {
     "section": "2 Execution",
     "flag": "Q2 - How It Was Launched",
     "points": 75,
     "objective": "Get the exact command line that launched the payload, full path and arguments.",
     "where_to_look": {
      "decision": "Same Process table, now zoomed to that single process.",
      "why_here": "The ProcessCommandLine field holds the literal invocation, exactly as it was typed/scripted.",
      "why_not_others": "Nothing new to find; you are reading one field off the row you already located."
     },
     "steps": [
      {
       "think": "You have the binary. Pull its row and read ProcessCommandLine verbatim. The flag wants it exactly, including the switches, so copy what the data shows, do not paraphrase.",
       "query": "RdpFlarePracticeProcess_CL\n| where TimeGenerated > ago(365d)  // logs were loaded on one day; widen the window so the portal time picker cannot hide them\n| where FileName =~ \"msupdate.exe\"\n| project Timestamp, ProcessCommandLine",
       "run_it": "Run it.",
       "look_for": "1 row. Read the full command string: its flags and the script path it runs.",
       "observe": "The '-ExecutionPolicy Bypass' flag is the real tell: it survives even if the attacker renames the binary, so a good detection targets that behaviour, not the file name.",
       "defender_url": "https://security.microsoft.com/v2/advanced-hunting?query=H4sIAAAAAAACCm2RwWrCQBCG%2F3OfYvFUobQHsRdpL4K9iIh4l8WEqnWzwURUKH12v51NoIWyzDDzz%2Bw3mc1KhWrNdJTXSaWWeK%2BtWu3xOY8WNZyNpprrQd9yumiHmu44rekORB9YZaqHUMJ2ese8PqE8aqRXjVGHaE4vHMfkSLUxYs9LmqcvEyLM7FOtoHLTxPr31pOqrX1N1irUSOSgxl%2B1muxE5uE72zB0etr1y6Y7Ig%2Bhorcl23Uzekr4Z%2FsZPUeiBTcz8U0%2F%2BAFZozP8onuPZ%2ByKDTpKba97QNnatP4dG%2FvKQP0J9e8%2FmBIHjrc957ZvqTvK8EnhyAEAAA%3D%3D&timeRangeId=month&tid=939e93f3-04f6-479d-82ff-345c231abb4d"
      }
     ],
     "reveal": {
      "type": "input",
      "format": "the full command line",
      "unordered": false,
      "salt": "rdp-flare|4|",
      "check": [
       "6226719e56abb1cf47aa6bc929b680b141504fc96a28253f77309b0ea84ab156"
      ]
     },
     "mitre": "T1059.001 PowerShell"
    },
    {
     "section": "3 Persistence",
     "flag": "Q1 - Staying In",
     "points": 125,
     "objective": "The attacker did not want to re-break-in every time. They registered something to survive a reboot. Name it (and do not assume it is a scheduled task).",
     "where_to_look": {
      "decision": "Back to the Process table.",
      "why_here": "Persistence is SET UP by running a command: sc create (a service), schtasks (a task), reg add (a run key), net user (an account). This hunt has no Registry table, so the command that created the persistence is your evidence, and it lives in Process.",
      "why_not_others": "You might reach for a dedicated persistence or registry table. You do not have one here, so hunt the command instead of the artefact."
     },
     "steps": [
      {
       "think": "Search the attacker's process activity for the handful of commands that create persistence. The question steers you off scheduled tasks, so watch especially for a new service (sc.exe create).",
       "query": "RdpFlarePracticeProcess_CL\n| where TimeGenerated > ago(365d)  // logs were loaded on one day; widen the window so the portal time picker cannot hide them\n| where Timestamp between (datetime(2025-09-16 18:40) .. datetime(2025-09-18 23:59))\n| where ProcessCommandLine has_any (\"sc create\",\"sc.exe\",\"schtasks\",\"reg add\",\"New-Service\",\"net user\")\n| project Timestamp, AccountName, FileName, ProcessCommandLine\n| order by Timestamp asc",
       "run_it": "Run it.",
       "look_for": "37 rows, most from SYSTEM. The attacker's rows sit together at 19:39:45 UTC. Find the sc.exe create line that makes a new service, and read its name and the binPath it will run.",
       "observe": "The new service's binPath is a PowerShell script, and the display name is dressed up to look like a Windows update. Also notice the repeating 'net user guest ...' lines from SYSTEM/wmiprvse every ~10 minutes: that is lab noise, not the attacker. Telling one real event from repeating automation is a core hunting skill.",
       "defender_url": "https://security.microsoft.com/v2/advanced-hunting?query=H4sIAAAAAAACCo2S0UsCQRDGv%2Bf%2BisUnBbOyDDUIQrAXiajeYz1FLc8T78yE%2Fvh%2BO3tGkoQMtzfzzey3M9%2Fuk0Zaqq%2B5vFYa65HVK1GhGWuMM%2FNy7FU9DXSiLzltNAUNe5xeqE7x7vkWhnoYxnA73fJ5TWCp6lLXaoHWwJzOMMfJGdncGHd8AfPURYYMzriG3IjMVjdWP7OakC2sm4gtQDM8B2v2K7ckWhF5%2BJ1NmJZ4mPXdTnd4HoYFtQXRtDxjx5L%2BM31u3Cl8TkPiwiaK%2FVWt78LQWF1VU%2Bd8LZ3y77BeoI5jbaurK7CgUgNzR%2B1tU9dE4S5oh721A53u32YPP8W8KTYw5cY2s7e7DvjWeq8QJ6ZN4Im9VFQv8QbR5x4yNSVyNM1LNOyb2EsYYRF7ANvQ%2B7P191G%2BuJhb2LROaxhCtvIzz9JmeANNrOKv%2BnXQO7IJdWuYCk7yVhMyfern%2BL%2BxY3SJp4cXNCpfytDUOXT73lT4Bp81DLdcAwAA&timeRangeId=month&tid=939e93f3-04f6-479d-82ff-345c231abb4d"
      }
     ],
     "reveal": {
      "type": "input",
      "format": "service name",
      "unordered": false,
      "salt": "rdp-flare|5|",
      "check": [
       "b53e1a1f150c3de205167bb77ebd9f9290223d41f3e25acebc0a3cdfc3da8c52"
      ]
     },
     "mitre": "T1543.003 Windows Service"
    },
    {
     "section": "4 Discovery",
     "flag": "Q1 - Mapping the Host",
     "points": 75,
     "objective": "Right after persistence, the attacker ran a burst of discovery commands. Name the two that are about the HOST itself: basic fingerprinting, not network and not accounts.",
     "where_to_look": {
      "decision": "Process table, the burst of commands just after the persistence step.",
      "why_here": "Discovery is the attacker running built-in commands to learn the box. Those are process executions.",
      "why_not_others": "No new source needed; you are reading the same account's activity in a tight time window."
     },
     "steps": [
      {
       "think": "Don't search for command names: you'd only find the ones you already thought of. The persistence step (the service creation) happened at about 19:39:45 on 16 Sept. Attackers usually look around right after landing a foothold, so pull EVERYTHING the attacker's account ran in the next few minutes and read it in order.",
       "query": "RdpFlarePracticeProcess_CL\n| where TimeGenerated > ago(365d)  // logs were loaded on one day; widen the window so the portal time picker cannot hide them\n| where AccountName =~ \"slflare\"\n| where Timestamp between (datetime(2025-09-16 19:40) .. datetime(2025-09-16 19:41))\n| project Timestamp, FileName, ProcessCommandLine\n| order by Timestamp asc",
       "run_it": "Run it.",
       "look_for": "21 rows inside 16 seconds (19:40:28 to 19:40:44 UTC). Each tool shows up twice: once as the cmd.exe /c wrapper and once as the tool itself. Sort each tool into a bucket: it describes the machine itself (its OS, patches, what's running on it), the network (addresses, connections, domain), or users and sessions. Exactly two land in the machine bucket.",
       "observe": "Sorting recon into buckets like this is how you summarise an attacker's discovery in a report: it shows what they wanted to learn, not just what they typed.",
       "defender_url": "https://security.microsoft.com/v2/advanced-hunting?query=H4sIAAAAAAACCpWSW0vDQBCFz7O%2FYulTCt6qVqiiIIX6UkTE97JNq63mRhMRQfztfjubiGIRZNnJzJmZs3PJnRaqNFEmr42WukV6pWq0Rka7NK3mzDTWVDt6l9OrVqAhx%2Bme6BztmlsY6mFYwu10yfV6hCXRsU41BO2DOR1wHC%2BXeGtj7PgC5omLDCWcUQbfAs%2Bbzi1%2BbTHB21g1EStASzQHa%2FnNV2FtsDz8zjrMWzz0%2BmyvOzQPQ0Fsg7Vq3%2BhY8i3dX5GTEv9CVqMb8iPvhT6QParI9PA14d4f86utupyKnObYjc0kdphY542hMTrRkQ65Q%2B3xHSEHzNchRzrTCViY8z7H%2FTt3QG6%2FrbSyf%2BCJrNRm8rvaXdAJaAba9R%2Bwn3%2FPGD3neNvQ1Da1bN8Im1m0G5iz3%2B0z8VipPgFqMB4MtAIAAA%3D%3D&timeRangeId=month&tid=939e93f3-04f6-479d-82ff-345c231abb4d"
      }
     ],
     "reveal": {
      "type": "input",
      "format": "two commands, comma separated",
      "unordered": true,
      "salt": "rdp-flare|6|",
      "check": [
       "173caaea0505653ea22036473ac5c395a5a4440abcb1a67866a4f7a73da93ec2",
       "7547664421dad94b317cbdc781a84207c26186d7a626764f0cabcb09ccb8a7a4",
       "9250afd42a585933d14f15bafef3e94e625216b840f93b6ede2a337f9181ecb6"
      ]
     },
     "mitre": "T1082 System Information Discovery"
    },
    {
     "section": "5 Collection",
     "flag": "Q1 - Packaged for Theft",
     "points": 75,
     "objective": "Something got zipped up and staged locally, in the attacker's temp directory, with a name made to look routine. Name the archive.",
     "where_to_look": {
      "decision": "Go to the File table (RdpFlarePracticeFile_CL).",
      "why_here": "An archive being created is a file event: a new .zip appearing on disk. The File table shows the artefact directly, with the path and the process that made it.",
      "why_not_others": "You could grep Process for a zip command, but the File table hands you the file itself, which is cleaner."
     },
     "steps": [
      {
       "think": "List archive files created during the incident, then read their paths. Several will be benign (Windows, Edge, the VM agent). The flag gives you two discriminators: it is in a TEMP directory and the name looks routine, so match those.",
       "query": "RdpFlarePracticeFile_CL\n| where TimeGenerated > ago(365d)  // logs were loaded on one day; widen the window so the portal time picker cannot hide them\n| where FileName endswith \".zip\" or FileName endswith \".7z\" or FileName endswith \".rar\"\n| summarize Actions=make_set(ActionType), First=min(Timestamp) by FileName, FolderPath, InitiatingProcessFileName\n| order by First asc",
       "run_it": "Run it.",
       "look_for": "13 rows. An archive in a user Temp path, created by powershell, with an innocuous name. Benign ones sit in Program Files or D:\\CollectGuestLogs and the like.",
       "observe": "You will also see C:\\ProgramData\\backup\\employee-data-*.zip files, but those are the persistence service's later runs in a different path, not this flag. Match the clue: temp directory plus a routine-looking name.",
       "defender_url": "https://security.microsoft.com/v2/advanced-hunting?query=H4sIAAAAAAACCpWSQUvEMBCF39lfEfa0C6IHUQ%2BiIIIiiCyyd4m22LK2KU1FFH%2B8XyatLurBJWRI3sx7mczMnQp1utSzvHqVWmK9HjWoxpZ4anyl7nWhG%2B3oQ06vqkBStNMKf8Ppit0a6uGWqDqdsb2eFDTXgY50CLoAc9pnOXQD3miKk17CPHFZIaCZbfIVeN50YvG1xSTvYNlkrAUNnByqYcPXceu5efSd%2Fa0Z8fTLtb3uOHkUWmIHbtX4xqTS%2FPH7qTq3MLNiaTlEyybxnGba0zu3jpOzPP7PO4a5Pau3Xs7GfKNeiG4Mq9FLvPOxw6myUafmXVuXI3agX5sRK6regS%2B0O2bREzcYL9V8%2FjUF0WrcEJ36%2FADvd9ZZI4AVVselTUxl%2BDVqtb3rzbbMR5rIYLMYWT%2FV8h9TfYqxi9%2Bv5izTDEb4n%2BrMdsLqAgAA&timeRangeId=month&tid=939e93f3-04f6-479d-82ff-345c231abb4d"
      }
     ],
     "reveal": {
      "type": "input",
      "format": "filename",
      "unordered": false,
      "salt": "rdp-flare|7|",
      "check": [
       "66145f6d003704ca987f3ebae4de597b0d6c53b5b970c359401f3f43370d5247"
      ]
     },
     "mitre": "T1560 Archive Collected Data"
    },
    {
     "section": "6 Command and Control",
     "flag": "Q1 - Phoning Home",
     "points": 100,
     "objective": "The payload you found in the Execution section (msupdate.exe) did not run in a vacuum. It called out somewhere. Give that destination.",
     "where_to_look": {
      "decision": "Go to the Network table (RdpFlarePracticeNetwork_CL).",
      "why_here": "A callout is an outbound network connection. The flag ties it to a specific process, so filter the network events by that initiating process rather than reading them all.",
      "why_not_others": "The box talks to many Microsoft endpoints; filtering by the process that made the connection is what keeps you from blaming legitimate traffic."
     },
     "steps": [
      {
       "think": "Filter network events to connections initiated by msupdate.exe (and the attacker's powershell). Whatever external IP that payload contacted is the C2. Summarising by RemoteIP/RemoteUrl keeps it readable.",
       "query": "RdpFlarePracticeNetwork_CL\n| where TimeGenerated > ago(365d)  // logs were loaded on one day; widen the window so the portal time picker cannot hide them\n| where InitiatingProcessFileName in~ (\"msupdate.exe\",\"powershell.exe\")\n| summarize Hits=count(), First=min(Timestamp) by RemoteIP, RemoteUrl, InitiatingProcessFileName\n| order by First asc",
       "run_it": "Run it.",
       "look_for": "9 rows. The external IP whose InitiatingProcessFileName is msupdate.exe. Separate the noise: edr-*.microsoft.com is Defender telemetry, raw.githubusercontent.com is script hosting, *.blob.core.windows.net is storage.",
       "observe": "Only one destination has msupdate.exe as the initiator. Attributing a connection to the exact process that made it is how you pick the C2 out of ordinary traffic.",
       "defender_url": "https://security.microsoft.com/v2/advanced-hunting?query=H4sIAAAAAAACCpWST0sDQQzF39lPMfS0haIH0YvoRagWRKToWUa32KW7O8VZ8Q%2FiZ%2FeX7NaKeClDprMvyctL0rlKrTVVrahnLXTDHfWoThX3QtdYp1cl8JXuda4r7elTAWyJz3KCbolueF1graORrAXcQWdY1BMMhQ51rCPQMVjQASdQOeHNzrjhMywS1zMkOPvbfCWed514fOUx5u1cTY%2B1oIlXgDX98q29i4782tFes%2BHW68qrB14RhpbYjq%2FlUGPD0vzT%2FYzoyvmi3y392ByTTzBzpqC1TzMONS3qi99CI5CsF1SUw9T2sTdspAm29l6sVvaaNWcbMR70GEPDsS1W%2BvAal64q6xQdCX%2FLV0HGBJ8pMsYOb%2BNqip8tZp9RQ2Xb0wPTDpp778n1zehu8ge7g612dPdp9B3YbsphB33NrUb7B2XyvwGYfjrdrgIAAA%3D%3D&timeRangeId=month&tid=939e93f3-04f6-479d-82ff-345c231abb4d"
      }
     ],
     "reveal": {
      "type": "input",
      "format": "IP or domain",
      "unordered": false,
      "salt": "rdp-flare|8|",
      "check": [
       "ce27cea2bf82abf8a6b543e4c9eb5e2767e590510cfb5e7b3c5cd547414e324d"
      ]
     },
     "mitre": "T1071 Application Layer Protocol"
    },
    {
     "section": "7 Exfiltration",
     "flag": "Q1 - The Failed Handoff",
     "points": 100,
     "objective": "After staging the archive, the session tried to send it somewhere external. Give the destination as IP:Port. It does not matter that the attempt failed; they want where the attacker aimed.",
     "where_to_look": {
      "decision": "Network table again, around the collection time, looking for a failed outbound.",
      "why_here": "Exfiltration is an outbound connection carrying the data out. A failed attempt still leaves a ConnectionFailed row.",
      "why_not_others": "Same table as C2, but a different moment (just after the archive was staged) and you care about the port, not just the IP."
     },
     "steps": [
      {
       "think": "Look at the attacker's network connections right after backup_sync.zip was staged, especially ConnectionFailed ones. The format wants IP:Port, so you need the port, and the port field may be empty.",
       "query": "RdpFlarePracticeNetwork_CL\n| where TimeGenerated > ago(365d)  // logs were loaded on one day; widen the window so the portal time picker cannot hide them\n| where RemoteIP == \"185.92.220.87\"\n| project Timestamp, RemoteIP, RemotePort, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine\n| order by Timestamp asc",
       "run_it": "Run it.",
       "look_for": "4 rows, every one a ConnectionFailed, and RemotePort is empty on all of them. Check which process made each attempt and read the command line of the one that sent a file.",
       "observe": "RemotePort may be empty, but a command line that sent the file often spells out the whole URL, port included. When a structured field is blank, the command line usually still carries the fact.",
       "defender_url": "https://security.microsoft.com/v2/advanced-hunting?query=H4sIAAAAAAACCo2SW0vDQBCFz7O%2FYvFJQbxU1IooSEEpFAml72Vtg41tssEERPDH%2B80kBZE8yLKTzTkzZy67c61V60k7RX0oV4aNWqlVgc31wm71qQS%2B1VITzXSgbwWwDZzFBC3wLjk9sytHI1E52kEP7Kg3FI50qWtdgR6DBZ2xApkTbOOKez3DIn6dQkKzs8atYb505%2F6F%2BxjbejUdVoEmTgHV9IurvYuW%2BJ2jXc2GW69bzx44RRQqfFv%2BNn2OvUo50P3c8eQdT5lg0D0r6FAXGtPvqW41wo5Y53zHuoHrdGo0kt6JXHm%2B%2FSQbr7OEPxnI8BfL%2Bs4Mf%2Bxvz%2Ba1YFI1vOFT%2FgtnotuKqWeefeX5Gl5BwWTszqPX8L%2BoCeeSFX3uM%2FfJ%2B%2B6sqnU%2F11dqGerPXkeD2g9y7A%2BnigIAAA%3D%3D&timeRangeId=month&tid=939e93f3-04f6-479d-82ff-345c231abb4d"
      }
     ],
     "reveal": {
      "type": "input",
      "format": "IP:Port",
      "unordered": false,
      "salt": "rdp-flare|9|",
      "check": [
       "3cc9387a9d5473d8ff94622fe3a3e9ba1f262b8330d9e05a71ace4cd22a8d02a"
      ]
     },
     "mitre": "T1041 Exfiltration Over C2 Channel"
    },
    {
     "section": "8 Judgement",
     "flag": "Q1 - Shared Infrastructure",
     "points": 100,
     "objective": "185.92.220.87 shows up twice: once as the payload's C2 (port 80) and once as the exfil target (port 8081). Same IP, two different ports, two different purposes. What does that reuse tell you about how this attacker's infrastructure is set up?",
     "where_to_look": {
      "decision": "No query. This is a reasoning flag.",
      "why_here": "The final flag tests whether you can interpret your findings, not find a new one. You already have both facts (the C2 and the exfil target). The question is what they mean together.",
      "why_not_others": "There is no row that states the conclusion; you synthesise it from what you already proved."
     },
     "steps": [
      {
       "think": "One host doing two jobs on two ports means the attacker is NOT using separate, dedicated servers for C2 and exfil. It is a single multi-purpose box. Reason about the implications: limited resources or a hasty setup, and, for a defender, a single chokepoint, because blocking that one IP kills both channels at once.",
       "query": "(no query, synthesise your findings)",
       "run_it": "Write your reasoning, then reveal a model answer to compare.",
       "look_for": "The implication, not a new data point.",
       "observe": "This is the kind of judgment a report's conclusion rewards: not just what happened, but what it tells you about the actor and how to act on it."
      }
     ],
     "reveal": {
      "type": "input",
      "format": "one or two sentences of reasoning",
      "unordered": false
     },
     "mitre": "T1583 Acquire Infrastructure"
    }
   ]
  }
 }
];
window.HC_VER = "79b515394d";
