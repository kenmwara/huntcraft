# KQL cookbook: the queries to know by heart

KQL (Kusto Query Language) is how you ask the logs a question. A query is a table name, then a pipe `|`, then
a chain of operators that filter and shape the rows. Read it left to right: "take this table, keep these rows,
show these columns."

The queries below are the ones that recur in almost every hunt. Learn the shapes, not the specific values.

## Two clocks: Timestamp and TimeGenerated {#two-clocks}
Every row can carry two times, and picking the wrong one is the most common way a beginner gets an empty result.

| Column | What it is | Use it for |
|---|---|---|
| `Timestamp` | when the event happened on the host | hunting: filters, sorting, timelines |
| `TimeGenerated` | when the log reached the workspace | almost never in a lab |

On a live tenant the two are seconds apart, so either works. In a Range lab they are not: the logs were recorded
months earlier and loaded into the workspace in one go, so `TimeGenerated` is the same load moment on every row
and only `Timestamp` holds the real attack time. The rule for the Range: **filter and sort on `Timestamp`**. The
one place `TimeGenerated` still appears is a single widening line (`| where TimeGenerated > ago(365d)`) that stops
the portal's time picker from hiding the loaded rows. Some tables (the Windows `SecurityEvent` log) only have
`TimeGenerated`; there it is the event time.

All times are **UTC**, inside queries and in this manual. Set Defender to UTC so what you read matches
(Settings > Microsoft Defender portal > Time zone > UTC).

## The operators you use constantly
| Operator | Does | Example |
|---|---|---|
| `where` | keep rows that match | `where AccountName == "r.whitfield"` |
| `project` | choose columns to show | `project Timestamp, FileName, ProcessCommandLine` |
| `summarize` | aggregate / count | `summarize count() by DeviceName` |
| `order by` | sort | `order by Timestamp asc` |
| `take` / `limit` | cap rows while exploring | `take 20` |
| `extend` | add a computed column | `extend Hour = bin(Timestamp, 1h)` |
| `join` | enrich one table with another | process `join` network on PID |
| `distinct` | unique values | `distinct RemoteIP` |

String tests: `==` exact, `has` whole-word (fast, preferred), `contains` substring, `startswith`, `=~`
case-insensitive, `in (...)` list. Use `has` over `contains` unless you need a partial token.

## Orientation: always run these first {#orientation}
```kql
// What tables have data, and how much?
union withsource=T * | summarize Rows=count() by T | order by Rows desc

// The incident window for a table
DeviceProcessEvents | summarize FirstEvent=min(Timestamp), LastEvent=max(Timestamp), LoadedAt=max(TimeGenerated)

// What columns does a table have?
DeviceProcessEvents | getschema

// Which hosts and accounts are active?
DeviceProcessEvents | summarize count() by DeviceName
DeviceLogonEvents   | summarize count() by AccountName
```
> In the Cyber Range the tables are often custom logs named `*_CL` (for example `RdpFlarePracticeLogon_CL`).
> The columns mirror the Microsoft Defender schema below. In Defender, check the selected workspace (top right)
> is the hunt's own. See [the Range's custom tables](log-tables.html#range-cl-tables).

## Execution: what ran, and who launched it {#execution}
```kql
// Suspicious PowerShell: hidden, encoded, or download cradles
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc","-EncodedCommand","Hidden","Bypass","IEX","Invoke-WebRequest","DownloadString")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine

// Parent to child chain (what spawned this?). explorer then powershell = a user clicked something.
DeviceProcessEvents
| where DeviceName == "<host>"
| project Timestamp, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp asc

// LOLBins: living-off-the-land binaries attackers abuse
DeviceProcessEvents
| where FileName in~ ("certutil.exe","bitsadmin.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe")
```
Windows Security-log equivalent: EventID `4688` (process creation, `NewProcessName` + `CommandLine`).

## Initial access: the phishing click {#initial-access}
```kql
// Files written to Downloads/Temp then executed (lure payloads)
DeviceFileEvents
| where FolderPath has_any (@"\Downloads", @"\Temp")
| where FileName endswith ".lnk" or FileName endswith ".zip" or FileName endswith ".exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FolderPath, FileName
```
Look for `explorer.exe` launching `powershell.exe` and a `smartscreen.exe` nearby (a Mark-of-the-Web prompt = a
downloaded file was opened).

## Network: beacons and C2 {#network}
```kql
// Outbound connections by a suspicious process
DeviceNetworkEvents
| where InitiatingProcessFileName has_any ("powershell","rundll32","<payload>.exe")
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName

// Rare destinations: an IP only one host talked to (possible C2)
DeviceNetworkEvents
| summarize Hosts=dcount(DeviceName), Hits=count() by RemoteIP
| where Hosts == 1 | order by Hits desc
```
Sysmon equivalent: EventID `3` (network connect).

## Authentication and lateral movement {#authentication}
```kql
// Logons by type (3=network, 10=RDP, 2=interactive): find the pivot
// SecurityEvent only has TimeGenerated, and there it is the event time
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account, LogonTypeName, IpAddress, Computer
```
Key IDs: `4624` success, `4625` failure (brute force = many 4625 then one 4624), `4672` admin logon,
`4768/4769` Kerberos tickets, `4776` NTLM.

## Persistence {#persistence}
```kql
// New accounts and group changes (the classic AD escalation tell)
SecurityEvent | where EventID in (4720,4722,4728,4732,4756)
| project TimeGenerated, EventID, TargetAccount, SubjectAccount

// New services (7045) and scheduled tasks (4698) = persistence
SecurityEvent | where EventID in (7045, 4698)
```
Registry run-keys: `DeviceRegistryEvents | where RegistryKey has "CurrentVersion\\Run"`.

## Credential access and collection {#collection}
```kql
// Reads of a sensitive share/file (needs object-access auditing / a SACL): 4663
SecurityEvent
| where EventID == 4663 and ObjectName has "MemberRecords"
| project TimeGenerated, SubjectAccount, ObjectName, AccessMask
```

## The patterns that make you fast
```kql
// let = name a value or a sub-result and reuse it
let window = ago(7d);
let host = "hg-ws01";
DeviceProcessEvents | where Timestamp > window and DeviceName == host

// bin() = bucket time for a timeline
DeviceProcessEvents | summarize count() by bin(Timestamp, 1h)

// make_set / make_list = collapse many rows into one per key
DeviceNetworkEvents | summarize RemoteIPs = make_set(RemoteIP) by DeviceName

// join = tie a process to its network traffic by PID
DeviceProcessEvents | where FileName == "<payload>.exe"
| join kind=inner (DeviceNetworkEvents) on $left.ProcessId == $right.InitiatingProcessId

// anti-join / "rare" = things that appear now but not in the baseline
```

**Rule of thumb:** filter by **time** and **host** first (cheap, shrinks the data), then by behaviour, then
`project` down to the columns you'll read. A query you can't read in one glance is too wide.
