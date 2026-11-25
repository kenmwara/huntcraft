# Log-table reference: what each table holds and what it reveals

A hunt is only as good as your map of the telemetry. This is what the common tables are, the columns that
carry the answers, and the kind of flag each one solves. When you [orient](method.html#the-loop), you are finding out
which of these are present.

## Microsoft Defender for Endpoint: the `Device*` tables
These are the richest source. Each row is one event on one host, with the **acting process** and its
**initiating (parent) process** both described, which is why they answer "what spawned this?" so well.

| Table | One row = | Key columns | Flags it answers |
|---|---|---|---|
| `DeviceProcessEvents` | a process started | `FileName`, `ProcessCommandLine`, `InitiatingProcessFileName`, `AccountName`, `ProcessId` | execution, LOLBins, the click chain, who ran what |
| `DeviceNetworkEvents` | a network connection | `RemoteIP`, `RemotePort`, `RemoteUrl`, `InitiatingProcessFileName` | C2, beacons, downloads, exfil destinations |
| `DeviceFileEvents` | a file created/modified | `FileName`, `FolderPath`, `ActionType`, `InitiatingProcessAccountName` | dropped payloads, staged archives, lure files |
| `DeviceLogonEvents` | a logon | `AccountName`, `LogonType`, `RemoteIP`, `DeviceName` | lateral movement, which account from where |
| `DeviceRegistryEvents` | a registry change | `RegistryKey`, `RegistryValueName`, `RegistryValueData` | run-key persistence, config tampering |
| `DeviceEvents` | mixed security events | `ActionType` | SmartScreen, AMSI, defender actions, misc |

Common key columns on all of them: `Timestamp` (the event time; see [two clocks](kql-cookbook.html#two-clocks)), `DeviceName`, and the full `InitiatingProcess*` family
(`InitiatingProcessId`, `InitiatingProcessParentFileName`, `InitiatingProcessAccountName`) which is how you
walk a process tree.

## Windows Security log: `SecurityEvent`
The raw Windows audit log. Keyed by **EventID**. Noisier than Defender but it carries auth and account events
Defender doesn't always surface. Memorise these IDs:

| EventID | Meaning | Use |
|---|---|---|
| 4624 / 4625 | logon success / failure | brute force (many 4625 → one 4624), lateral movement by `LogonType` |
| 4672 | special privileges assigned | an admin just logged on |
| 4688 | process created | execution, with `CommandLine` if command-line auditing is on |
| 4720 | user account created | a backdoor account (persistence) |
| 4722 / 4725 | account enabled / disabled | re-enabling a stale account |
| 4724 | password reset by another account | helpdesk abuse, forced resets |
| 4728 / 4732 / 4756 | member added to global / local / universal group | privilege escalation |
| 4663 | object access (needs a SACL) | reads of sensitive files/shares (exfil) |
| 4698 | scheduled task created | persistence |
| 4768 / 4769 / 4776 | Kerberos TGT / service ticket / NTLM | auth, kerberoasting, pass-the-hash |
| 7045 | new service installed | persistence, lateral tooling |

`LogonType` cheat: 2 interactive (at the keyboard), 3 network (share/SMB), 10 RemoteInteractive (RDP),
5 service, 4 batch.

## Sysmon: `Sysmon*` / Event tables
When Sysmon is deployed you get deep host detail. Key event IDs: `1` process create (with hashes + parent),
`3` network connect, `7` image/DLL load, `8` remote thread (injection), `11` file create, `13` registry set,
`22` DNS query. Sysmon's `1` and Defender's `DeviceProcessEvents` overlap; use whichever the hunt provides.

## Identity and cloud: Sentinel tables
`SigninLogs` (interactive Entra sign-ins), `AADNonInteractiveUserSignInLogs`, `AuditLogs` (directory changes),
`SecurityAlert` / `SecurityIncident` (what the SOC product already flagged). Useful on cloud and hybrid hunts.

## The Cyber Range's custom tables (`*_CL`) {#range-cl-tables}
Range hunts ship telemetry as **custom logs** with a `_CL` suffix. The names change per scenario but the
**columns mirror the Defender / Security schema above**, so every query in the cookbook works by swapping the
table name.

The RDP-Flare practice hunt (workspace LAW-HuntPractice) has four, all from one host:

| Table | Defender equivalent | One row = | Rows |
|---|---|---|---|
| `RdpFlarePracticeLogon_CL` | `DeviceLogonEvents` | a sign-in attempt (`ActionType`, `LogonType`, `AccountName`, `RemoteIP`) | 260 |
| `RdpFlarePracticeProcess_CL` | `DeviceProcessEvents` | a process start (`FileName`, `ProcessCommandLine`, `InitiatingProcessFileName`) | 1,799 |
| `RdpFlarePracticeNetwork_CL` | `DeviceNetworkEvents` | a connection (`RemoteIP`, `RemotePort`, `ActionType`) | 1,377 |
| `RdpFlarePracticeFile_CL` | `DeviceFileEvents` | a file event (`FileName`, `FolderPath`, `ActionType`) | 4,768 |

Three gotchas:
- **Two clocks.** `Timestamp` is the real event time (16 to 18 Sep 2025 for RDP-Flare); `TimeGenerated` is the
  day the lab loaded the logs (29 Oct 2026). Hunt on `Timestamp`. See [two clocks](kql-cookbook.html#two-clocks).
- **Widen the window.** Defender's time picker defaults to the last 7 days and filters `TimeGenerated`, so it
  hides every loaded row. Put `| where TimeGenerated > ago(365d)` as the second line and the picker switches to
  "Set in query".
- **The right workspace.** In Defender, check the selected workspace (top right) is the hunt's own, or the `_CL`
  tables won't resolve.

## How to decide which table a flag needs
| The flag asks about… | Go to |
|---|---|
| a command, a script, "what ran" | `DeviceProcessEvents` / 4688 / Sysmon 1 |
| an IP, a domain, a download, exfil | `DeviceNetworkEvents` / Sysmon 3 |
| a dropped or staged file | `DeviceFileEvents` / Sysmon 11 |
| who logged in, from where, lateral movement | `DeviceLogonEvents` / 4624 |
| a new account, group change, reset | `SecurityEvent` 4720 / 4728 / 4724 |
| persistence (service, task, run-key) | 7045 / 4698 / `DeviceRegistryEvents` |
| a read of sensitive data | `SecurityEvent` 4663 (needs a SACL) |
