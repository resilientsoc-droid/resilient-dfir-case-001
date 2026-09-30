# CASE001 — Windows Digital Forensics & Incident Response

## Case Information

| Field | Value |
|---|---|
| Case ID | CASE001 |
| Investigation Type | Windows Digital Forensics & Incident Response |
| Investigation Date | 09 September 2026 |
| Host | DESKTOP-U434GBI |
| Operating System | Windows 11 Pro — Build 26200 |
| Primary Evidence Source | Splunk |
| Investigated Account | DESKTOP-U434GBI\leader Resilient |

---

## Executive Summary

The investigation identified a sequence of activity beginning with a local interactive logon, followed by PowerShell execution, system and account discovery activity, and the creation of a Scheduled Task.

The Scheduled Task `CASE001_TestPersistence` was successfully created with an `ONLOGON` trigger.

An attempt was subsequently made to execute the task; however, successful execution of the associated payload could not be confirmed.

The expected payload file:

`C:\Users\Public\CASE001_PERSISTENCE.txt`

was not observed during verification.

The Scheduled Task was subsequently removed as part of the investigation cleanup.

---

## Investigation Scope

The investigation focused on reconstructing security-relevant activity on the Windows endpoint `DESKTOP-U434GBI`.

The following telemetry was examined:

- Windows Security Event Logs
- PowerShell Script Block Logging
- PowerShell Module Logging
- Sysmon process creation events
- Process creation and termination activity
- Account discovery activity
- System information discovery
- Process discovery
- Network connection discovery
- Scheduled Task creation and execution
- Cleanup activity

The investigation primarily used the following Splunk indexes:

- `resilient_windows_security`
- `resilient_windows_powershell`
- `resilient_windows_sysmon`

The primary investigated account was:

`DESKTOP-U434GBI\leader Resilient`

---

## Interactive Logon

At `10:54:39.073`, Windows Security Event ID 4624 recorded a successful logon for `DESKTOP-U434GBI\leader Resilient` with **Logon Type 2**.

Logon Type 2 represents an interactive local logon.

The source address `::1` is the IPv6 loopback address, indicating that the authentication activity originated locally on the investigated host rather than from a remote network source.

Based on the available telemetry, this event represents the beginning of the investigated activity sequence.

---

## PowerShell Execution

Approximately one second after the interactive logon, Windows Security Event ID 4688 recorded the creation of:

`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

The parent process was:

`C:\Windows\explorer.exe`

This establishes that PowerShell was launched from the interactive Windows user session.

The first relevant PowerShell command identified during the investigation was:

Get-LocalUser

The command was recorded by PowerShell Script Block Logging Event ID 4104 at:

`10:54:57.041`

This activity was classified as:

**MITRE ATT&CK T1087.001 — Account Discovery: Local Account**
---

## Discovery Activity

Following PowerShell execution, several discovery commands were identified.

### Account Discovery

Get-LocalUser

Purpose:

Identify local user accounts configured on the Windows endpoint.

MITRE ATT&CK:

T1087.001 — Account Discovery: Local Account

### System Information Discovery

Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, CSName

Purpose:

Collect operating system and host information.

MITRE ATT&CK:

T1082 — System Information Discovery

### Process Discovery

Get-Process | Select-Object -First 20 Name, Id, CPU

Purpose:

Enumerate running processes on the endpoint.

MITRE ATT&CK:

T1057 — Process Discovery

### Network Connection Discovery

Get-NetTCPConnection | Select-Object -First 20 LocalAddress,LocalPort,RemoteAddress,RemotePort,State

Purpose:

Inspect active TCP connections and associated network endpoints.

MITRE ATT&CK:

T1049 — System Network Connections Discovery

The presence of network connections in the output alone does not establish command-and-control activity. The observed connections were therefore not classified as malicious without additional supporting evidence.
---

## Scheduled Task Persistence Analysis

At `11:08:39.473`, PowerShell Script Block Logging recorded the following command:

schtasks /Create /TN "CASE001_TestPersistence" /TR "cmd.exe /c echo CASE001_PERSISTENCE_TEST > C:\Users\Public\CASE001_PERSISTENCE.txt" /SC ONLOGON /F

The command created a Windows Scheduled Task named:

`CASE001_TestPersistence`

The task was configured with an `ONLOGON` trigger, meaning that the task was designed to execute when a user logs on.

### Task Configuration

| Property | Value |
|---|---|
| Task Name | `CASE001_TestPersistence` |
| Trigger | `ONLOGON` |
| Action | `cmd.exe` |
| Arguments | `/c echo CASE001_PERSISTENCE_TEST > C:\Users\Public\CASE001_PERSISTENCE.txt` |
| User | `DESKTOP-U434GBI\leader Resilient` |
| Logon Type | `InteractiveToken` |
| Run Level | `LeastPrivilege` |
| Task File | `C:\Windows\System32\Tasks\CASE001_TestPersistence` |

The configuration represents a logon-triggered persistence mechanism.

---

## Cross-Source Correlation

The Scheduled Task creation was independently observed across multiple telemetry sources.

### PowerShell — Event ID 4104

Recorded the complete `schtasks /Create` command at:

`11:08:39.473`

### Windows Security — Event ID 4688

Recorded the creation of:

`C:\Windows\System32\schtasks.exe`

at:

`11:08:39.556`

### Sysmon — Event ID 1

Recorded the same `schtasks.exe` execution at:

`11:08:39.616`

The Sysmon event identified:

- Process: `schtasks.exe`
- Process ID: `4116`
- Parent Process ID: `5520`
- Parent Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- User: `DESKTOP-U434GBI\leader Resilient`

The close temporal relationship between the three telemetry sources provides strong cross-source correlation for the Scheduled Task creation.
---

## Scheduled Task Execution Analysis

At `11:20:31.766`, PowerShell recorded an execution attempt using:

Start-ScheduledTask -TaskName "CASE001_TestPersistence"

The task was subsequently inspected using:

Get-ScheduledTaskInfo -TaskName "CASE001_TestPersistence"

The resulting information included:

LastRunTime        : 11/30/1999 12:00:00 AM
LastTaskResult     : 267011
NumberOfMissedRuns : 0

The expected payload output was then checked using:

Test-Path "C:\Users\Public\CASE001_PERSISTENCE.txt"

The result was:

False

> **Analyst note:** `LastTaskResult 267011` is `0x00041303` (`SCHED_S_TASK_HAS_NOT_YET_RUN`), and `LastRunTime 11/30/1999` is the placeholder Windows shows for a task with no recorded run. Read together with `Test-Path = False`, Task Scheduler had no completed run on record at query time. This is why the outcome is reported as *not confirmed* rather than as a confirmed failure.

The evidence establishes that execution was attempted, but successful execution of the scheduled task payload was not confirmed.

The expected payload file was not observed.

### Execution Determination

| Activity | Determination |
|---|---|
| Scheduled Task Creation | CONFIRMED |
| Execution Attempt | CONFIRMED |
| Successful Task Execution | NOT CONFIRMED |
| Payload File Creation | NOT OBSERVED |

---

## Cleanup Activity

At `11:22:28.163`, PowerShell executed:

Unregister-ScheduledTask -TaskName "CASE001_TestPersistence" -Confirm:$false

A subsequent verification command:

Get-ScheduledTask -TaskName "CASE001_TestPersistence" -ErrorAction SilentlyContinue

returned a non-terminating error indicating that no scheduled task with the specified name was found.

This confirms that the test Scheduled Task was removed during cleanup.

---

## MITRE ATT&CK Mapping

| Technique ID | Technique | Observed Activity | Evidence |
|---|---|---|---|
| T1087.001 | Account Discovery: Local Account | `Get-LocalUser` | PowerShell 4104 |
| T1082 | System Information Discovery | `Get-CimInstance Win32_OperatingSystem` | PowerShell 4104 |
| T1057 | Process Discovery | `Get-Process` | PowerShell 4104 |
| T1049 | System Network Connections Discovery | `Get-NetTCPConnection` | PowerShell 4104 |
| T1053.005 | Scheduled Task/Job: Scheduled Task | `schtasks /Create` with `ONLOGON` trigger | PowerShell 4104, Security 4688, Sysmon 1 |

---

## Final Analyst Assessment

The available telemetry establishes a clear sequence of activity on the investigated Windows endpoint:

Interactive Logon
        |
        v
PowerShell Execution
        |
        v
Account Discovery
        |
        v
System Information Discovery
        |
        v
Process Discovery
        |
        v
Network Connection Discovery
        |
        v
Scheduled Task Creation
        |
        v
Execution Attempt
        |
        v
Execution Not Confirmed
        |
        v
Cleanup

The evidence confirms that the account `DESKTOP-U434GBI\leader Resilient` performed local interactive activity followed by PowerShell-based discovery commands.

A Scheduled Task named `CASE001_TestPersistence` was subsequently created using `schtasks.exe`.

The task was configured with an `ONLOGON` trigger and an associated command designed to create:

`C:\Users\Public\CASE001_PERSISTENCE.txt`

The creation of the Scheduled Task is strongly supported by correlated PowerShell, Windows Security, and Sysmon telemetry.

An execution attempt was subsequently performed using `Start-ScheduledTask`. However, the available evidence does not establish successful execution of the task payload.

The expected output file was not observed, and the recorded task state provided a failure indicator.

The Scheduled Task was then removed successfully during cleanup.

Therefore, the investigation supports the following conclusions:

- Scheduled Task creation: **CONFIRMED**
- Persistence mechanism configuration: **CONFIRMED**
- Execution attempt: **CONFIRMED**
- Successful payload execution: **NOT CONFIRMED**
- Payload file creation: **NOT OBSERVED**
- External attacker involvement: **NOT ESTABLISHED**
- Cleanup: **CONFIRMED**

No conclusion of successful compromise or malicious external activity should be made solely from the observed telemetry.

---

## Conclusion

The investigation reconstructed the relevant activity on `DESKTOP-U434GBI` and identified a sequence from local user activity through discovery and Scheduled Task creation.

The most security-relevant finding was the creation of `CASE001_TestPersistence`, which was configured as a logon-triggered Scheduled Task.

Although execution was attempted, successful execution of the associated payload could not be established from the available evidence.

The case should therefore be classified as:

**Confirmed Scheduled Task Creation with Unconfirmed Payload Execution**

The investigation was completed after verification and cleanup of the test persistence mechanism.
