<div align="center">

# CASE001 — Windows DFIR Investigation

**Scheduled Task Persistence Reconstruction using Splunk, Sysmon & PowerShell Logging**

![Type](https://img.shields.io/badge/Type-Windows%20DFIR-1f6feb?style=for-the-badge)
![Tool](https://img.shields.io/badge/SIEM-Splunk-000000?style=for-the-badge&logo=splunk)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-5%20Techniques-da3633?style=for-the-badge)
![Verdict](https://img.shields.io/badge/Verdict-Execution%20Not%20Confirmed-d29922?style=for-the-badge)

</div>

---

## Overview

This case reconstructs a full activity chain on a Windows 11 endpoint using three telemetry sources correlated in Splunk: **Windows Security**, **PowerShell Script Block / Module logging**, and **Sysmon**.

The activity starts with a local interactive logon, moves through PowerShell-based discovery, and ends with the creation, execution attempt and removal of a logon-triggered Scheduled Task. The investigation also shows how to avoid over-claiming: the task was created, but payload execution could **not** be confirmed.

| Field | Value |
|---|---|
| Case ID | CASE001 |
| Date | 09 September 2026 |
| Host | `DESKTOP-U434GBI` (Windows 11 Pro, Build 26200) |
| Account | `DESKTOP-U434GBI\leader Resilient` |
| Evidence source | Splunk (`resilient_windows_security`, `resilient_windows_powershell`, `resilient_windows_sysmon`) |
| Environment | Home lab, controlled test activity |

## Key Findings

| Finding | Status |
|---|---|
| Interactive local logon (Type 2, source `::1`) | ✅ CONFIRMED |
| PowerShell launched from `explorer.exe` | ✅ CONFIRMED |
| Account / system / process / network discovery | ✅ CONFIRMED |
| Scheduled Task `CASE001_TestPersistence` created (`ONLOGON`) | ✅ CONFIRMED |
| Task creation correlated across 3 sources | ✅ CONFIRMED |
| Execution attempt (`Start-ScheduledTask`) | ✅ CONFIRMED |
| Successful payload execution | ❌ NOT CONFIRMED |
| Payload file `C:\Users\Public\CASE001_PERSISTENCE.txt` | ❌ NOT OBSERVED |
| External attacker involvement | ❌ NOT ESTABLISHED |
| Cleanup (task removed) | ✅ CONFIRMED |

**Classification:** *Confirmed Scheduled Task Creation with Unconfirmed Payload Execution*

---

## Attack Chain

<p align="center">
  <img src="assets/attack_flow.svg" alt="CASE001 attack chain" width="100%">
</p>

## Timeline (2026-09-09)

<p align="center">
  <img src="assets/timeline.svg" alt="CASE001 timeline" width="100%">
</p>

Full timeline with assessments: [`02_Timeline/CASE001_Timeline.csv`](02_Timeline/CASE001_Timeline.csv)

---

##  MITRE ATT&CK Mapping

| Technique | Name | Observed activity | Evidence |
|---|---|---|---|
| T1087.001 | Account Discovery: Local Account | `Get-LocalUser` | PowerShell 4104 |
| T1082 | System Information Discovery | `Get-CimInstance Win32_OperatingSystem` | PowerShell 4104 |
| T1057 | Process Discovery | `Get-Process` | PowerShell 4104 |
| T1049 | System Network Connections Discovery | `Get-NetTCPConnection` | PowerShell 4104 |
| T1053.005 | Scheduled Task/Job: Scheduled Task | `schtasks /Create ... /SC ONLOGON` | PowerShell 4104, Security 4688, Sysmon 1 |

---

##  Evidence Walkthrough

### 1. Interactive logon: Security 4624
Logon Type 2 from `::1` (IPv6 loopback) shows the session started locally, not from a remote source.

![Interactive logon](04_Screenshots/01_interactive_logon_4624.png)

### 2. PowerShell process creation: Security 4688
PowerShell was spawned by `explorer.exe`, meaning it was launched from the interactive desktop session.

![PowerShell process creation](04_Screenshots/02_powershell_process_4688.png)

### 3. Discovery commands: PowerShell 4104
Four discovery commands recorded by Script Block Logging.

![Discovery commands](04_Screenshots/03_discovery_commands_4104.png)

### 4. Scheduled Task creation: PowerShell 4104
The full `schtasks /Create` command line, including the `ONLOGON` trigger.

```text
schtasks /Create /TN "CASE001_TestPersistence" /TR "cmd.exe /c echo CASE001_PERSISTENCE_TEST > C:\Users\Public\CASE001_PERSISTENCE.txt" /SC ONLOGON /F
```

![Scheduled task creation](04_Screenshots/04_schtasks_create_4104.png)

### 5. Cross-source correlation: Security 4688 + Sysmon 1
The same `schtasks.exe` execution seen by two independent sources within about 140 ms of the PowerShell event.

| Time | Source | Event |
|---|---|---|
| 11:08:39.473 | PowerShell | 4104, `schtasks /Create` |
| 11:08:39.556 | Security | 4688, `schtasks.exe` |
| 11:08:39.616 | Sysmon | 1, `schtasks.exe` (parent `powershell.exe`, PID 5520) |

![Cross-source correlation](04_Screenshots/05_schtasks_crosssource.png)

### 6. Execution attempt: PowerShell 4104
`Start-ScheduledTask -TaskName "CASE001_TestPersistence"`

![Execution attempt](04_Screenshots/06_task_execution_attempt.png)

### 7. Task result: `Get-ScheduledTaskInfo`
`LastTaskResult 267011` equals `0x00041303` (`SCHED_S_TASK_HAS_NOT_YET_RUN`), and `LastRunTime 11/30/1999` is the placeholder for "no recorded run".

![Task info result](04_Screenshots/07_task_info_result.png)

### 8. Payload verification: `Test-Path`
The expected output file does not exist.

![Payload not found](04_Screenshots/08_payload_test_path_false.png)

### 9. Cleanup: `Unregister-ScheduledTask`
![Cleanup](04_Screenshots/09_cleanup_unregister.png)

### 10. Cleanup verification
![Task not found](04_Screenshots/10_task_not_found.png)

---

## 🔎 Splunk Queries

| # | Purpose | File |
|---|---|---|
| 01 | Interactive logon (4624, Type 2) | [`01_Interactive_Logon.spl`](03_Splunk_Queries/01_Interactive_Logon.spl) |
| 02 | PowerShell process creation (4688) | [`02_PowerShell_Execution.spl`](03_Splunk_Queries/02_PowerShell_Execution.spl) |
| 03 | Discovery commands (4104) | [`03_Discovery_Activity.spl`](03_Splunk_Queries/03_Discovery_Activity.spl) |
| 04 | Scheduled Task creation | [`04_Scheduled_Task_Creation.spl`](03_Splunk_Queries/04_Scheduled_Task_Creation.spl) |
| 05 | Task execution attempt | [`05_Task_Execution.spl`](03_Splunk_Queries/05_Task_Execution.spl) |
| 06 | Cleanup | [`06_Cleanup.spl`](03_Splunk_Queries/06_Cleanup.spl) |

Example, task creation:

```spl
index=resilient_windows_powershell EventCode=4104 "schtasks /Create" "CASE001_TestPersistence"
| table _time ScriptBlockText
| sort _time
```

---

## 📁 Repository Structure

```text
.
├── README.md
├── assets/                 # attack flow + timeline graphics
├── 01_Report/              # full DFIR report
├── 02_Timeline/            # timeline CSV
├── 03_Splunk_Queries/      # SPL queries used
├── 04_Screenshots/         # Splunk screenshots
├── 05_Evidence/            # evidence scope and map
└── 06_Hashes/              # SHA-256 integrity list
```

## Integrity

```bash
sha256sum -c 06_Hashes/SHA256SUMS.txt
```

## Skills Demonstrated

`Windows DFIR` · `Splunk SPL` · `Sysmon` · `PowerShell Logging (4103/4104)` · `Windows Security Events (4624/4688)` · `Cross-source correlation` · `MITRE ATT&CK mapping` · `Evidence-based reporting`

## Full Report

[`01_Report/CASE001_Final_DFIR_Report.md`](01_Report/CASE001_Final_DFIR_Report.md)

---

<div align="center">
<sub>Part of the <b>Resilient SOC</b> case file series · Lab activity only, no real-world victim data</sub>
</div>
