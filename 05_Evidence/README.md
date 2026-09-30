# CASE001 — Evidence

## Evidence Scope

This directory documents the evidence used during the CASE001 Windows DFIR investigation.

The investigation was performed against telemetry collected from:

- Windows Security Event Logs
- PowerShell Operational Logs
- Sysmon telemetry
- Splunk Search & Reporting

## Investigated Host

- Hostname: DESKTOP-U434GBI
- OS: Windows 11 Pro
- Build: 26200
- Investigated User: DESKTOP-U434GBI\leader Resilient

## Key Evidence

The investigation confirmed:

1. Interactive local logon.
2. PowerShell execution.
3. Account, system, process, and network discovery.
4. Creation of `CASE001_TestPersistence`.
5. Cross-source correlation of `schtasks.exe`.
6. Attempted execution of the scheduled task.
7. Failure to establish successful payload execution.
8. Removal of the scheduled task.

## Scheduled Task Evidence

Task:

`CASE001_TestPersistence`

Trigger:

`ONLOGON`

Action:

```text
cmd.exe /c echo CASE001_PERSISTENCE_TEST > C:\Users\Public\CASE001_PERSISTENCE.txt
```

## Evidence Map

| # | Finding | Source | Query | Screenshot |
|---|---|---|---|---|
| 1 | Interactive logon (Type 2) | Security 4624 | `01_Interactive_Logon.spl` | `01_interactive_logon_4624.png` |
| 2 | PowerShell launched from explorer.exe | Security 4688 | `02_PowerShell_Execution.spl` | `02_powershell_process_4688.png` |
| 3 | Discovery commands | PowerShell 4104 | `03_Discovery_Activity.spl` | `03_discovery_commands_4104.png` |
| 4 | Scheduled Task created | PowerShell 4104 | `04_Scheduled_Task_Creation.spl` | `04_schtasks_create_4104.png` |
| 5 | schtasks.exe cross-source | Security 4688 + Sysmon 1 | (see report) | `05_schtasks_crosssource.png` |
| 6 | Execution attempt | PowerShell 4104 | `05_Task_Execution.spl` | `06_task_execution_attempt.png` |
| 7 | Task result 267011 | PowerShell 4103 | (see report) | `07_task_info_result.png` |
| 8 | Payload file not found | PowerShell 4103 | (see report) | `08_payload_test_path_false.png` |
| 9 | Task removed | PowerShell 4104 | `06_Cleanup.spl` | `09_cleanup_unregister.png` |
| 10 | Task no longer found | PowerShell 4103 | (see report) | `10_task_not_found.png` |

## Integrity

SHA-256 hashes of every file are in `../06_Hashes/SHA256SUMS.txt`. Verify with:

```bash
sha256sum -c 06_Hashes/SHA256SUMS.txt
```

