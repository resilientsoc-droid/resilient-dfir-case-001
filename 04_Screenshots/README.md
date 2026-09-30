# Screenshots

Drop the Splunk screenshots here using **exactly** these file names so the main README renders them.

| File | What it should show |
|---|---|
| `01_interactive_logon_4624.png` | Result of `01_Interactive_Logon.spl` (Logon_Type=2, `::1`) |
| `02_powershell_process_4688.png` | Result of `02_PowerShell_Execution.spl` (parent `explorer.exe`) |
| `03_discovery_commands_4104.png` | Result of `03_Discovery_Activity.spl` (all 4 commands) |
| `04_schtasks_create_4104.png` | Result of `04_Scheduled_Task_Creation.spl` |
| `05_schtasks_crosssource.png` | Security 4688 and Sysmon 1 for `schtasks.exe` side by side |
| `06_task_execution_attempt.png` | Result of `05_Task_Execution.spl` |
| `07_task_info_result.png` | `Get-ScheduledTaskInfo` output (LastTaskResult 267011) |
| `08_payload_test_path_false.png` | `Test-Path` returning False |
| `09_cleanup_unregister.png` | Result of `06_Cleanup.spl` |
| `10_task_not_found.png` | Task-not-found error after cleanup |

Before publishing, check each image for browser-bar URLs, internal IPs, tokens and anything else you would not want public.
