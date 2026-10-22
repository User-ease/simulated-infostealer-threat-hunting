# Assignment 4: Weeks 6-7

Status: practical implementation and report completed on 22 October 2026 and included alongside Weeks 1-5 in the repository. See [the final report](week_6-7.md). The design below records the original plan; the final implementation uses the disclosed inventory-data adaptation.

## Requirements

Source: syllabus 2026-2027, section 3.3, PDF page 7. The supplied assignment grouping is Weeks 6-7.

| Week | Required practice | Planned project increment |
| --- | --- | --- |
| 6 | Study one ATT&CK technique; simulate an attack and map the results to tactics and techniques. | Harmless PowerShell execution, T1059.001 under Execution, with new evidence from the current Windows PC. |
| 7 | Select an analytic from MITRE CAR, implement it in a SIEM, and map it to ATT&CK. | Adapt CAR-2014-04-003 to Elasticsearch/Kibana after establishing a suitable process telemetry source. |

## Design and boundaries

The project continues the Windows infostealer research and Week 5 PowerShell hunt. The first pilot only prints unique training markers, including one encoded invocation. It validates execution and evidence collection; it does not emulate credential theft or a complete infection chain. Encoding alone does not establish an additional malicious technique or intent.

Current ATT&CK mapping: T1059.001 PowerShell, parent T1059 Command and Scripting Interpreter, tactic Execution. The CAR page retains a Defense Evasion association; do not automatically carry that historical mapping into a claim about this benign experiment.

CAR-2014-04-003 examines PowerShell process creation with a parent other than explorer.exe. A hit is a review candidate: legitimate automation can match. The broad parent condition is not evidence of a malicious process.

Week 5 Event 400 evidence lacks parent process identity. The new pilot records native Event 400 XML and live CIM process inventory separately. CIM inventory is not a process-creation event stream and will not be presented as equivalent to Sysmon Event 1 or Security Event 4688.

## Initial machine check

- Windows 11 Pro, approximately 15.4 GiB usable RAM; firmware virtualization enabled.
- Docker CLI and Docker Desktop files are present, but the Linux engine was unavailable during the initial check.
- Approximately 1 GiB free RAM during that check. The existing Compose services have combined memory limits of approximately 3.5 GiB, in addition to Windows and WSL overhead.
- Windows PowerShell log is enabled and readable.
- Sysmon Operational log was not found. The Security log requires elevated rights in the current session.
- CIM process inventory, parent IDs, and command lines are readable.
- The existing repository contains local changes. Archived Week 5 results are historical evidence from another PC; new experiments must use separate directories.

## Pilot

Completed pilot run: `20261022T111144251Z`. Both benign cases exited with code 0 and printed their exact unique marker. Matching native Event 400 record IDs were 28045 (plain) and 28053 (encoded); both CIM snapshots identified `pwsh.exe` as the parent. Evidence is stored under `evidence/week6-pilot/20261022T111144251Z/`. This confirms the pilot only, not full Week 6 assessment or Week 7 SIEM completion.

Run `scripts/collect_week6_pilot.ps1` with PowerShell. Each execution writes a separate directory under `evidence/week6-pilot/` containing native Event 400 XML, output, a manifest, and hashes. The script requires successful exit codes, exact marker output, and matching native events. Inspect the actual manifest before reporting success.

## Completion record

1. Created separate Docker project `threat-hunting-assignment4`; Elasticsearch and Kibana are healthy on loopback ports 19200 and 15601.
2. Process-creation sensor setup was replaced with a disclosed CAR adaptation to controlled live CIM observations. Sysmon process-creation coverage remains untested and is not claimed.
3. Completed authoritative collection `20261022T111712644Z`: two benign PowerShell cases and one cmd negative control, with independent case labels and native XML for PowerShell.
4. Executed the CAR predicate in Elasticsearch: 3 observations, 2 PowerShell records, 2 candidates. All 6 isolated synthetic boundary checks passed.
5. Preserved API transcripts, hashes and Kibana screenshots. The main report discusses legitimate automation matches and collection blind spots.
6. Prepared the report and 7:30 defense notes with AI assistance disclosure. Oral defense and instructor evaluation remain submission steps.

## Primary references

- https://attack.mitre.org/techniques/T1059/001/
- https://car.mitre.org/analytics/CAR-2014-04-003/
