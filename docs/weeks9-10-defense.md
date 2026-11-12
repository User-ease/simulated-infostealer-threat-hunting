# Weeks 9 and 10 - 7 to 8 minute group defense

Use the Week 9 report, its saved Elasticsearch responses, and the Week 10 mapping. Aim for **7 minutes 30 seconds**, leaving 30 seconds of the eight-minute limit for a brief question or transition. This outline is preparation; it does not certify that a defense has occurred. Speakers are suggested roles, not invented group members.

| Time | Speaker role | Show | Explain |
| --- | --- | --- | --- |
| 0:00-0:45 | Introduction | README and syllabus requirements summary | Week 9 executes atomic tests and analyzes SIEM results; Week 10 maps APT29 TTPs. |
| 0:45-1:30 | Lab operator | Training window, Security 488/490 and 507 | Contrast the original Linux and Windows tar controls with the separate ClickFix-to-receiver Windows run. Show the cmd.exe parent and the logon task marker. |
| 1:30-2:45 | Lab operator | Windows reads 515–522, receipt and Linux write-error trace | Trace the four files through Compress-Archive and the receiver. Show HTTP 201, the ZIP digest and the rejected request. Use the Linux trace to contrast a failed write. |
| 2:45-3:45 | Detection analyst | Kibana Discover or saved SIEM summary and queries | Show 43 executions, 18 archiver launches, seven profile archive attempts, five successful exits and two failed writes. |
| 3:45-4:30 | Detection analyst | Windows EQL pair and read-only control | Compare records 569 and 571 with list-mode read 581. Explain why an authorized backup also matches. |
| 4:30-6:00 | CTI analyst | APT29 mapping and coverage figure | Explain RDP Bitmap Cache for password export, Shellbags and extension telemetry for cookies, and the local Event 400 / CIM pair. Keep SolarWinds and later StellarParticle reporting separate. |
| 6:00-7:15 | CTI analyst | Evidence-status column and future hunts | Linux and Windows archive behavior was tested. Remote staging and session misuse remain separate investigation questions. |
| 7:15-7:30 | Any speaker | GitHub commits and conclusion | Demonstrate traceability, honest dates and the Windows workflow and nine results. |

The later [complete Windows chain](week8-windows-run.md) supplements the earlier datasets. Use the [updated Russian speaking script](../reports/Защита_недель_9_и_10.docx) for the 7:30 group presentation.

## Suggested spoken explanation

### Introduction

“Our project studies forensic analysis and detection of simulated infostealer-like activity in Windows environments. For Week 9, the syllabus asks us to run selected Atomic Red Team tests and analyze their results in a SIEM. For Week 10, it asks us to analyze APT29 or APT41 and map the reported techniques to MITRE ATT&CK. We selected APT29 because published investigations describe browser credential access, cookie theft and archive creation, which connect directly to our project topic.”

### Explain the laboratory scope

“We ran three pinned Linux Atomic Red Team procedures, then recreated the archive scenario on Windows Server 2022 using built-in tar.exe. On Windows we audited process creation and file access. We used synthetic profile data on both platforms.”

### Walk through one evidence chain

“Here is the exact command and its successful exit status. This raw strace record shows a successful execve system call. The normalized event points back to the trace filename and line number. A failed executable lookup is excluded by the parser, so attempted PATH locations do not inflate the process count. We also checked the archives independently: decompressing the gzip output and reading the expected tar members reproduced the original bytes. Cleanup removed the generated archives while preserving the synthetic input files and evidence.”

The Windows Run dialog opened cmd.exe, which started PowerShell PID 3936. Show Security records 488 and 490. Task registration is record 507 and its on-demand action is record 509. Follow PID 3936 to records 515–522 for the four synthetic files. Compare the 578-byte receipt on /receive with the zero-byte rejection. The published ZIP and the sender have the same SHA-256.

### Explain the SIEM results

“We observed 43 executions across fifteen cases. Eighteen launched tar or gzip. Seven issued a create command and opened a training profile input. Five archivers exited zero. The other two failed to write. We also opened the five completed outputs before cleanup and compared their contents with the fixtures.”

### Explain the controls

“On Linux the same PID opened a source file, hit ENOSPC and exited 2. On Windows, record 569 shows PID 2000 running tar.exe cf. Record 571 shows its read of the exact profile file. The extracted member matched. PID 1680 also read that file but used tf, so the query excluded it. The authorized backup matched because it performed the same operation.”

### Explain the APT29 analysis

“Our mapping uses primary reporting and MITRE's current technique pages. FireEye's initial SolarWinds report describes the compromised update mechanism; its later attribution update connects UNC2452 to APT29. Volexity shows an Exchange mailbox export followed by 7-Zip reading the exported local PST as its input. That local input supports T1005. MITRE maps HTTPS retrieval to T1048.002 and cites Volexity. Volexity shows the archive command and an example URL. To establish a specific download, we would need a web request, response status and bytes served. CrowdStrike reconstructed a password export from the RDP Bitmap Cache. For cookies they combined Shellbags navigation with telemetry identifying the Cookie Editor extension. In our own Windows lab, Event 400 record 28101 and a CIM observation corroborate a PowerShell launch and parent; matching hashes support local staging. We retain the different reporting periods instead of presenting every procedure as one universal attack sequence. The table maps ten selected techniques and links each reported behavior to a source.”

### State what the mapping does and does not prove

“The clearest connection to the new experiment is T1560.001, Archive via Utility. Our Linux tar/gzip and Windows tar.exe runs exercised that behavior on synthetic data. They are not Windows 7-Zip tests and they do not show password-protected archives or exfiltration. Our fake cookies are not authenticated session cookies, so archiving them cannot establish T1539. Similarly, a mock password string does not validate access to browser encryption or DPAPI. The Unix shell test is T1059.004 and is not relabelled as PowerShell or presented as evidence of an APT29 procedure.”

### Close

“Nine Windows controls reproduced the expected SIEM results, including an authorized backup. A production analyst would need backup authorization or other context to investigate intent. Our archive evidence supports T1560.001. The later run verified HTTP receipt on loopback. External egress and remote staging remain open questions.”

## Quick demonstration

1. Open the [revised collection](../evidence/week9/20261111T192612720530Z/collection.json) and [SIEM summary](../evidence/week9/20261111T192612720530Z/siem/summary.json). Show one source trace line next to its normalized event.
2. Open Kibana at `http://127.0.0.1:15609`, after reproducing the run, create or select the data view for its exact index. Use its absolute UTC interval. For the published revision, the case table and full responses are available offline. A relative last-15-minutes filter will eventually hide the saved observations.
3. If Kibana is unavailable, open `siem/queries.json` and `siem/results.json`. These contain actual executed Elasticsearch requests and responses; do not pretend a static chart is a live SIEM screenshot.
4. Open the [Windows EQL response](../evidence/week9-windows/vm-20261111T210834Z/siem/correlated.json) and [native Security XML](../evidence/week9-windows/vm-20261111T210834Z/events.xml). Find record 571 and compare it with 581.
5. Show the Week 10 mapping and the separate GitHub commits.

## Questions to rehearse

- **Why no T1003?** The syllabus gives examples, not a mandatory credential-dumping test. Our selected supported tests cover execution and archiving using synthetic data.
- **Is this malware detection?** No. These are search predicates and controlled behavior observations. Both atomics and controls are benign.
- **Why Linux in a Windows project?** The three upstream Linux procedures supplied the starting point. A separate Windows run now confirms the tar.exe process/file event correlation.
- **Does a cookie file prove T1539?** No. A valid browser session and actual access to its cookie material are different from a fake JSON file.
- **Does the archive prove exfiltration?** No. The first archive experiment had no transfer. In the later Windows run, the receiver logged HTTP 201 and matching bytes and SHA-256. It was bound to loopback only.
- **Why not call every archive event an attack?** Backup and administrative activity use the same utilities; source, ancestry, file access and later network activity are needed for context.
- **Were the commits made in separate weeks?** No. These two increments were prepared on 8 November 2026 and committed separately on their actual date.
- **Was AI used?** Yes. Codex assisted with research, code, execution, validation and writing. Follow the instructor's permission and disclosure rules.

## Краткая памятка для подготовки

Главное: различайте **выполнено**, **сообщается в источнике** и **предлагается проверить**. Выполнены Linux Atomic-тесты, девять Windows-контролей tar и отдельный сквозной прогон с Compress-Archive и HTTP POST на 127.0.0.1. В Elasticsearch покажите пару 4688/4663 для PID 2000 и объясните, почему разрешённый бэкап тоже совпал. Сведения об APT29 взяты из указанных публикаций. Windows-кража credentials/cookies, удалённый staging и передача за пределы машины не проверялись. Перед защитой каждый участник должен уметь объяснить одну цепочку «команда → исходная трасса → событие → запрос → результат» и причину совпадения обычного backup.
