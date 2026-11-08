# Weeks 9 and 10 - 7 to 8 minute group defense

Use the Week 9 report, its saved Elasticsearch responses, and the Week 10 mapping. Aim for **7 minutes 30 seconds**, leaving 30 seconds of the eight-minute limit for a brief question or transition. This outline is preparation; it does not certify that a defense has occurred. Speakers are suggested roles, not invented group members.

| Time | Speaker role | Show | Explain |
| --- | --- | --- | --- |
| 0:00-0:45 | Introduction | README and syllabus requirements summary | Week 9 executes atomic tests and analyzes SIEM results; Week 10 maps APT29 TTPs. |
| 0:45-1:30 | Lab operator | Selected atomic GUIDs and workflow diagram | Three pinned tests; Linux scope; synthetic files; no real credentials. |
| 1:30-2:45 | Lab operator | collection.json, one raw trace, matching normalized event | Five cases ran; three official atomics and two controls. Explain exit codes, native execve evidence, archive round-trip checks and cleanup. |
| 2:45-3:45 | Detection analyst | Kibana Discover or saved SIEM summary and queries | Show inventory, broad archive query, refined source-path query. Counts are events, not infected devices. |
| 3:45-4:30 | Detection analyst | benign_backup and regression.json | Ordinary backup matches the broad query. Refinement depends on a lab path and is not a production malware verdict. |
| 4:30-6:00 | CTI analyst | APT29 mapping and coverage figure | Explain three source-backed examples: browser credentials, cookies, archiving. Keep SolarWinds and later StellarParticle reporting separate. |
| 6:00-7:15 | CTI analyst | Evidence-status column and future hunts | Only the Linux archive analogue is freshly tested; Windows telemetry, remote staging and session misuse need separate validation. |
| 7:15-7:30 | Any speaker | GitHub commits and conclusion | Demonstrate traceability, honest dates and the next Windows collection experiment. |

## Suggested spoken explanation

### Introduction

“Our project studies forensic analysis and detection of simulated infostealer-like activity in Windows environments. For Week 9, the syllabus asks us to run selected Atomic Red Team tests and analyze their results in a SIEM. For Week 10, it asks us to analyze APT29 or APT41 and map the reported techniques to MITRE ATT&CK. We selected APT29 because published investigations describe browser credential access, cookie theft and archive creation, which connect directly to our project topic.”

### Explain the laboratory scope

“The current host is Linux. We therefore executed supported Linux tests and clearly separated them from the earlier Windows experiments. This is a portable validation of command execution and archiving, not a claim that Windows credential theft has been tested. We pinned the Atomic Red Team source commit and retained each test's GUID, original executor command and substituted inputs. The selected tests are a shell loop, gzip compression of a single mock file, and tar compression of a mock browser directory.”

### Walk through one evidence chain

“Here is the exact command and its successful exit status. This raw strace record shows a successful execve system call. The normalized event points back to the trace filename and line number. A failed executable lookup is excluded by the parser, so attempted PATH locations do not inflate the process count. We also checked the archives independently: decompressing the gzip output and reading the expected tar members reproduced the original bytes. Cleanup removed the generated archives while preserving the synthetic input files and evidence.”

### Explain the SIEM results

“The custom collector only observes the launched process trees. We imported those observations into a new Elasticsearch index, saved the exact Query DSL and full API responses, and checked that the ingested count matched the collection. First we inspect all observed executions. Next we select tar and gzip processes. Finally we require the command arguments to reference our lab-browser directory. The report shows the actual counts and matching cases. The queries do not use the case label or the expected result to decide whether an event matches.”

### Explain the controls

“We deliberately ran an ordinary document backup. It also uses tar and a gzip child process, so it matches the broad archive query. That is useful evidence of ambiguity: a legitimate backup and a collection simulation can look similar at this level. The refined query distinguishes the synthetic browser directory in this experiment, but a path condition is not a reliable production detection rule. We tested additional boundary cases in a separate regression index, including missing fields, uppercase executable names and renamed binaries. These fixtures are synthetic and are not included in the real observation count.”

### Explain the APT29 analysis

“Our mapping uses primary reporting and MITRE's current technique pages. FireEye's initial SolarWinds report describes the compromised update mechanism; its later attribution update connects UNC2452 to APT29. Microsoft's investigation reports archive creation with 7-Zip. CrowdStrike's later StellarParticle report describes Chrome cookie and saved-password theft. We retain the different reporting periods instead of presenting every procedure as one universal attack sequence. The table maps ten selected techniques and links each reported behavior to a source.”

### State what the mapping does and does not prove

“The clearest connection to the new experiment is T1560.001, Archive via Utility. Our tar and gzip runs are Linux examples of that broad behavior. They are not Windows 7-Zip tests and they do not show password-protected archives or exfiltration. Our fake cookies are not authenticated session cookies, so archiving them cannot establish T1539. Similarly, a mock password string does not validate access to browser encryption or DPAPI. The Unix shell test is T1059.004 and is not relabelled as PowerShell or presented as evidence of an APT29 procedure.”

### Close

“The next useful increment is a dedicated Windows VM with suitable process and file-access telemetry, synthetic browser-profile data and a legitimate-backup control. We would correlate collection, archiving and any controlled transfer separately. The current repository contains the actual execution evidence, queries, tests, reports and source mapping. The commits use their real preparation dates; they do not reconstruct a weekly history that did not occur. The main result is a reproducible experiment and an evidence-qualified APT analysis, with the remaining coverage gaps explicitly stated.”

## Quick demonstration

1. Open the Week 9 collection and SIEM summary. Show one source trace line next to its normalized event.
2. Open Kibana at `http://127.0.0.1:15609`, choose the Week 9 data view and use the absolute UTC interval printed in the report. A relative last-15-minutes filter will eventually hide the saved observations.
3. If Kibana is unavailable, open `siem/queries.json` and `siem/results.json`. These contain actual executed Elasticsearch requests and responses; do not pretend a static chart is a live SIEM screenshot.
4. Show the Week 10 mapping and the separate GitHub commits.

## Questions to rehearse

- **Why no T1003?** The syllabus gives examples, not a mandatory credential-dumping test. Our selected supported tests cover execution and archiving using synthetic data.
- **Is this malware detection?** No. These are search predicates and controlled behavior observations. Both atomics and controls are benign.
- **Why Linux in a Windows project?** It validates a portable archive behavior and the ingestion workflow on the available host. Windows-specific behavior remains explicitly untested in this increment.
- **Does a cookie file prove T1539?** No. A valid browser session and actual access to its cookie material are different from a fake JSON file.
- **Does the archive prove exfiltration?** No. Transfer telemetry is needed; this run made no outbound data transfer.
- **Why not call every archive event an attack?** Backup and administrative activity use the same utilities; source, ancestry, file access and later network activity are needed for context.
- **Were the commits made in separate weeks?** No. These two increments were prepared on 8 November 2026 and committed separately on their actual date.
- **Was AI used?** Yes. Codex assisted with research, code, execution, validation and writing. Follow the instructor's permission and disclosure rules.

## Краткая памятка для подготовки

Главное: различайте **выполнено**, **сообщается в источнике** и **предлагается проверить**. Реально выполнены Linux Atomic-тесты, сбор strace и запросы Elasticsearch. Сведения об APT29 взяты из указанных публикаций. Windows-кража credentials/cookies, удалённый staging и exfiltration в этом запуске не выполнялись. Перед защитой каждый участник должен уметь объяснить одну цепочку «команда → исходная трасса → событие → запрос → результат» и причину совпадения обычного backup.
