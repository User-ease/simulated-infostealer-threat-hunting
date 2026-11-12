# Windows run of the Week 8 emulation plan

On 12 November 2026 the group executed stages A–F on a disposable Windows Server 2022 Datacenter Evaluation VM. The exercise used a fixed set of four synthetic files. The guest had no network adapter. Its HTTP receiver listened only on 127.0.0.1:18768. Run ID **c5dff010b214**, OS build **20348**. The earlier Week 9 archive experiment and its nine controls retain their own evidence. [Original plan](week8-adversary-emulation-plan.md) · [Earlier Week 9 run](week9-atomic-red-team.md)

| Stage | Action and observed evidence |
| --- | --- |
| A · ClickFix simulation | A guest client fetched the static update page (HTTP 200). The local training window displayed its command. The operator copied it and submitted it in the Windows guest. The page contained no automatic execution. [Page](../evidence/week9-windows-chain/c5dff010b214/update.html) · [Training window](../evidence/week9-windows-chain/c5dff010b214/operator-page.png) · [Pasted command](../evidence/week9-windows-chain/c5dff010b214/operator-paste.png) |
| B · Loader | Security 4688 records **488** and **490** show the cmd.exe parent and its PowerShell child (PID **3936**). The loader decoded a fixed training marker. The manifest records the marker value. [Native events](../evidence/week9-windows-chain/c5dff010b214/events.xml) |
| C · Scheduled Task | Security 4698 record **507** and the task XML identify a logon trigger and a local marker action. Security 4688 record **509** shows the on-demand marker action. Its output matched the run ID. Security 4699 record **524** records deletion. A subsequent logon trigger was not exercised. [Task definition](../evidence/week9-windows-chain/c5dff010b214/task.xml) |
| D · Discovery | Children of the loader ran hostname.exe and whoami.exe (4688 records **511, 512**). The manifest contains the returned identity, host and enumerated fixture filenames. [Manifest](../evidence/week9-windows-chain/c5dff010b214/completed.json) |
| E · Collection and archiving | The same loader read all four registered files (4663 records **515, 516, 517, 518, 519, 520, 521, 522**), staged copies, then called Compress-Archive (4104 record **17** contains its script). Recovering the four members independently from the received ZIP verifies the outcome. [Member verification](../evidence/week9-windows-chain/c5dff010b214/verification.json) |
| F · Loopback transfer | The application log recorded POST /receive, HTTP 201, both endpoints on 127.0.0.1 and **578 bytes** written. Sender, receiver and the published ZIP have the same SHA-256. [Receiver log](../evidence/week9-windows-chain/c5dff010b214/http.jsonl) · [Received synthetic ZIP](../evidence/week9-windows-chain/c5dff010b214/received.zip) |

The archive SHA-256 was `eeed7a4baa02fff7fbc50ba55b265fea3257121bd8b168b1d23bf55c5a8bdebf`. The compact evidence XML contains the measured processes and task within the run window. Security audit record IDs and PowerShell operational record IDs belong to different channels. The static page fetch and Windows process records establish the surrounding actions. The screenshots document the operator step. The audit events alone cannot identify a clipboard gesture. The Windows RunMRU value also contains the displayed loader command. The compact export has no attributable classic PowerShell 400 record. For this run the loader evidence is Security 4688 and PowerShell Operational 4104. The earlier Week 5 Event 400 evidence belongs to its own run.

## SIEM verification

Elasticsearch **9.5.5** indexed **26 native events** and **3 receiver entries**. The replay identifies the loader by executable and command, follows its native parent and PID, checks task registration and deletion, eight ReadData records across four exact paths and the receiver's independent receipt. The ordered timeline spans the initial HTTP GET through task deletion. HTTP entries use line numbers in the receiver log. A script block containing Compress-Archive identifies code, while the ZIP and its hashes establish its execution outcome. [Queries](../evidence/week9-windows-chain/c5dff010b214/siem/queries.json) · [Search hits](../evidence/week9-windows-chain/c5dff010b214/siem/hits.json) · [Counts and timeline](../evidence/week9-windows-chain/c5dff010b214/siem/summary.json)

- A directory-only control listed the same four names. Its PID **4412** returned **zero** 4663 ReadData matches on the four files. Directory listing and file content reads are separately observable.
- A POST to /rejected returned **404** and saved **zero** bytes. Only /receive accepted the archive. That comparison shows why an attempted connection alone is insufficient.
- The collector verified that the task and temporary lab tree were removed and that the receiver exited. A successful HTTP POST on this isolated guest models **T1048.003**. The APT29 HTTPS retrieval classification **T1048.002** is based on the MITRE campaign entry citing Volexity. No real credentials, external egress or APT attribution were tested. [Cleanup](../evidence/week9-windows-chain/c5dff010b214/cleanup.json) · [APT29 source analysis](week10-apt29-analysis.md#t1048002-and-the-owa-retrieval)

## Reproduction

1. Take a clean snapshot of a disposable Windows Server VM with Windows PowerShell 5.1, an interactive administrative session and the Task Scheduler service. Disconnect the guest NIC. Copy the four files in [scripts/week8_windows](../scripts/week8_windows/) into a single directory. Use new C:\Week8Lab and C:\Week8Evidence paths (the collector refuses an existing workspace).
2. Run `powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\prepare.ps1` in that directory. Copy the displayed command into the Windows Run dialog and submit it. Wait for the scheduled marker, file collection, loopback receipt and native event export. Copy C:\Week8Evidence out and revert the disposable overlay. Keep the original XML and ZIP intact.
3. Start a local Elasticsearch instance and replay from the repository root. Supply a new output directory for each run.

```sh
python3 scripts/analyze_week8_chain.py evidence/week9-windows-chain/c5dff010b214 replay-week8 --url http://127.0.0.1:9200
```

This is a custom emulation of the Week 8 plan. The three pinned upstream Atomic Red Team procedures remain documented in the original Week 9 experiment. Codex assisted with implementation, operator input, verification and writing.
