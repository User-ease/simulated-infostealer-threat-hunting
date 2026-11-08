# Week 9 - Atomic Red Team execution and SIEM analysis

Project: **Forensic Analysis and Detection of Simulated Infostealer-Like Activity in Windows Environments**. Prepared 8 November 2026. This increment addresses syllabus 2026-2027 section 3.3, Week 9: execute selected atomic tests and record/analyze their results in a SIEM. The examples T1059 and T1003 are illustrative; credential dumping is not required for this chosen experiment.

## Actual result

Three official Linux Atomic Red Team tests and two benign controls completed successfully. Native child-process tracing recorded **18 successful execve events**. Elasticsearch 9.5.5 indexed all 18; the broad archive query returned **5 events**, and the source-path refinement returned **2 events** belonging to `atomic_gzip` and `atomic_tar`. All **20 query boundary assertions** passed in a separate synthetic index. Archive integrity and cleanup checks passed.

**Platform scope:** the available host is Linux. This is a portable extension of the Windows-focused project, validating shell execution and archive behavior. It does not validate Windows PowerShell, browser credential decryption, cookie theft, persistence or exfiltration. The Week 8 Windows plan remains a plan for those stages; this run is not represented as its full execution.

![Evidence pipeline](../images/week9/evidence-pipeline.svg)

## Atomic selection and provenance

Source commit: [`a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6`](https://github.com/redcanaryco/atomic-red-team/tree/a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6). Test GUIDs, original executor strings, supported platforms, source URLs and YAML SHA-256 values are in [selected-atomics.json](../data/week9/selected-atomics.json). The relevant source snippets retain the [upstream MIT license](../data/week9/ATOMIC-RED-TEAM-LICENSE.txt).

| Technique / test number at pin | Test name | GUID | Substituted inputs |
| --- | --- | --- | --- |
| T1059.004 / 8 | Command line scripts | b04ed73c-7d43-4dc8-b563-a2fc595cba1a | None; five harmless shell markers |
| T1560.001 / 6 | Data Compressed - nix - gzip Single File | cde3c2af-3485-49eb-9c1f-0ed60e9cc0af | `input_file=lab-browser/mock-browser.json`; fallback content is a training marker |
| T1560.001 / 7 | Data Compressed - nix - tar Folder or File | 7af2b51e-ad1c-498c-aca8-d3290c19535a | `input_file_folder=lab-browser`; `output_file=out/browser.tar.gz` |

The selected executor commands were run manually under a custom Python/strace wrapper. This is **not an Invoke-AtomicRedTeam run**. The [Atomic Red Team getting-started guidance](https://github.com/redcanaryco/atomic-red-team/wiki/Getting-Started) supports reviewing and executing the individual test procedure. No dependency installer or unreviewed upstream payload was run. [T1059.004 source](https://github.com/redcanaryco/atomic-red-team/blob/a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6/atomics/T1059.004/T1059.004.yaml), [T1560.001 source](https://github.com/redcanaryco/atomic-red-team/blob/a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6/atomics/T1560.001/T1560.001.yaml).

## Environment and collection

The collector generated `lab-browser/mock-browser.json`, `lab-browser/cookies.json` and `ordinary-docs/notes.txt` within a new evidence directory. Values include `FAKE-STUDENT`, `NOT-A-REAL-PASSWORD`, an invalid session marker and `https://training.invalid`. There are no real browser profiles or account credentials.

`strace -ff -ttt` followed each launched process tree and recorded `execve`, `openat`, `unlink`, `unlinkat` and `rename`. The normalized dataset contains only successful `execve` calls; failed executable lookups are excluded. File-operation traces remain available for examination but are not indexed as a complete file-access dataset. Collection is limited to the selected child processes, not system-wide monitoring. Each event retains the raw trace filename and line number.

The event label is `event.dataset=lab.strace`; `host.name=LAB-LINUX` is a fixed pseudonym, and no actual hostname was collected. Commands use relative lab paths so public evidence does not expose the user's home path. Process IDs and native timestamps are retained. The synthetic-case labels are added by the harness and are used for evaluation, not query selection.

Run ID: `20261108T145956001720Z`. Collection: **8 November 2026 14:59:56-15:00:01 UTC**, or **19:59:56-20:00:01 Asia/Almaty**. These times are actual execution times. Earlier Windows evidence is not reused as new Week 9 telemetry.

| Case | Type | Exit code | Successful execve events |
| --- | --- | --- | --- |
| `atomic_shell` | Official atomic | 0 | 7 |
| `atomic_gzip` | Official atomic | 0 | 2 |
| `atomic_tar` | Official atomic | 0 | 4 |
| `benign_backup` | Benign control | 0 | 4 |
| `plain_control` | Benign control | 0 | 1 |

## Outcome and cleanup checks

The shell test printed exactly five expected lines. The gzip round trip reproduced the source file bytes. The tar archive contained the expected mock-browser and cookie files, and their extracted byte streams matched the original inputs. The tar test ran after gzip, so it also included `mock-browser.json.gz`; the exact member list is recorded in the collection manifest. No archive was extracted onto the filesystem during validation.

SHA-256 values were captured before cleanup. The upstream cleanup commands removed the gzip and tar outputs; the ordinary backup was also removed. Synthetic input files, native traces, output streams and manifests remain as reproducibility evidence. The [collection manifest](../evidence/week9/20261108T145956001720Z/collection.json) records each command, its timing, its exit status, input substitutions, checks and cleanup results.

## SIEM implementation and findings

The dedicated Elasticsearch node uses [week9-elasticsearch.yml](../config/week9-elasticsearch.yml), with its HTTP listener on `127.0.0.1:19209`. Kibana uses [week9-kibana.yml](../config/week9-kibana.yml) at `127.0.0.1:15609`. These are new loopback-only teaching services with authentication disabled in this isolated configuration; the configuration must not be reused on a shared server. No existing service or security agent was reconfigured.

This is an Elastic hunting pipeline with custom collection and Query DSL. It does not configure the Elastic Security detection engine, production integration or scheduled alerts. The [analyzer](../scripts/analyze_week9_elastic.py) verifies collection hashes before ingestion, creates a new index, uses create-only bulk operations and saves actual API requests/responses. A second ingestion into the same evidence directory or index is refused.

Index: `lab-week9-20261108t145956001720z`. The normalizer lowercases executable names; arguments retain their values. The queries do not filter on `lab.case`, test GUIDs or expected labels.

| Query | Predicate | Actual events | Interpretation |
| --- | --- | --- | --- |
| Inventory | `event.dataset = lab.strace` | 18 | All successfully traced executions |
| Archive utility | Inventory + `process.name IN (tar, gzip)` | 5 | Includes ordinary backup and tar's gzip children |
| Lab browser archive | Archive utility + an argument containing `lab-browser` | 2 | Direct gzip and tar cases referencing the synthetic browser source |

![Actual query results](../images/week9/query-results.svg)

The figure is generated from the saved Elasticsearch responses; it is not a Kibana screenshot. A tar invocation can launch a shell and a gzip child, so counts of events and counts of tests differ. The child gzip processes have no browser-source argument and drop out of the refined search.

The ordinary document backup is a deliberate benign match to the broad query. The refined predicate distinguishes our controlled inputs but has an obvious dependency on the lab path. A production rule would need file-access context, process ancestry, source sensitivity, baseline backup behavior and transfer evidence. Legitimate browser backups could still match. No precision, recall or production false-positive estimate is justified by this small, entirely benign dataset.

A separate `-regression` index contains ten synthetic boundary documents: browser tar, browser gzip, ordinary backup, shell wrapper, missing name, uppercase name, missing arguments, a different executable name, empty arguments and a renamed-binary gap. The two predicates produced their expected results in all 20 assertions. These are query-semantics checks, not additional endpoint observations or evidence of malicious activity.

## Evidence inventory

| Artifact | Meaning |
| --- | --- |
| [collection.json](../evidence/week9/20261108T145956001720Z/collection.json) | Commands, outcomes, archive checks and cleanup |
| [events.jsonl](../evidence/week9/20261108T145956001720Z/events.jsonl) and [traces/](../evidence/week9/20261108T145956001720Z/traces/) | Normalized real observations and their raw syscall sources |
| [collection-sha256.json](../evidence/week9/20261108T145956001720Z/collection-sha256.json) | Byte-integrity inventory of collection files |
| [SIEM summary](../evidence/week9/20261108T145956001720Z/siem/summary.json) | Counts, matching cases and assertion status |
| [queries.json](../evidence/week9/20261108T145956001720Z/siem/queries.json), [results.json](../evidence/week9/20261108T145956001720Z/siem/results.json) | Executed queries and full search responses |
| [api-transcript.json](../evidence/week9/20261108T145956001720Z/siem/api-transcript.json) | Actual Elasticsearch calls and responses, including separate fixtures |
| [runtime.json](../evidence/week9/20261108T145956001720Z/siem/runtime.json), [regression.json](../evidence/week9/20261108T145956001720Z/siem/regression.json) | Server-reported version and case-by-case query checks |
| [SIEM hashes](../evidence/week9/20261108T145956001720Z/siem/sha256.json) | Integrity inventory of analysis outputs |

## Reproduction

Requirements: Linux, Python 3.9+, strace, sh, tar, gzip, seq and sleep. The Python collectors require no third-party packages. Elasticsearch/Kibana 9.5.5 were downloaded from the official Elastic archive distribution and verified against vendor SHA-512 files. [Elastic archive-installation documentation](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-from-archive-on-linux-macos).

From a writable repository checkout:

1. Extract the verified Elasticsearch and Kibana archives outside the repository. Copy the supplied YAML configurations into their respective `config/` directories. Use `ES_JAVA_OPTS='-Xms512m -Xmx512m'` for this small lab and run Elasticsearch as a normal user. Start Kibana with `NODE_OPTIONS=--max-old-space-size=768`.
2. Run the collector, then pass its printed new evidence directory to the analyzer:

```bash
python3 scripts/collect_week9_atomics.py
python3 scripts/analyze_week9_elastic.py evidence/week9/<NEW_RUN_ID>
python3 -m unittest discover -s tests -v
```

3. Create a Kibana data view for the exact new index, with `@timestamp` as time field. For the archived run use the index above and **2026-11-08T14:59:50Z through 2026-11-08T15:00:10Z**. Use absolute time; relative time filters eventually hide old observations.
4. Display `process.name`, `process.command_line` and `lab.case`. Equivalent broad KQL: `event.dataset:"lab.strace" and process.name:("tar" or "gzip")`. To reproduce the refinement exactly, run the saved Query DSL in Dev Tools; it uses a case-insensitive wildcard on argument values.
5. Keep the original evidence unchanged. A rerun gets a new run ID, directory and index. Stop only the dedicated lab services when finished; the indices persist in their own data directories.

## Continuity and limitations

Week 8 planned a longer Windows sequence. This increment executes a deliberately small subset using supported Linux procedures. T1059.004 is Unix Shell, not T1059.001 PowerShell. T1560.001 applies to the archive utility behavior; its mapping does not prove credential theft, a malicious objective or exfiltration. The [Week 10 APT29 analysis](week10-apt29-analysis.md) connects source-reported behavior to this evidence with explicit qualifiers.

Both increments were prepared on 8 November 2026, with separate commits using actual timestamps. That provides transparent change separation but cannot establish historical weekly commit cadence. The group still needs to give the [7-8 minute defense](weeks9-10-defense.md).

**AI assistance:** OpenAI Codex assisted with source review, test selection, code, execution, validation, figures and writing. The group should review and understand the material and follow the course's AI-permission and disclosure requirements. Instructor permission is not asserted here.
