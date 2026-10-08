# Forensic Analysis and Detection of Simulated Infostealer-Like Activity in Windows Environments

## Project Overview

This project focuses on threat hunting, forensic analysis, and detection of simulated infostealer-like activity in a controlled Windows environment.

The project does not use real malware or real credentials. Instead, synthetic browser-like data and safe simulated activity are used to study:

* Cyber Threat Intelligence related to infostealer activity
* Windows telemetry and forensic artifacts
* Threat-hunting hypotheses
* Behavioral detection of suspicious activity
* Visibility gaps in collected telemetry

## Weekly Progress

* [Week 1](docs/week1-cti-fundamentals.md): CTI fundamentals and threat classification — completed
* [Week 2](docs/week2-data-collection.md): VirusTotal/Shodan collection and source mapping — documented; Maltego NS transform — verified with an exported graph
* [Week 3](docs/week3-data-processing.md): IOC processing, local MISP import, attribute verification, warning-list and correlation review, export, and screenshots — completed on 26 September 2026
* [Week 4](docs/week4-cyber-kill-chain.md): Cyber Kill Chain analysis of Microsoft's real-world ACR Stealer Campaign 1, with evidence-qualified ATT&CK mapping and a 7–8 minute defense outline — documented on 1 October 2026
* [Week 5](docs/week5-threat-hunting.md): Hypothesis-driven PowerShell hunt in Elasticsearch and Kibana — the 7 October 2026 collection, query results, and screenshots are included; corrected queries and a fresh replay were verified locally on 8 October. Practical validation is complete; the practice-teacher defense remains pending.

## Week 5: Hypothesis-driven Threat Hunting

The [Week 5 report](docs/week5-threat-hunting.md) documents four harmless PowerShell launches, their native Event 400 records, and the original Elasticsearch results of **4 → 2 → 1** review candidates. All four cases are benign; the exercise validates a limited launch-flag hypothesis, not a malware detector. The implementation uses Elasticsearch and Kibana with a custom collector, without Logstash or Winlogbeat.

| Artifact | Purpose |
| --- | --- |
| [Collected events](data/week5-powershell-events.jsonl), [native XML](evidence/week5/windows-events.xml), and [manifest](evidence/week5/run-manifest.json) | Preserved telemetry and provenance from 7 October 2026 |
| [Original Query DSL](evidence/week5/original-hunt-queries.json) and [original results](evidence/week5/hunt-results.json) | Exact historical queries and recorded Elasticsearch responses |
| [Current Query DSL](data/week5-hunt-queries.json) | Version 2 accepts the full `Hidden`/`Bypass` flag-value pairs at the end of a command line as well as before another argument |
| [Replay runner](scripts/run_week5_hunt.py) and [Compose configuration](docker/week5-compose.yml) | Import the archived dataset into a new index and save new execution evidence separately |
| [Original Kibana views](docs/week5-threat-hunting.md#kibana-verification-of-the-original-run) | Historical screenshots of the original queries and results |
| [Runtime redaction record](evidence/week5/runtime-redactions.json) | Disclosure of host-path anonymization in the published runtime evidence |
| [Correction validation](evidence/week5-validation/validation-summary.json) and [new replay results](evidence/week5-replays/2026-10-08-validation/hunt-results.json) | Actual verification of revised queries, fresh ingestion, and preservation of the original evidence |

For a fresh machine, use Docker Desktop with its Linux engine and Python 3.9 or newer. From the repository root:

```powershell
docker compose -f docker/week5-compose.yml up -d --wait
python scripts/run_week5_hunt.py --replay
```

Replay preserves the collected events and original results, creates a unique index and Kibana data view, and writes new outputs under `evidence/week5-replays/`. The [full instructions](docs/week5-threat-hunting.md#replaying-the-archived-dataset-on-a-fresh-machine) explain how to select that view, use the historical event time range, and repeat queries. The 7 October evidence does not certify subsequent query revisions.

## Week 4: Cyber Kill Chain

The [Week 4 report](docs/week4-cyber-kill-chain.md) maps Microsoft's published Campaign 1 behavior to all seven Kill Chain stages and the relevant ATT&CK techniques. It marks reconnaissance and weaponization as undocumented, limits the blockchain C2 variation to a subset of intrusions, and separates source-reported attack behavior from the group's Week 2–3 IOC evidence. The report includes a diagram, proposed defensive questions for a later safe lab, and a timed defense outline. No new attack execution or local endpoint telemetry is claimed.

## Week 3: IOC Processing

The [Week 3 report](docs/week3-data-processing.md) processes the three indicators already documented in [Week 2](docs/week2-data-collection.md). It preserves source references and distinguishes a vendor-reported C2 domain from contextual passive DNS IP addresses.

| Artifact | Purpose |
| --- | --- |
| [Raw IOC CSV](data/week3-iocs-raw.csv) | Traceable transcription of the Week 2 records; not a raw tool export |
| [Normalized IOC CSV](data/week3-iocs-normalized.csv) | Validated values, MISP type mapping, and `to_ids` decisions |
| [Processing summary](data/week3-processing-summary.json) | Reproducible counts and input SHA-256 |
| [Processing script](scripts/process_week3_iocs.py) | Offline validation, normalization, deduplication, and artifact generation |
| [MISP import draft](misp/week3-event-import.json) | Prepared unpublished, organization-only event; **not a MISP export** |
| [MISP server export](misp/week3-event-export.json) | JSON returned by the running MISP instance for event ID 1 |
| [MISP record](misp/README.md) | Deployment, import, verification, and review results |
| [Validation transcript](evidence/week3-validation.txt) | Actual offline run, 15 tests, and hashes of tested inputs/code |
| [MISP screenshots](images/week3/README.md) | Actual event, attribute, correlation, and warning-list views |

Run from the repository root with Python 3.9 or newer; no third-party packages are required:

```bash
python scripts/process_week3_iocs.py
python scripts/process_week3_iocs.py --check
python -m unittest discover -s tests -v
```

The processing script does not contact indicators or perform live enrichment. The separate Week 3 deployment used a local MISP 2.5.47 instance at `http://127.0.0.1:8080`. Event ID 1 contains the three prepared indicators. The Cloudflare warning list matched both contextual IPs; no correlations were returned in this new instance, whose two feeds are disabled. See the [Week 3 report](docs/week3-data-processing.md) for the scope and evidence. Later simulations must use synthetic data and a controlled local receiver, never these external addresses.
