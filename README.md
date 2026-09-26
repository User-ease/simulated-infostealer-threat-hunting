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

* Week 1: CTI fundamentals and threat classification — completed
* Week 2: VirusTotal/Shodan collection and source mapping — documented; Maltego NS transform — verified with an exported graph
* Week 3: IOC processing, local MISP import, attribute verification, warning-list and correlation review, export, and screenshots — completed on 26 September 2026

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
