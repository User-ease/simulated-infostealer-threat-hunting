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
* Week 2: OSINT data collection and source mapping — completed
* Week 3: IOC processing and normalization — implemented and locally checked; MISP import preparation — ready; actual MISP import, correlation review, and export — pending

## Week 3: IOC Processing

The [Week 3 report](docs/week3-data-processing.md) processes the three indicators already documented in [Week 2](docs/week2-data-collection.md). It preserves source references and distinguishes a vendor-reported C2 domain from contextual passive DNS IP addresses.

| Artifact | Purpose |
| --- | --- |
| [Raw IOC CSV](data/week3-iocs-raw.csv) | Traceable transcription of the Week 2 records; not a raw tool export |
| [Normalized IOC CSV](data/week3-iocs-normalized.csv) | Validated values, MISP type mapping, and `to_ids` decisions |
| [Processing summary](data/week3-processing-summary.json) | Reproducible counts and input SHA-256 |
| [Processing script](scripts/process_week3_iocs.py) | Offline validation, normalization, deduplication, and artifact generation |
| [MISP import draft](misp/week3-event-import.json) | Prepared unpublished, organization-only event; **not a MISP export** |
| [MISP preparation guide](misp/README.md) | Import checks and the evidence still needed to finish Week 3 |

Run from the repository root with Python 3.9 or newer; no third-party packages are required:

```bash
python scripts/process_week3_iocs.py
python scripts/process_week3_iocs.py --check
python -m unittest discover -s tests -v
```

The script does not contact indicators, perform live enrichment, or connect to MISP. External IOC values are reference data only. Later simulations must use synthetic data and a controlled local receiver, never these external addresses. No MISP import, correlation result, screenshot, or server export has been produced as part of this preparation.
