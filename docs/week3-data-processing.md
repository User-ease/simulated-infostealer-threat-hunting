# Week 3 – IOC Processing, Normalization, and MISP Verification

## Objective and status

Convert the three indicators documented in [Week 2](week2-data-collection.md) into traceable normalized records and verify them in a local MISP event.

**Completed:** local processing, validation, deduplication, MISP field mapping, import draft generation, automated checks, local MISP deployment and import, server-side verification, warning-list and correlation review, screenshots, and a genuine server export.

The scope remains safe simulation: no real malware, real credential collection, active probing of the indicators, or connections to external C2 infrastructure. These records are historical external intelligence, not evidence of compromise in the future Windows laboratory.

## Input and provenance

[week3-iocs-raw.csv](../data/week3-iocs-raw.csv) is a manually curated transcription of the Week 2 report. “Raw” means the input to this processing pipeline; it is **not** an original VirusTotal, Shodan, or Maltego export. Indicator spelling from the report is retained, including the defanged domain. No artificial duplicates or malformed rows were added to the evidence dataset to make the processing appear more substantial.

The observation date `2026-09-24` comes from the Week 2 report. It is not a new passive DNS lookup, a first/last-seen timestamp, or a date of infection. The Microsoft report was checked during preparation and lists `looksta[.]icu` as a C2 domain. VirusTotal and Shodan results were not refreshed; their values and limitations are carried forward from the repository.

An evidence audit confirmed that the saved VirusTotal **Relations / Passive DNS Replication** screenshot displays `2026-04-22` in **Date resolved** for both IPs. That date is now retained in each raw record's notes and propagated into the derived CSV and MISP comments. It is separate from the collection date. Screenshot filenames were corrected to match their visible panels without changing image content. A later Maltego NS transform on 26 September 2026 returned two name servers; its graph is documented in Week 2 and does not alter the three Week 3 indicator mappings.

| Record | Input | Evidence basis | Limitation |
| --- | --- | --- | --- |
| `w2-001` | `looksta[.]icu` | Microsoft report; Week 2 selected indicator | A historical vendor IOC does not establish current activity or local compromise |
| `w2-002` | `104.21.33.112` | Week 2 passive DNS and Shodan records | Week 2 identifies Cloudflare AS13335 shared infrastructure; no independent malicious ownership is established |
| `w2-003` | `172.67.161.227` | Week 2 passive DNS record | Not investigated separately in Shodan; a DNS association alone is insufficient for blocking or attribution |

The raw schema is:

| Column | Meaning |
| --- | --- |
| `record_id` | Unique stable reference used in generated CSV and MISP comments |
| `indicator`, `type` | Transcribed value and input type (`domain`, `ip`, or `ipv4`) |
| `source`, `source_url` | Named source and reference URL(s), never fetched by the script |
| `evidence_ref` | Repository document section or existing screenshot supporting the record |
| `observation_date` | Date recorded in the source report, in `YYYY-MM-DD` format |
| `evidence_role` | Analyst classification: `vendor_reported_c2` or `passive_dns_context` |
| `notes` | Interpretation and limitations retained in all outputs |

The script validates metadata presence and syntax, not the truth or reachability of a reference. Evidence classification is an explicit analyst input, not an automated reputation verdict.

## Processing decisions

1. Read UTF-8 CSV (an optional BOM is accepted) with strict quote parsing. Require the documented column order, nonempty fields, unique record IDs, and valid ISO dates. A validation or parsing error, including an unterminated quoted field, stops processing before outputs are written. Error messages identify the physical input line, including after multiline fields; records are never silently dropped.
2. Trim surrounding whitespace. Replace `[.]` with `.`. Lowercase DNS names and remove one optional trailing DNS dot. Accept ASCII DNS labels only; reject URLs, ports, wildcards, empty labels, and malformed names. Internationalized domains and other defanging formats are outside this small workflow.
3. Validate IPv4 with Python's standard `ipaddress` library and normalize input `ip` to `ipv4`. Reject IPv6 and unsupported IOC types explicitly rather than guessing a type.
4. Group by normalized type and value. Merge repeated indicators while retaining all raw record IDs and unique provenance values, joined with ` | `. The original rows remain in the raw CSV, which preserves the exact source-to-record association. Mixed evidence roles conservatively result in `to_ids=false`.
5. Map domains to MISP `domain` and IPv4 destinations to `ip-dst`, under `Network activity`. The destination type describes their possible role in the threat context; it does not assert an observed laboratory connection or malicious ownership.
6. Set `to_ids=true` only for an explicitly vendor-reported C2 domain. Keep passive DNS context `false`; IP records cannot be promoted to IDS candidates by this workflow. This flag prepares a detection candidate for review, not an instruction to deploy a blocklist.
7. Write deterministic CSV, a processing summary including the raw file SHA-256, and a MISP import draft. Generated JSON uses actual boolean values. No network calls, MISP API credentials, invented server IDs, UUIDs, sightings, or first/last-seen values are involved.

| Normalized indicator | Normalized type | MISP type | `to_ids` | Reason |
| --- | --- | --- | --- | --- |
| `looksta.icu` | `domain` | `domain` | `true` | Named C2 in the Microsoft report; review freshness before any operational use |
| `104.21.33.112` | `ipv4` | `ip-dst` | `false` | Contextual passive DNS and shared infrastructure |
| `172.67.161.227` | `ipv4` | `ip-dst` | `false` | Contextual passive DNS; no separate Shodan investigation in Week 2 |

No hashes, URLs, filenames, additional hostnames, or other indicators from the wider Microsoft report were added. The dataset is intentionally limited to Week 2's collected-indicator table.

## Reproduction and local validation

From the repository root, with Python 3.9+ and no additional packages:

```bash
python scripts/process_week3_iocs.py
python scripts/process_week3_iocs.py --check
python -m unittest discover -s tests -v
```

The first command regenerates the three derived artifacts. `--check` compares them byte for byte without writing and exits nonzero if a file is missing or stale. Alternative inputs can be processed with `--raw PATH --output-root DIRECTORY`; that feature does not perform enrichment or establish evidence provenance. Use a separate output directory for experiments. Edit the curated input, not the derived files, when correcting evidence records.

The local run produced:

| Measure | Result |
| --- | --- |
| Input records | 3 |
| Valid unique indicators | 3 |
| Duplicate records merged | 0 |
| Rejected records | 0 |
| IDS candidates | 1 |
| Context-only indicators | 2 |

The [generated summary](../data/week3-processing-summary.json) includes an input hash for reproducibility, not a claim of external evidentiary authenticity. On invalid input the script exits with an error and leaves prior generated artifacts in place; those older artifacts must not be mistaken for successful processing of the invalid input.

Fifteen automated tests passed locally on Python 3.12.14. They cover valid normalization, invalid input, metadata and schema errors, duplicate IDs, duplicate merging with provenance retention, conservative IDS decisions, JSON flags, generated-file consistency, drift detection, existing evidence paths, malformed CSV quoting, physical error line numbers, and protection of outputs after a validation failure. The captured [validation transcript](../evidence/week3-validation.txt) records the actual commands, results, UTC run time, and hashes of the tested script, tests, and input. Edge cases use synthetic `example.test` and documentation IP fixtures inside tests only. Minimum-version Python execution remains untested; the live MISP import is recorded below.

## MISP deployment and observed evidence

The [prepared import](../misp/week3-event-import.json) was posted once after confirming that no matching event existed. The local Docker installation used official `misp-docker` commit `d2b82533d5335b2ff81eb7a8548757bbdbf4076c`; Docker Engine `29.8.0`, Docker Desktop `4.92.0`, and Compose `v5.5.1`. MISP reported `2.5.47`. All six services ran, with Core, Nginx, Modules, MariaDB, and Valkey healthy. Nginx published only on loopback. The working URL was `http://127.0.0.1:8080` (local lab, no TLS certificates).

MISP created event **ID 1**, UUID `0d97a833-75a8-46b1-a499-b99313ad31c9`, titled “Week 3 - ACR Stealer OSINT IOC Processing - PREPARED IMPORT”. A separate server read confirmed **exactly three** stored `Network activity` attributes: `looksta.icu` as `domain` with `to_ids=true`; `104.21.33.112` and `172.67.161.227` as `ip-dst` with `to_ids=false`. All three comments were retained. The event and attributes have distribution `0` (“Your organisation only”), and the event is unpublished. The event view's contextualisation warning reports missing tags/galaxy clusters; it does not mean the IOCs matched a warning list.

At first, all 225 installed warning lists were disabled. After enabling only “List of known Cloudflare IP ranges” (ID 33), MISP's `checkValue` returned two hits: `104.21.33.112` in `104.16.0.0/13` and `172.67.161.227` in `172.64.0.0/13`. `looksta.icu` did not match that enabled list. These are expected shared-infrastructure warnings and reinforce the context-only decision for both IPs.

An `attributes/restSearch` call with `includeCorrelations=true` returned zero related attributes for each of the three values. The UI correlation graph was empty. This was a new local instance containing only this event; both built-in feeds were disabled. “No correlations observed” therefore applies only to this instance and its accessible data on **26 September 2026**, approximately **13:00 UTC / 18:00 Asia/Qyzylorda**. It is not a claim about all MISP data or current external DNS.

The [server-exported event JSON](../misp/week3-event-export.json) was saved from `/events/view/1.json`, verified to contain the three expected attributes, and checked against locally configured secrets. SHA-256: `CE56FCE639264C5FC2A1BA44AB9021DEC45616D30FEFCA1EEB583DAAA43523DE`. Genuine UI captures show the [event](../images/week3/misp-event.png), [attributes](../images/week3/misp-attributes.png), [empty correlation graph](../images/week3/misp-correlation.png), and [enabled Cloudflare warning list](../images/week3/misp-warninglist.png). The graph screenshot documents the empty UI view; the API result supports the per-attribute zero-correlation count. The [MISP record](../misp/README.md) gives further deployment and review detail.

## References

* [Week 2 collection report and evidence](week2-data-collection.md), repository source for the three records and observation date.
* [Microsoft Security Research: ACR Stealer](https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/), published 16 July 2026; IOC table lists the selected C2 domain.
* [MISP categories and types](https://www.circl.lu/doc/misp/categories-and-types/), field mapping reference.
* [MISP automation and API guide](https://www.circl.lu/doc/misp/automation/), event JSON preparation and import reference.
