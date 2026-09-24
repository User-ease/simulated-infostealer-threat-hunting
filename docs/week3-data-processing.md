# Week 3 – IOC Processing, Normalization, and MISP Preparation

## Objective and status

Convert the three indicators documented in [Week 2](week2-data-collection.md) into traceable normalized records and prepare an unpublished MISP event for a controlled laboratory.

**Completed:** local processing, validation, deduplication, MISP field mapping, import draft generation, and automated checks.

**Pending:** import into a real MISP instance, inspection of the stored attributes, correlation review, screenshots, and a genuine server-generated export. Week 3 remains in progress until those steps are actually performed. Local checks do not establish MISP server compatibility or prove a successful import.

The scope remains safe simulation: no real malware, real credential collection, active probing of the indicators, or connections to external C2 infrastructure. These records are historical external intelligence, not evidence of compromise in the future Windows laboratory.

## Input and provenance

[week3-iocs-raw.csv](../data/week3-iocs-raw.csv) is a manually curated transcription of the Week 2 report. “Raw” means the input to this processing pipeline; it is **not** an original VirusTotal, Shodan, or Maltego export. Indicator spelling from the report is retained, including the defanged domain. No artificial duplicates or malformed rows were added to the evidence dataset to make the processing appear more substantial.

The observation date `2026-09-24` comes from the Week 2 report. It is not a new passive DNS lookup, a first/last-seen timestamp, or a date of infection. The Microsoft report was checked during preparation and lists `looksta[.]icu` as a C2 domain. VirusTotal and Shodan results were not refreshed; their values and limitations are carried forward from the repository.

An evidence audit confirmed that the saved VirusTotal **Relations / Passive DNS Replication** screenshot displays `2026-04-22` in **Date resolved** for both IPs. That date is now retained in each raw record's notes and propagated into the derived CSV and MISP comments. It is separate from the collection date. Screenshot filenames were corrected to match their visible panels without changing image content. The existing Maltego image supports only an initial domain entity, so the Week 2 report and README now identify the missing relationship evidence explicitly.

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

Fifteen automated tests passed locally on Python 3.12.14. They cover valid normalization, invalid input, metadata and schema errors, duplicate IDs, duplicate merging with provenance retention, conservative IDS decisions, JSON flags, generated-file consistency, drift detection, existing evidence paths, malformed CSV quoting, physical error line numbers, and protection of outputs after a validation failure. The captured [validation transcript](../evidence/week3-validation.txt) records the actual commands, results, UTC run time, and hashes of the tested script, tests, and input. Edge cases use synthetic `example.test` and documentation IP fixtures inside tests only. Minimum-version execution and a live MISP import have not been tested.

## MISP preparation and remaining evidence

Use the [MISP guide](../misp/README.md) with [week3-event-import.json](../misp/week3-event-import.json). It deliberately lacks server-generated event and attribute identifiers. Its date reflects the documented OSINT collection date; its title identifies it as a prepared import. Event and attribute distribution are restricted to the importing organization, and the event is unpublished.

To complete the MISP portion, record the actual instance version and import outcome, inspect all three stored attributes and flags, review any warnings and correlations, and export the saved event. A correlation match only means a relationship exists in that instance's accessible data; it does not prove common ownership or compromise. If the review finds no matches, document that observed result and the instance/feed limitations. Do not replace “not tested” with “no correlations.”

Only after these steps should a real export be added as `misp/week3-event-export.json` and genuine screenshots be added under `images/week3/`. Review exported metadata and screenshots for credentials, API keys, private organization information, and unrelated events before committing them. No placeholder screenshots or fabricated export files are included.

The [Week 3 screenshot checklist](../images/week3/README.md) specifies the views needed and what each image should demonstrate. It is a checklist, not evidence that those views have been captured.

## References

* [Week 2 collection report and evidence](week2-data-collection.md), repository source for the three records and observation date.
* [Microsoft Security Research: ACR Stealer](https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/), published 16 July 2026; IOC table lists the selected C2 domain.
* [MISP categories and types](https://www.circl.lu/doc/misp/categories-and-types/), field mapping reference.
* [MISP automation and API guide](https://www.circl.lu/doc/misp/automation/), event JSON preparation and import reference.
