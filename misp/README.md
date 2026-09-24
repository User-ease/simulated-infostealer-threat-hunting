# Week 3 MISP Preparation

`week3-event-import.json` is generated locally from the curated IOC dataset. It is a **prepared import payload**, not an export from MISP, proof of an imported event, or a correlation result. No MISP instance was used in this preparation.

## Draft settings

| Field | Prepared value | Meaning |
| --- | --- | --- |
| Event `info` | Week 3 - ACR Stealer OSINT IOC Processing - PREPARED IMPORT | Clearly identifies preparation and external intelligence |
| `date` | `2026-09-24` | Documented Week 2 OSINT observation date, not an infection timestamp |
| `distribution` | `0` on event and all attributes | Your organization only |
| `published` | `false` | Unpublished draft |
| `analysis` | `0` | Initial; server review is pending |
| `threat_level_id` | `4` | Undefined; no unsupported severity assessment |
| Attributes | 1 domain and 2 `ip-dst`, all `Network activity` | No invented indicators |
| `to_ids` | Domain `true`; IPs `false` | Candidate detection indicator versus contextual data |

Comments retain raw record IDs, dates, sources, reference URLs, evidence paths, and caveats. There are no fabricated event IDs, attribute IDs, UUIDs, sightings, timestamps, or correlation objects. `to_ids` does not publish or deploy anything by itself; review downstream automation before using the draft in a shared instance.

## Import and verification procedure — pending

1. Use an authorized, isolated laboratory MISP instance with no automatic publishing or synchronization. If an instance still needs to be provisioned, follow the [official MISP Docker project](https://github.com/MISP/misp-docker) and its current setup instructions. This repository neither installs MISP nor stores credentials.
2. Run `python scripts/process_week3_iocs.py --check` from the repository root. Review the raw source records and the three attributes before importing.
3. Import the JSON using the instance's supported event import function, or use the authenticated event-creation API (`POST /events`) with the JSON file as the body. The [official automation guide](https://www.circl.lu/doc/misp/automation/) describes that payload. Use the instance's trusted TLS configuration; keep API keys outside the repository and screenshots. API/UI behavior and permissions must be checked on the actual installed version.
4. Record the actual response and server event ID. If creation fails or the result is uncertain, inspect the event list before retrying. The draft has no persistent UUID, so blindly submitting it again can create duplicate events.
5. Open the saved event. Verify exactly three imported attributes, their values/types/categories, domain `to_ids=true`, both IPs `to_ids=false`, retained comments, unpublished status, and organization-only distribution. Investigate any rejected or altered fields before recording success.
6. Review available warning-list matches and correlations in that instance. Record the actual result, review time, and feed/data scope. Context IPs can still correlate even when `to_ids=false`; any match requires interpretation. “No matches observed” is only valid after an actual review.
7. Export the saved event as MISP JSON. After reviewing sensitive metadata, save the genuine output as `misp/week3-event-export.json`. Preserve the prepared input separately; do not rename it to imply it came from a server.
8. Capture actual event, attribute, and correlation views under `images/week3/`, then update the Week 3 report and README status with links to that evidence. Record any redactions. Leave missing or unperformed steps explicitly pending.

The [screenshot checklist](../images/week3/README.md) specifies exactly what each planned view should show. Local processing evidence is available in the [validation transcript](../evidence/week3-validation.txt).

## Current evidence status

| Item | Status |
| --- | --- |
| Input dataset and deterministic import preparation | Available in this repository |
| Local processing tests and generated-file checks | Passed; see the Week 3 report |
| Installed MISP version | Not recorded; no instance used |
| Import response / stored event ID | Not produced |
| Server-side attribute validation | Not performed |
| Warning-list and correlation review | Not performed |
| Screenshots | Not captured |
| MISP server export | Not produced |

This is external OSINT preparation for a safe-simulation project. Do not visit the indicator domain, probe these IP addresses, download malware, or use real credentials as part of the laboratory exercise.
