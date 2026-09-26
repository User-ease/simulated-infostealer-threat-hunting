# Week 3 MISP Deployment and Import

`week3-event-import.json` is generated locally from the curated IOC dataset. It remains the **prepared import payload**. [`week3-event-export.json`](week3-event-export.json) is the separate response saved from the running MISP instance on 26 September 2026.

## Draft settings

| Field | Prepared value | Meaning |
| --- | --- | --- |
| Event `info` | Week 3 - ACR Stealer OSINT IOC Processing - PREPARED IMPORT | Clearly identifies preparation and external intelligence |
| `date` | `2026-09-24` | Documented Week 2 OSINT observation date, not an infection timestamp |
| `distribution` | `0` on event and all attributes | Your organization only |
| `published` | `false` | Unpublished draft |
| `analysis` | `0` | Initial analysis state retained after the documented server review |
| `threat_level_id` | `4` | Undefined; no unsupported severity assessment |
| Attributes | 1 domain and 2 `ip-dst`, all `Network activity` | No invented indicators |
| `to_ids` | Domain `true`; IPs `false` | Candidate detection indicator versus contextual data |

Comments retain raw record IDs, dates, sources, reference URLs, evidence paths, and caveats. There are no fabricated event IDs, attribute IDs, UUIDs, sightings, timestamps, or correlation objects. `to_ids` does not publish or deploy anything by itself; review downstream automation before using the draft in a shared instance.

## Local deployment and observed result

The official `MISP/misp-docker` checkout was at commit `d2b82533d5335b2ff81eb7a8548757bbdbf4076c`. Docker Engine was `29.8.0`, Docker Desktop `4.92.0`, and Docker Compose `v5.5.1`. MISP reported version `2.5.47` through `/servers/getVersion`. The six Compose services were running; Core, Nginx, Modules, MariaDB, and Valkey reported healthy. Nginx published only `127.0.0.1:8080` and `127.0.0.1:8443`; the working HTTP URL was `http://127.0.0.1:8080`. Non-default administrator, database, Redis, and Supervisor credentials were generated in the local ignored `.env`; no secret is stored here. This is a localhost-only lab without TLS certificates.

After confirming no matching event existed, the prepared JSON was sent once to `POST /events`. MISP created unpublished, organization-only event **ID 1**, UUID `0d97a833-75a8-46b1-a499-b99313ad31c9`. A separate read of `/events/view/1.json` confirmed exactly three attributes with intact comments and mapping:

| Value | Type | `to_ids` |
| --- | --- | --- |
| `looksta.icu` | `domain` | `true` |
| `104.21.33.112` | `ip-dst` | `false` |
| `172.67.161.227` | `ip-dst` | `false` |

All three attributes have category `Network activity` and distribution `0`. Event distribution is also `0`; it remains unpublished. The event view displays a **contextualisation warning** because no tags or galaxy clusters are attached. That is a real MISP UI warning, separate from warning-list hits.

All 225 installed warning lists were initially disabled, so an initial empty `checkValue` result was not meaningful. The relevant **List of known Cloudflare IP ranges** (ID 33, version `20260811`) was enabled and the three values were checked again. Both IPs matched: `104.21.33.112` against `104.16.0.0/13`, and `172.67.161.227` against `172.64.0.0/13`. The domain had no match in this enabled list. These hits support treating the IPs as shared-infrastructure context, not standalone blocking indicators.

An `attributes/restSearch` query with `includeCorrelations=true` returned all three attributes and no related attributes for any of them. The UI correlation graph was empty. This new instance had only this event and both built-in feeds (`CIRCL OSINT Feed` and `The Botvrij.eu Data`) were disabled; the result does not rule out relationships in other data sources. The server export was saved separately and checked for the three attributes and absence of configured secrets. Its SHA-256 is `CE56FCE639264C5FC2A1BA44AB9021DEC45616D30FEFCA1EEB583DAAA43523DE`.

Actual screenshots are indexed in [`images/week3/README.md`](../images/week3/README.md). The browser captures show the local MISP UI, including the enabled warning list and empty correlation graph. The specific warning-list hits and per-attribute correlation counts were checked through its API; their response bodies are not separately published.

## Repeating the import and verification

1. Use an authorized, isolated laboratory MISP instance with no automatic publishing or synchronization. If an instance still needs to be provisioned, follow the [official MISP Docker project](https://github.com/MISP/misp-docker) and its current setup instructions. This repository neither installs MISP nor stores credentials.
2. Run `python scripts/process_week3_iocs.py --check` from the repository root. Review the raw source records and the three attributes before importing.
3. Import the JSON using the instance's supported event import function, or use the authenticated event-creation API (`POST /events`) with the JSON file as the body. The [official automation guide](https://www.circl.lu/doc/misp/automation/) describes that payload. Use the instance's trusted TLS configuration; keep API keys outside the repository and screenshots. API/UI behavior and permissions must be checked on the actual installed version.
4. Record the actual response and server event ID. If creation fails or the result is uncertain, inspect the event list before retrying. The draft has no persistent UUID, so blindly submitting it again can create duplicate events.
5. Open the saved event. Verify exactly three imported attributes, their values/types/categories, domain `to_ids=true`, both IPs `to_ids=false`, retained comments, unpublished status, and organization-only distribution. Investigate any rejected or altered fields before recording success.
6. Review available warning-list matches and correlations in that instance. Record the actual result, review time, and feed/data scope. Context IPs can still correlate even when `to_ids=false`; any match requires interpretation. “No matches observed” is only valid after an actual review.
7. Export the saved event as MISP JSON. After reviewing sensitive metadata, save the genuine output as `misp/week3-event-export.json`. Preserve the prepared input separately; do not rename it to imply it came from a server.
8. Capture actual event, attribute, and correlation views under `images/week3/`, then update the Week 3 report and README status with links to that evidence. Record any redactions. Leave missing or unperformed steps explicitly pending.

The [screenshot checklist](../images/week3/README.md) specifies exactly what each planned view should show. Local processing evidence is available in the [validation transcript](../evidence/week3-validation.txt).

## Evidence status

| Item | Status |
| --- | --- |
| Input dataset and deterministic import preparation | Available in this repository |
| Local processing tests and generated-file checks | Passed; see the Week 3 report |
| Installed MISP version | `2.5.47` |
| Import response / stored event ID | Event ID 1, UUID recorded above |
| Server-side attribute validation | Three values and flags confirmed by separate read |
| Warning-list and correlation review | Cloudflare list: both IPs matched; no correlations in current local data |
| Screenshots | Four genuine UI captures under `images/week3/` |
| MISP server export | `week3-event-export.json` |

This is external OSINT preparation for a safe-simulation project. Do not visit the indicator domain, probe these IP addresses, download malware, or use real credentials as part of the laboratory exercise.
