# Week 3 screenshot checklist

**Status: no MISP screenshots captured.** The files listed below are planned evidence names; they do not yet exist. Do not generate mock MISP screens or reuse Week 2 screenshots as proof of Week 3 execution.

| Planned file | Capture from the actual laboratory | What it establishes |
| --- | --- | --- |
| `misp-event.png` | Saved event showing ID, title, date, publication status, and distribution | The event exists in the instance and its settings can be inspected |
| `misp-attributes.png` | All three attributes with values, types, categories, and IDS flags visible | One domain candidate and two contextual IPs were stored with the intended mapping |
| `misp-correlation.png` | Actual correlation view for the saved event, including an empty result when observed | The correlation result available in that instance at the time of review |

Record the MISP version, event ID, capture time and timezone, relevant feed/data scope, and any redactions in `docs/week3-data-processing.md`. Add Markdown image links only after the corresponding files actually exist. An empty correlation view is not a global claim that no relationships exist.

Retain the genuine server export separately as `misp/week3-event-export.json`; compare its attribute values and flags with the prepared input. Screenshots supplement that export, not replace it. Exclude API keys, credentials, unrelated events, and private instance metadata from public evidence, and document any redactions.

The offline processing run is documented by `evidence/week3-validation.txt`. A terminal screenshot is optional because the transcript and reproducible checks provide the relevant processing evidence.
