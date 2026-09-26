# Week 3 MISP screenshots

**Status: four MISP UI screenshots captured on 26 September 2026**, around 13:02–13:07 UTC (18:02–18:07 Asia/Qyzylorda), from the localhost MISP 2.5.47 instance. They were captured in Edge after logging in to the real event. No UI content was synthesized or redacted.

| File | Capture from the actual laboratory | What it establishes |
| --- | --- | --- |
| `misp-event.png` | Saved event showing ID, title, date, publication status, and distribution | The event exists in the instance and its settings can be inspected |
| `misp-attributes.png` | All three attributes with values, types, categories, and IDS flags visible | One domain candidate and two contextual IPs were stored with the intended mapping |
| `misp-correlation.png` | Actual correlation view for the saved event, including an empty result when observed | The correlation result available in that instance at the time of review |
| `misp-warninglist.png` | Enabled Cloudflare warning list, ID 33, with its CIDR ranges | The list used for the actual warning-list checks |

The event ID is 1. The [Week 3 report](../../docs/week3-data-processing.md) records versions, exact warning-list hits, zero correlations returned by the API, and the limited data scope. The correlation screenshot shows an empty graph; it is not a global claim that no relationships exist.

The genuine server export is retained separately as [`misp/week3-event-export.json`](../../misp/week3-event-export.json). The screenshots supplement that export. The lab uses a synthetic organization and email address; no credentials, API keys, or unrelated events appear in these captures.

The offline processing run is documented by `evidence/week3-validation.txt`. A terminal screenshot is optional because the transcript and reproducible checks provide the relevant processing evidence.
