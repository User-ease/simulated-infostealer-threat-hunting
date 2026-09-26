# Week 2 – Data Collection Process

## Project Topic

**Forensic Analysis and Detection of Simulated Infostealer-Like Activity in Windows Environments**

## Objective

The objective of Week 2 is to collect and analyze relevant external threat intelligence using OSINT sources.

The collected information is used to better understand infostealer-related indicators, infrastructure, and relationships before building the controlled Windows laboratory for later stages of the project.

## Hunting Question

**What publicly available indicators and threat intelligence can help us understand infostealer-related activity and identify useful data sources for future threat-hunting experiments?**

## Data Sources

The following sources and tools form the collection workflow. VirusTotal and Shodan results are supported by saved screenshots. A Maltego graph export records a later NS transform result:

| Source                  | Purpose                                                                                  |
| ----------------------- | ---------------------------------------------------------------------------------------- |
| VirusTotal              | Analyze public information related to domains, files, hashes, URLs, and IP addresses     |
| Shodan                  | Investigate publicly visible information about Internet-facing IP addresses and services |
| Maltego                 | Visualize relationships between indicators and related infrastructure                    |
| MITRE ATT&CK            | Provide behavioral and adversary-technique context                                       |
| Public security reports | Obtain documented indicators and information about infostealer activity                  |

## Data Collection Process

The Week 2 workflow and its evidence status are:

1. Select a publicly documented infostealer-related indicator from a reliable security report.
2. Analyze and enrich the indicator using VirusTotal.
3. Identify related IP addresses using passive DNS information.
4. Investigate relevant infrastructure using Shodan.
5. Add the domain in Maltego, run the DNS NS transform, and export the resulting relationship graph.
6. Compare information from multiple sources instead of treating a single reputation result as definitive evidence.
7. Document important observations and limitations.

## Observation Date

The VirusTotal and Shodan OSINT observations and screenshots documented in this report were captured on **24 September 2026**. The Maltego NS graph was generated separately on **26 September 2026**.

VirusTotal, Shodan, passive DNS, and other external intelligence sources are dynamic. Detection counts, resolved IP addresses, exposed services, and relationships may change after the observation date.

## Selected Indicator

The domain `looksta[.]icu` was selected as the primary indicator for the Week 2 investigation.

The indicator was obtained from a public Microsoft Security Research report discussing ACR Stealer activity, published on 16 July 2026.

| Indicator       | Type   | Original Source                                  |
| --------------- | ------ | ------------------------------------------------ |
| `looksta[.]icu` | Domain | Microsoft Security Research – ACR Stealer report |

## VirusTotal Analysis

VirusTotal was used to investigate the selected domain and related infrastructure.

At the time of analysis, the root domain `looksta.icu` showed **0/89 detections**. However, additional information showed that this result alone was not sufficient to classify the domain as safe.

VirusTotal also showed:

* multiple detected files communicating with the domain;
* a related `www.looksta.icu` hostname with detections;
* passive DNS relationships;
* associated IP addresses.

The following IP addresses were observed through passive DNS information:

* `104.21.33.112`
* `172.67.161.227`

The saved **Relations / Passive DNS Replication** view lists **Date resolved: 22 April 2026** for both IP addresses. This is the date shown by the source, distinct from the **24 September 2026** collection date. It is not treated as a first-seen/last-seen range or evidence of a current DNS resolution.

Several communicating Windows executable or DLL files also showed detections in VirusTotal.

This demonstrated an important limitation of relying only on the detection score of a root domain. A zero detection count does not automatically mean that an indicator is safe. Related files, hostnames, infrastructure, and external threat intelligence should also be considered.

### VirusTotal – Detection

![VirusTotal Detection](../images/week2/virustotal-detection.png)

### VirusTotal – Relations

![VirusTotal Relations: passive DNS, subdomains, and communicating files](../images/week2/virustotal-passive-dns.png)

### VirusTotal – Details

![VirusTotal Details: last DNS records](../images/week2/virustotal-dns-records.png)

## Shodan Analysis

The IP address `104.21.33.112` was investigated using Shodan.

Shodan identified the address as infrastructure belonging to:

* **Organization:** Cloudflare, Inc.
* **ASN:** AS13335

Several HTTP and HTTPS-related services and ports were visible in the Shodan results.

However, this information must be interpreted carefully. Cloudflare provides shared infrastructure for many different websites and services.

Therefore, the IP address cannot be directly attributed to the investigated threat actor or infostealer campaign.

The Shodan result was useful for understanding the infrastructure context, but not for direct attribution.

### Shodan – IP Analysis

![Shodan IP Analysis](../images/week2/shodan-ip-analysis.png)

## Maltego Analysis

The original screenshot shows only the initial `looksta.icu` domain entity. On 26 September 2026, Maltego Graph (Desktop) 4.13.0 ran `[Utilities] To DNS Name - NS (name server)` on that entity. The transform output reported two returned entities, and the exported graph shows two links from the domain to NS records: `kami.ns.cloudflare.com` and `hunts.ns.cloudflare.com`. Both values were also checked in Maltego's entity detail view. The graph contains **3 entities and 2 links**.

These are name-server relationships observed on the later run. They do not establish malicious ownership or attribution, and they do not independently verify the two historical passive DNS IP associations. Those IP associations remain supported by the saved VirusTotal evidence.

### Maltego – Initial Domain Entity

![Maltego initial domain entity; relationship results not shown](../images/week2/maltego-initial-entity.png)

### Maltego – Verified NS Relationship Graph

![Maltego graph export showing looksta.icu linked to kami.ns.cloudflare.com and hunts.ns.cloudflare.com](../images/week2/maltego-ns-graph.png)

## Data Source Mapping

| Data Type         | Source                                               | Use in the Project                                               |
| ----------------- | ---------------------------------------------------- | ---------------------------------------------------------------- |
| Domain            | VirusTotal; Maltego NS graph                          | Reputation, passive DNS context, and observed NS relationships      |
| File              | VirusTotal                                           | Identify files communicating with investigated infrastructure    |
| IP address        | VirusTotal / Shodan                                 | Network and infrastructure context; no confirmed Maltego output   |
| ATT&CK technique  | MITRE ATT&CK                                         | Behavioral classification                                        |
| Threat report     | Microsoft Security Research and other public reports | Threat context and documented activity                           |
| Windows telemetry | Future controlled laboratory                         | Internal evidence for later threat-hunting and forensic analysis |

## Collected Indicators

| Indicator        | Type       | VirusTotal Result                                                                               | Shodan Result                                                  | Maltego Result                    |
| ---------------- | ---------- | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | --------------------------------- |
| `looksta[.]icu`  | Domain     | Root domain showed 0/89 detections, but related detected files and infrastructure were observed | Related IP infrastructure was associated with Cloudflare       | Linked to two Cloudflare NS records |
| `104.21.33.112`  | IP address | Observed through passive DNS                                                                    | Cloudflare, Inc., AS13335                                      | Not shown in saved evidence |
| `172.67.161.227` | IP address | Observed through passive DNS                                                                    | Not investigated separately during the initial Shodan analysis | Not shown in saved evidence |

## Key Findings

The OSINT investigation produced several useful observations:

* A single VirusTotal detection score should not be treated as a final verdict.
* Relationships with detected files and related hostnames can provide additional context.
* Passive DNS can identify infrastructure related to an investigated domain.
* Shared infrastructure such as Cloudflare limits the usefulness of an IP address for direct attribution.
* The later Maltego NS transform returned two name servers; this is DNS context, not attribution or proof of malicious ownership.
* Information from several sources should be correlated before drawing conclusions.

## Bridge to Future Threat Hunting

The external threat intelligence collected during Week 2 will later be used to guide the design of the controlled threat-hunting laboratory.

Public threat reports describe behaviors associated with infostealer activity, while the saved VirusTotal and Shodan results provide additional indicator and infrastructure context. The later Maltego graph adds observed name-server relationships.

For the later laboratory stage, only safe simulated behaviors will be reproduced using synthetic data. The project will not attempt to reproduce ACR Stealer or any other real infostealer exactly.

| Threat Intelligence Source    | Documented or Relevant Behavior            | Planned Safe Simulation                                    | Future Evidence Source                      | Limitation                                                                     |
| ----------------------------- | ------------------------------------------ | ---------------------------------------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------ |
| Public threat reports         | Data collection and staging                | Copy synthetic browser-like files into a staging directory | Windows telemetry and file artifacts        | Simulation does not reproduce real credential theft                            |
| Public threat reports         | Archive creation                           | Create an archive containing synthetic data                | Process and file creation telemetry         | Archive creation is also common in legitimate activity                         |
| Public threat reports         | Network communication                      | Connect to a controlled local receiver                     | Windows network telemetry and receiver logs | A network connection alone does not prove that a specific file was transferred |
| VirusTotal / Shodan | Indicator and infrastructure relationships | Use the collected OSINT as external context                | Week 2 OSINT records                        | Related infrastructure does not automatically prove malicious ownership        |

This connection allows the Week 2 OSINT results to provide context for later hypothesis-driven threat hunting without treating external indicators as sufficient evidence by themselves.

## Week 2 Result

During Week 2, OSINT sources were used to investigate a publicly documented infostealer-related indicator.

VirusTotal provided reputation, file, and passive DNS context. Shodan provided information about related Internet-facing infrastructure. The later Maltego NS transform returned two name servers, and the actual relationship graph was exported. The Week 2 collection and visualization steps are therefore documented with evidence; Maltego was not used to reverify the historical IP addresses.

The investigation demonstrated the importance of source correlation. A single reputation score or IP address is not enough to make a reliable conclusion. Threat intelligence should be evaluated together with related indicators, infrastructure context, source reliability, and known limitations.

The collected information provides external threat context that can later support the design of controlled threat-hunting experiments in the Windows laboratory.

## References

* Microsoft Security Research. *ACR Stealer: Two observed intrusion chains amid increased threat activity*. Published 16 July 2026. https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/
* VirusTotal. Domain report for `looksta.icu`. Accessed 24 September 2026. https://www.virustotal.com/gui/domain/looksta.icu
* Shodan. Host information for `104.21.33.112`. Accessed 24 September 2026. https://www.shodan.io/host/104.21.33.112
* MITRE ATT&CK. *Enterprise ATT&CK*. Accessed 24 September 2026. https://attack.mitre.org/
