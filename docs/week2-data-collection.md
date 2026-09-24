# Week 2 – Data Collection Process

## Project Topic

**Forensic Analysis and Detection of Simulated Infostealer-Like Activity in Windows Environments**

## Objective

The objective of Week 2 is to collect and analyze relevant external threat intelligence using OSINT sources.

The collected information is used to better understand infostealer-related indicators, infrastructure, and relationships before building the controlled Windows laboratory for later stages of the project.

## Hunting Question

**What publicly available indicators and threat intelligence can help us understand infostealer-related activity and identify useful data sources for future threat-hunting experiments?**

## Data Sources

The following OSINT tools and sources were used:

| Source                  | Purpose                                                                                  |
| ----------------------- | ---------------------------------------------------------------------------------------- |
| VirusTotal              | Analyze public information related to domains, files, hashes, URLs, and IP addresses     |
| Shodan                  | Investigate publicly visible information about Internet-facing IP addresses and services |
| Maltego                 | Visualize relationships between indicators and related infrastructure                    |
| MITRE ATT&CK            | Provide behavioral and adversary-technique context                                       |
| Public security reports | Obtain documented indicators and information about infostealer activity                  |

## Data Collection Process

The Week 2 workflow was:

1. Select a publicly documented infostealer-related indicator from a reliable security report.
2. Analyze and enrich the indicator using VirusTotal.
3. Identify related IP addresses using passive DNS information.
4. Investigate relevant infrastructure using Shodan.
5. Use Maltego to visualize DNS and infrastructure relationships.
6. Compare information from multiple sources instead of treating a single reputation result as definitive evidence.
7. Document important observations and limitations.

## Selected Indicator

The domain `looksta[.]icu` was selected as the primary indicator for the Week 2 investigation.

The indicator was obtained from a public Microsoft Security report discussing ACR Stealer activity.

| Indicator       | Type   | Original Source                                  |
| --------------- | ------ | ------------------------------------------------ |
| `looksta[.]icu` | Domain | Microsoft Security Research – ACR Stealer report |

## VirusTotal Analysis

VirusTotal was used to investigate the selected domain and related infrastructure.

At the time of analysis, the root domain `looksta.icu` showed **0/89 detections**. However, additional context showed that this result alone was not sufficient to classify the domain as safe.

VirusTotal also showed:

* multiple detected files communicating with the domain;
* a related `www.looksta.icu` hostname with detections;
* passive DNS relationships;
* associated IP addresses.

The following IP addresses were observed through passive DNS information:

* `104.21.33.112`
* `172.67.161.227`

Several communicating Windows executable or DLL files also showed significant detection ratios in VirusTotal.

This demonstrated an important limitation of relying only on the detection score of a root domain. A zero detection count does not automatically mean that an indicator is safe. Related files, hostnames, infrastructure, and external threat intelligence must also be considered.

## Shodan Analysis

The IP address `104.21.33.112` was investigated using Shodan.

Shodan identified the address as infrastructure belonging to:

* **Organization:** Cloudflare, Inc.
* **ASN:** AS13335

Several HTTP and HTTPS-related services and ports were visible in the Shodan results.

However, this information must be interpreted carefully. Cloudflare provides shared infrastructure for many unrelated websites and services.

Therefore, the IP address cannot be directly attributed to the investigated threat actor or infostealer campaign.

The Shodan result was useful for understanding the infrastructure context, but not for direct attribution.

## Maltego Analysis

Maltego was used to visualize relationships associated with `looksta.icu`.

The domain was added as the initial entity and a **Domain Name System (DNS) Lookup** transform was executed.

The resulting graph displayed DNS-related entities and infrastructure associated with the investigated domain.

Maltego was useful for visually representing relationships between the initial observable and related infrastructure.

The graph was treated as contextual information rather than proof that every connected entity was malicious or directly controlled by the same threat actor.

## Data Source Mapping

| Data Type         | Source                                               | Use in the Project                                               |
| ----------------- | ---------------------------------------------------- | ---------------------------------------------------------------- |
| Domain            | VirusTotal / Maltego                                 | Reputation, relationships, and infrastructure context            |
| File              | VirusTotal                                           | Identify files communicating with investigated infrastructure    |
| IP address        | VirusTotal / Shodan / Maltego                        | Network and infrastructure context                               |
| ATT&CK technique  | MITRE ATT&CK                                         | Behavioral classification                                        |
| Threat report     | Microsoft Security Research and other public reports | Threat context and documented activity                           |
| Windows telemetry | Future controlled laboratory                         | Internal evidence for later threat-hunting and forensic analysis |

## Collected Indicators

| Indicator        | Type       | VirusTotal Result                                                                               | Shodan Result                                            | Maltego Result                    |
| ---------------- | ---------- | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------- | --------------------------------- |
| `looksta[.]icu`  | Domain     | Root domain showed 0/89 detections, but related detected files and infrastructure were observed | Related IP infrastructure was associated with Cloudflare | DNS relationships were visualized |
| `104.21.33.112`  | IP address | Observed through passive DNS                                                                    | Cloudflare, Inc., AS13335                                | Related infrastructure entity     |
| `172.67.161.227` | IP address | Observed through passive DNS                                                                    | Not required for the initial Shodan investigation        | Related infrastructure entity     |

## Evidence and Screenshots

The following evidence was collected during the Week 2 investigation:

* VirusTotal domain analysis
* VirusTotal relations and passive DNS information
* VirusTotal domain details
* Shodan infrastructure analysis
* Maltego DNS relationship graph

## Week 2 Result

During Week 2, OSINT sources were used to investigate a publicly documented infostealer-related indicator.

VirusTotal provided reputation, file, and passive DNS context. Shodan provided information about the related Internet-facing infrastructure, while Maltego was used to visualize DNS relationships.

The investigation also demonstrated the importance of source correlation. A single reputation score or IP address is not enough to make a reliable conclusion. Threat intelligence should be evaluated together with related indicators, infrastructure context, source reliability, and known limitations.

The collected information provides external threat context that can later be compared with telemetry generated in the controlled Windows threat-hunting laboratory.
