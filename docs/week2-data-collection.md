# Week 2 – Data Collection Process

## Project Topic

**Forensic Analysis and Detection of Simulated Infostealer-Like Activity in Windows Environments**

## Objective

The objective of Week 2 is to identify and collect relevant external threat intelligence for the project using OSINT sources.

The collected information will later be used to better understand infostealer-related infrastructure, indicators, and behavioral patterns before building the controlled Windows laboratory.

## Hunting Question

**What publicly available indicators and threat intelligence can help us understand infostealer-related activity and identify useful data sources for our future threat-hunting experiments?**

## Data Sources

The following OSINT tools and sources will be used:

| Source                  | Purpose                                                                                  |
| ----------------------- | ---------------------------------------------------------------------------------------- |
| VirusTotal              | Analyze public information related to files, hashes, domains, URLs, and IP addresses     |
| Shodan                  | Investigate publicly visible information about Internet-facing IP addresses and services |
| Maltego                 | Visualize relationships between indicators and related infrastructure                    |
| MITRE ATT&CK            | Identify relevant adversary techniques and behavioral context                            |
| Public security reports | Obtain documented indicators and information about infostealer activity                  |

## Data Collection Process

The Week 2 workflow is:

1. Select publicly documented infostealer-related indicators from a reliable source.
2. Verify and enrich the indicators using VirusTotal.
3. Check relevant IP addresses or infrastructure using Shodan when applicable.
4. Use Maltego to visualize relationships between selected indicators.
5. Record the source, timestamp, and observed information.
6. Compare information from multiple sources instead of treating a single reputation result as definitive evidence.

## Data Source Mapping

| Data Type         | Possible Source                            | Use in the Project                             |
| ----------------- | ------------------------------------------ | ---------------------------------------------- |
| File hash         | VirusTotal                                 | File reputation and related information        |
| Domain            | VirusTotal / Maltego                       | Reputation and infrastructure relationships    |
| IP address        | VirusTotal / Shodan / Maltego              | Network and service information                |
| ATT&CK technique  | MITRE ATT&CK                               | Behavioral classification                      |
| Threat report     | Security vendors / CERT / research sources | Context and documented activity                |
| Windows telemetry | Our laboratory                             | Internal evidence used in later project stages |

## Collected Indicators

The indicators selected for analysis will be documented after OSINT collection.

| Indicator   | Type | Original Source | VirusTotal | Shodan | Maltego |
| ----------- | ---- | --------------- | ---------- | ------ | ------- |
| To be added | -    | -               | -          | -      | -       |

## Evidence and Screenshots

Screenshots from the OSINT investigation will be added here:

* VirusTotal analysis
* Shodan analysis
* Maltego relationship graph

## Initial Result

Week 2 establishes the external intelligence collection process for the project.

The collected OSINT will provide context for the simulated infostealer-like activity that will later be generated in the controlled Windows environment. Information from external sources will be compared and corroborated rather than relying on a single reputation score or source.
