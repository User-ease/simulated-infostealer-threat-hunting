# Week 1 – Cyber Threat Intelligence Fundamentals

## Project Topic

**Forensic Analysis and Detection of Simulated Infostealer-Like Activity in Windows Environments**

## Objective

The objective of Week 1 is to review basic Cyber Threat Intelligence concepts, classify several common cyber threat types, identify relevant threat intelligence sources, and select the threat category that will be used in the project.

The project focuses on simulated infostealer-like activity in a controlled Windows environment.

The project does not use real malware or real credentials. All later experiments will use synthetic data and safe simulated activity.

## Key CTI Terms

| Term           | Description                                                                                                                            |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| CTI            | Cyber Threat Intelligence is analyzed and contextualized information about cyber threats used to support defensive decisions.          |
| IOC            | Indicator of Compromise, such as a suspicious or malicious IP address, domain, file hash, or URL.                                      |
| IOA            | Indicator of Attack, describing behavior that may indicate an ongoing or attempted attack.                                             |
| TTP            | Tactics, Techniques, and Procedures used by threat actors.                                                                             |
| Threat Hunting | Proactive investigation for suspicious or malicious activity that may not have triggered existing security alerts.                     |
| Infostealer    | Malware designed to collect valuable information such as browser data, credentials, session information, files, or system information. |

## Threat Classification

Cyber threats can be divided into different categories depending on their objectives and behavior.

| Threat Type                | Description                                                                                                 | Typical Example                                                                            |
| -------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Phishing                   | Social engineering attacks designed to trick users into revealing information or opening malicious content. | Credential phishing email or fake login page                                               |
| Ransomware                 | Malware that encrypts or disrupts access to files and systems, usually to demand payment.                   | File encryption followed by a ransom demand                                                |
| Remote Access Trojan (RAT) | Malware that provides unauthorized remote access and control over an infected system.                       | Remote command execution and system control                                                |
| Infostealer                | Malware designed to collect valuable information from an infected system.                                   | Collection of browser data, credentials, session information, files, or system information |

For this project, **infostealer-related activity** was selected as the main threat category.

Typical infostealer-related behavior may include:

* System discovery
* Browser-related data collection
* Credential or session data collection
* Data staging
* Archive creation
* Network communication or exfiltration
* Cleanup of temporary files

The later laboratory work will use only safe simulated activity and synthetic data. It will not attempt to reproduce a specific real infostealer exactly.

## Threat Intelligence Sources

The project will use several types of threat intelligence and security data sources:

* MITRE ATT&CK
* Security vendor reports
* Public malware and threat reports
* VirusTotal
* Shodan
* Maltego
* Windows telemetry generated later in the controlled laboratory

External sources will be used to understand documented indicators, infrastructure, and behaviors. Internal Windows telemetry will be used later to investigate simulated activity inside the laboratory environment.

## Initial Threat-Hunting Direction

The project will later investigate whether Windows telemetry can reveal suspicious behavioral patterns associated with simulated infostealer-like activity.

An initial example hypothesis is:

> A process that collects data from several locations, creates a staging archive, and shortly afterwards establishes a network connection may represent suspicious information-stealing behavior.

This is an initial threat-hunting direction rather than a confirmed detection rule. It will need to be tested later using controlled simulated activity and comparison with normal system behavior.

## Week 1 Result

During Week 1, key CTI concepts were reviewed and several common cyber threat categories were classified.

Infostealer-related activity was selected as the focus of the project. Relevant threat intelligence sources and typical behavioral characteristics were identified to support the data collection and analysis performed in the following weeks.

## References

* MITRE ATT&CK. *Enterprise ATT&CK*. https://attack.mitre.org/
* ENISA. *ENISA Threat Landscape 2026*. Published 22 September 2026. https://www.enisa.europa.eu/publications/enisa-threat-landscape-2026
* Microsoft Security Research. *ACR Stealer: Two observed intrusion chains amid increased threat activity*. Published 16 July 2026. https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/
