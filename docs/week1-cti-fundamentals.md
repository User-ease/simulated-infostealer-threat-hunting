# Week 1 – Cyber Threat Intelligence Fundamentals

## Project Topic

**Forensic Analysis and Detection of Simulated Infostealer-Like Activity in Windows Environments**

## Objective

The goal of this project is to study infostealer-related threat activity and apply threat-hunting, forensic analysis, and detection techniques in a controlled Windows environment.

The project does not use real malware or real credentials. All experiments will use synthetic data and simulated activity.

## Key CTI Terms

| Term | Description |
|---|---|
| CTI | Cyber Threat Intelligence is analyzed information about cyber threats used to support defensive decisions. |
| IOC | Indicator of Compromise, such as a malicious IP address, domain, file hash, or URL. |
| IOA | Indicator of Attack, describing suspicious behavior that may indicate an ongoing attack. |
| TTP | Tactics, Techniques, and Procedures used by threat actors. |
| Threat Hunting | Proactive search for suspicious or malicious activity that may not have triggered existing security alerts. |
| Infostealer | Malware designed to collect valuable information such as browser credentials, cookies, session data, and system information. |

## Threat Classification

For this project, the main threat category is **information-stealing malware**.

Typical infostealer-related activity may include:

- System discovery
- Browser data collection
- Credential or session data collection
- Data staging
- Archive creation
- Network communication or exfiltration
- Cleanup of temporary files

## Threat Intelligence Sources

The project will use several types of sources:

- MITRE ATT&CK
- Security vendor reports
- VirusTotal
- Shodan
- Public malware and threat reports
- Windows telemetry generated in our own laboratory

## Initial Threat-Hunting Direction

The project will later investigate whether Windows telemetry can reveal suspicious behavioral patterns associated with simulated infostealer-like activity.

Example hypothesis:

> A process that collects data from several locations, creates a staging archive, and shortly afterwards establishes a network connection may indicate suspicious information-stealing behavior.

## Week 1 Result

During Week 1, the project topic was defined and the basic CTI concepts relevant to the project were identified. The threat was classified as information-stealing malware activity, and initial intelligence sources and behavioral characteristics were selected for further investigation.
