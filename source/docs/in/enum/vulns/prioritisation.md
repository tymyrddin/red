# Prioritisation of vulnerabilities

* Asset categorisation — how critical is the system that has vulnerabilities?
* Adjudication — making a decision on whether the vulnerability discovered is a false positive. Review and validate.
* Prioritisation of vulnerabilities — if a vulnerability exploits confidentiality, integrity, or availability, then
that vulnerability would typically take priority.

## Common Vulnerability Scoring System (CVSS)

### Advantages

* CVSS has been around for a long time.
* CVSS is popular in organisations.
* CVSS is a free framework to adopt and recommended by organisations such as NIST.

### Disadvantages

* CVSS was never designed to help prioritise vulnerabilities, instead, just assign a value of severity.
* CVSS heavily assesses vulnerabilities on an exploit being available. Only 20% of all vulnerabilities have 
an exploit available ([Tenable., 2020](https://www.tenable.com/research)).
* Vulnerabilities rarely change scoring after assessment despite the fact that new developments such as exploits 
may be found.

## Vulnerability Priority Rating (VPR)

### Advantages

* VPR is a modern framework that is real-world.
* VPR considers over 150 factors when calculating risk.
* VPR is risk-driven and used by organisations to help prioritise patching vulnerabilities.
* Scorings are not final and are very dynamic, meaning the priority a vulnerability should be given can change as the 
vulnerability ages.

### Disadvantages

* VPR is not open-source like some other vulnerability management frameworks.
* VPR can only be adopted separate from a commercial platform.
* VPR does not consider the CIA triad to the extent that CVSS does; meaning that risk to the confidentiality, integrity 
and availability of data does not play a large factor in scoring vulnerabilities when using VPR.

## Real Risk Score (RRS)

Real Risk Score (RRS) may offer a good alternative. It enriches CVSS data to provide a more precise risk score. 
