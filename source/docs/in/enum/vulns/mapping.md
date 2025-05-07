# Mapping vulnerabilities to exploits

## Attack tree

```text
1 List and score exploitable vulnerabilities 
    1.1 by Common Vulnerability Scoring System (CVSS) (OR)
        1.1.1 Calculate Exploitability
        1.1.2 Calculate Impact
        1.1.3 f(Impact)
        1.1.4 BaseScore
    1.2 by Vulnerability Priority Rating (VPR)
2 Prioritisation possibilities
    2.1 Severity level
    2.2 Vulnerability exposure
    2.3 Criticality
```

## Common Vulnerability Scoring System (CVSS)

The Common Vulnerability Scoring System (CVSS) is a standard vulnerability scoring
system used by vulnerability scanners to identify the severity of the vulnerability.
A CVSS base score can be a number from 0 to 10, with 0 being the least severe, and
10 being the most severe.

The format of the base score for CVSS2:

```text
CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C
```

Three metrics are used to calculate the exploitability of a vulnerability: 

* The access vector (AV), used to measure how the hacker executes the exploit. Does she have to have physical access 
to the system, be in an adjacent network and use pivoting, or is the vulnerability exploitable from a remote network?
* The attack complexity (AC), to describe how easy or difficult it is to exploit the vulnerability.
* Authentication (Au), used to specify how many times she would need to authenticate to exploit the vulnerability.

```text
Exploitability = 20 * AV * AC * Au
```

Impact metrics are used to identify what the impact of the exploit is on the confidentiality (C), integrity (I), and 
availability (A) of systems and their data. The values can be None (N), Partial (P) or Complete (C)

```text
Impact = 10.41 * (1-(1-C)*(1-I)*(1-A))
f(Impact) = 0 if Impact = 0, 1.176 otherwise.
```

End score:

```text
BaseScore = roundToOneDecimal(( (0.6*Impact) + (0.4*Exploitability)-1.5) * f(Impact))
```

## Vulnerability Priority Rating (VPR)

The VPR framework is a more modern framework in vulnerability management - developed by Tenable, an industry 
solutions provider for vulnerability management. This framework is considered to be risk-driven; meaning that 
vulnerabilities are given a score with a heavy focus on the risk a vulnerability poses to the organisation itself, 
rather than factors such as impact (like with CVSS).

Unlike CVSS, VPR scoring takes into account the relevancy of a vulnerability. For example, no risk is considered 
regarding a vulnerability if that vulnerability does not apply to the organisation. VPR is also considerably 
dynamic in its scoring, where the risk that a vulnerability may pose can change almost daily as it ages.

VPR uses a similar scoring range as CVSS. Two notable differences are 
that VPR does not have a `None/Informational` category, and because 
[VPR uses a different scoring method (youtube)](https://www.youtube.com/watch?v=XYIsBeRV1YQ), the same 
vulnerability will have a different score using VPR than when using CVSS.

## Nessus

In Nessus, the Vulnerability Information includes whether known exploits are available for a vulnerability. 
The section labeled “Exploitable With” even shows what tools can be used to exploit the vulnerability.

## Real Risk Score (RRS)

Real Risk Score (RRS) not only takes into account the equation behind the CVSS of each vulnerability, but also the 
Metasploit modules that could be launched against it, the malware kits detected, and even how old the vulnerability is.

## Resources

* [NVD CVSS v2 Calculator](https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator)
* [NVD CVSS v3 Calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator) 
* [Vulnerability Priority Rating (VPR) Summary](https://www.tenable.com/sc-dashboards/vulnerability-priority-rating-vpr-summary)
* [Real Risk Score](https://www.rapid7.com/products/insightvm/features/real-risk-prioritization/)