# Open Web Application Security Project (OWASP)

The OWASP Foundation is a nonprofit foundation focused on improving the security of software. OWASP released the 
popular [OWASP Top 10 document](https://owasp.org/www-project-top-ten/) that lists the ten most common security flaws 
in web applications that may put an organisation at risk. The OWASP Foundation has other projects as well, like 
[OWASP Mobile Application Security](https://owasp.org/www-project-mobile-app-security/).

## Top 10 2021

Listed here with its notable CWE's for quick references on low-hanging fruit.

### Broken Access Control

Many web applications do not enforce restrictions on what an authenticated user can do 
within the application. An attacker that exploits this flaw can gain access to sensitive information or
perform undesired actions. Notable Common Weakness Enumerations (CWEs) included are:
* [CWE-200](https://cwe.mitre.org/data/definitions/200.html): Exposure of Sensitive Information to an Unauthorized Actor
* [CWE-201](https://cwe.mitre.org/data/definitions/201.html): Insertion of Sensitive Information Into Sent Data
* [CWE-352](https://cwe.mitre.org/data/definitions/352.html): Cross-Site Request Forgery.

### Cryptographic Failures

The third most common flaw in web applications is sensitive data exposure flaws that involve web applications or
APIs not protecting sensitive data within the application. This could be financial data, healthcare data, or 
Personally Identifiable Information (PII) data. This could be due to a lack of encryption at rest and in transit, 
or other missing access control methods. Notable Common Weakness Enumerations (CWEs) included are:
* [CWE-259](https://cwe.mitre.org/data/definitions/259.html): Use of Hard-coded Password
* [CWE-327](https://cwe.mitre.org/data/definitions/327.html): Broken or Risky Crypto Algorithm
* [CWE-331](https://cwe.mitre.org/data/definitions/331.html): Insufficient Entropy

### Injection

Injection flaws occur when data is input into an application but the input is not sanitised or validated by the 
developer of the application. Notable Common Weakness Enumerations (CWEs) included are:
* [CWE-79](https://cwe.mitre.org/data/definitions/79.html): Cross-site Scripting 
* [CWE-89](https://cwe.mitre.org/data/definitions/89.html): SQL Injection 
* [CWE-73](https://cwe.mitre.org/data/definitions/73.html): External Control of File Name or Path

### Insecure Design

Insecure covers risk-related design flaws in applications. This new category looks to improve on the 
use of threat modeling and secure design patterns and principles during the development of the application. 
Notable Common Weakness Enumerations (CWEs) include: 
* [CWE-209](https://cwe.mitre.org/data/definitions/209.html): Generation of Error Message Containing Sensitive Information 
* [CWE-256](https://cwe.mitre.org/data/definitions/256.html): Unprotected Storage of Credentials, CWE-501: Trust Boundary Violation 
* [CWE-522](https://cwe.mitre.org/data/definitions/522.html): Insufficiently Protected Credentials

### Security Misconfiguration

Applications should have their default settings altered and security configuration settings reviewed as security
misconfigurations is a common flaw in web applications. Notable CWEs included are: 
* [CWE-16](https://cwe.mitre.org/data/definitions/16.html): Configuration 
* [CWE-611](https://cwe.mitre.org/data/definitions/611.html): Improper Restriction of XML External Entity Reference

### Vulnerable and Outdated Components
Components are libraries of code that an application may use. Development of an application may be following secure 
coding best practices, but once a third-party library is called, that component may be developed in an unsecure manner 
that exposes the application to security flaws.

### Identification and Authentication Failures

Flaws in authentication or session management may allow attackers to access passwords, keys, or session tokens. 
Notable CWEs included are: 
* [CWE-297](https://cwe.mitre.org/data/definitions/297.html): Improper Validation of Certificate with Host Mismatch 
* [CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication
* [CWE-384](https://cwe.mitre.org/data/definitions/384.html): Session Fixation

### Software and Data Integrity Failures

This flaw pertains to failures when verifying the integrity of components when applying software updates or updates to
critical data. Insecure Deserialization from 2017 is included in this category. Insecure deserialization flaws may 
result in an attacker being able to perform remote code execution, replay attacks, injection attacks, and privilege 
escalation attacks. Notable Common Weakness Enumerations (CWEs) include: 
* [CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere
* [CWE-494](https://cwe.mitre.org/data/definitions/494.html): Download of Code Without Integrity Check
* [CWE-502](https://cwe.mitre.org/data/definitions/502.html): Deserialization of Untrusted Data

### Security Logging and Monitoring Failures

Lack of logging and monitoring means that an application or system does not have the capabilities to detect and log 
breaches in security. Adequate logging and monitoring should be configured within an application or system to help 
determine the extent of a security breach during incident response. This category includes:
* [CWE-778](https://cwe.mitre.org/data/definitions/778.html): Insufficient Logging 
* [CWE-117](https://cwe.mitre.org/data/definitions/117.html): Improper Output Neutralization for Logs 
* [CWE-223](https://cwe.mitre.org/data/definitions/223.html): Omission of Security-relevant Information 
* [CWE-532](https://cwe.mitre.org/data/definitions/532.html): Insertion of Sensitive Information into Log File.

### Server-Side Request Forgery

This security flaw enables attackers to invoke requests from a vulnerable web application to another system. 
This category represents the scenario where the security community members are telling OWASP 
[this is important](red-recon:docs/seeking/ssrf), even though it’s not illustrated in the data yet.