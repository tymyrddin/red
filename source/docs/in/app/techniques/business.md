# Application logic errors

Application (business) logic errors are a different beast. These are not about patterns. Developers take decisions in the code, and after processing them, they have a result. When they do that, they think about just the possible options they have from design.

Finding logic bugs and not just security bugs is hard using static analysis or automated tools, and if testing is done from the application's design paradigms, the fails are never detected. Options outside the chosen paradigms were not thought of. Attackers might.

## Steps

1. Try to understand how the application works using an HTTP proxy. Focus on the variables and parameters that could be used to control the application's flow. Use automated tools for port scanning, vulnerability assessments, and configuration management issues.
2. Intercept requests while browsing the application and pay attention to sensitive functionalities. Keep track of every request sent during these actions.
3. Replicate previous vulnerabilities between applications.
4. Use your creativity to think of ways to interfere with application logic.
5. Think of ways to combine the vulnerability you’ve found with other vulnerabilities to maximise the potential impact of the flaw.
6. Draft the report.

## Learn about the target

Start by learning about your target application. Browse the application as a regular user to uncover functionalities and interesting features. You can also read the application’s engineering blogs and documentation. The more you understand about the architecture, development process, and business needs of that application, the better you will be at spotting these vulnerabilities.

## Intercept requests while browsing

Intercept requests while browsing the site and pay attention to sensitive functionalities. Keep track of every request sent during these actions. Take note of how sensitive functionalities and access control are implemented, and how they interact with client requests.

## Think outside the box

Use your creativity to think of ways to bypass access control or otherwise interfere with application logic. Play with the requests that you have intercepted and craft requests that should not be granted.

## Escalation

Escalating application logic errors depends entirely on the nature of the flaw you find. But a general rule of thumb is that you can try to combine the application logic error or broken access control with other vulnerabilities to increase their impact.

If you can find the configuration files of a web application, you can search for CVEs for the software versions in use to further compromise the application.

Think of ways malicious users can exploit these vulnerabilities to the fullest extent, and communicate their impact in detail in the report.

## Portswigger lab writeups

* [Excessive trust in client-side controls](../burp/business/1.md)
* [High-level logic vulnerability](../burp/business/2.md)
* [Inconsistent security controls](../burp/business/3.md)
* [Flawed enforcement of business rules](../burp/business/4.md)
* [Low-level logic flaw](../burp/business/5.md)
* [Inconsistent handling of exceptional input](../burp/business/6.md)
* [Weak isolation on dual-use endpoint](../burp/business/7.md)
* [Insufficient workflow validation](../burp/business/8.md)
* [Authentication bypass via flawed state machine](../burp/business/9.md)
* [Infinite money logic flaw](../burp/business/10.md)
* [Authentication bypass via encryption oracle](../burp/business/11.md)

## Remediation

* Everybody involved in developing the software needs to understand the domain that the application serves.
* Avoid making implicit assumptions about user behaviour or the behaviour of other parts of the application.
* Assess the codebase to understand the business rules and logic of the application and identify the security controls in place, how they work, and any control gaps.
  * Identify assumptions made about server-side states and implement the logic to verify that these assumptions are met. This includes verifying the value of any input makes sense before proceeding.
  * Maintain clear design documents and data flows for all transactions and workflows, noting any assumptions that are made at each stage. 
  * If it is difficult to understand what is supposed to happen, it will be difficult to spot any logic flaws. In unavoidably complex cases, producing clear documentation is essential to ensure that other developers and testers know what assumptions are being made and exactly what the expected behaviour is. 
  * Note any references to other code that uses each component. Think about any side effects of these dependencies if a malicious party were to manipulate them in an unusual way.

## Resources

* [CWE CATEGORY: Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)
* [Portswigger: Business logic vulnerabilities](https://portswigger.net/web-security/logic-flaws)
* [OWASP: Business logic vulnerability](https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability)


