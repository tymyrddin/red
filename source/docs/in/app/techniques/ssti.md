# Template injection (SSTI)

Template engines are a type of software used to determine the appearance of a web page. Developers often overlook
attacks that target these engines, called server-side template injections (SSTIs), yet they can lead to severe
consequences, like [remote code execution](rce.md). They have become more common in the past few years.

* This bug is critical. The impact could be an RCE attack, not just on the affected server, but on other hosts on the
  same network.
* An SSTI found in an application exposes the application, web server, and network.
* Looking for SSTI means entering values to be evaluated; a value that comes back evaluated is the signal to dig deeper.

## Steps

1. Identify any opportunity to submit user input to the application. Note candidates for template injection for further
   inspection.
2. Detect template injection by submitting test payloads, either payloads designed to induce errors or engine-specific
   payloads designed to be evaluated by the template engine.
3. Where an endpoint is vulnerable to template injection, determine the template engine in use. This guides building an
   exploit specific to that engine.
4. Research the template engine and programming language the target uses to construct an exploit.
5. Escalate the vulnerability towards arbitrary command execution.
6. Create a proof of concept that does not harm the targeted system. Executing `touch template_injection_by_NAME.txt` to
   create a specific proof-of-concept file is one safe way.
7. Draft report.

## Look for user-input locations

Look for locations that accept user input: URL paths, parameters, fragments, HTTP request headers and body, file
uploads, and more.

Templates are typically used to dynamically generate web pages from stored data or user input. For example, applications
often use template engines to generate customised email or home pages based on the user’s information. So the candidates
for template injection are endpoints that accept user input that will eventually be displayed back to the user. Since
these endpoints typically coincide with the endpoints for possible XSS attacks, the [XSS strategies](xss.md) identify
candidates for template injection too. Document these input locations for further testing.

## Detect template injection by submitting test payloads

Next, detect template injection vulnerabilities by injecting a test string into the input fields identified in the
previous step. This test string contains special characters commonly used in template languages.

* The string `{{1+abcxx}}${1+abcxx}<%1+abcxx%>[abcxx]` ia designed to induce errors in popular template engines.
* `${...}` is the special syntax for expressions in the FreeMarker and Thymeleaf Java templates.
* `{{...}}` is the syntax for expressions in PHP templates such as Smarty or Twig, and Python
  templates like Jinja2.
* `<%= ... %>` is the syntax for the Embedded Ruby template (ERB).

## Determine the template engine in use

Once the vulnerability is confirmed, determine the template engine in use to work out how best to exploit it. Escalation
calls for a payload written in the language the particular template engine expects.

## Automation

[tplmap](https://github.com/epinna/tplmap/) can scan for template injections, determine the template engine in use, and
construct exploits. While this tool does not support every template engine, it does provide a good starting point for
the most popular ones.

## Escalation

The impact of server-side template injection vulnerabilities is generally critical, resulting
in [remote code execution](rce.md) by taking full control of the back-end server. Even without the code execution, the
attacker may be able to [read sensitive data on the server](disclosure.md). There are also rare cases where an SSTI
vulnerability is not critical, depending on the template engine.

Once the template engine is known, the vulnerability can be escalated. The `7*7` payload is the usual starting point:

```text
GET /display_name?name=7*7
Host: example.com
```

Showing that the injection accomplishes more than simple arithmetic proves the impact of the bug and its value to the
security team.

The method of escalation depends on the template engine in play. The official documentation of the engine and the
accompanying programming language is the place to learn the specifics.

Being able to [execute system commands](rce.md) might allow for [reading sensitive system files](disclosure.md) like
customer data and source code files, update system configurations, escalate their privileges on the system, and attack
other machines on the network.

## Variants

The cases run from a basic injection (plain and in code context) through engine-specific
exploitation built from the documentation, including an unknown language identified by a
documented exploit. Where execution is blocked, information disclosure via user-supplied
objects or a sandbox escape carries the impact, and the hardest cases need a custom exploit.
The [server-side injection runbook](../runbooks/injection.md) covers the probe, engine
fingerprinting, and the route to code execution.

## Resources

* [Server-Side Template Injection: RCE for the modern webapp, James Kettle](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)
* [Portswigger: Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection)
* [OWASP: Testing for Server Side Template Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)

## Counter moves

Template injection (SSTI) is the variant in play. These come back to the same answers: validated input, encoded output,
server-side authorisation, and patched dependencies. The defender's view can be found in the blue notes
on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
