# Template injection (SSTI)

Template engines are a type of software used to determine the appearance of a web page. Developers often overlook attacks that target these engines, called server-side template injections (SSTIs), yet they can lead to severe consequences, like [remote code execution](rce.md). They have become more common in the past few years.

* This bug is critical. The impact could be an RCE attack, not just in the affected server, but in other hosts on the same network.
* An SSTI found in an application exposes the application, web server, and network.
* To look for SSTI vulnerabilities, enter values to be evaluated and if you get a result, try harder.

## Steps

1. Identify any opportunity to submit user input to the application. Mark down candidates of template injection for further inspection.
2. Detect template injection by submitting test payloads. You can use either payloads that are designed to induce errors, or engine-specific payloads designed to be evaluated by the template engine.
3. If you find an endpoint that is vulnerable to template injection, determine the template engine in use. This will help you build an exploit specific to the template engine.
4. Research the template engine and programming language that the target is using to construct an exploit.
5. Try to escalate the vulnerability to arbitrary command execution.
6. Create a proof of concept that does not harm the targeted system. A good way to do this is to execute `touch template_injection_by_YOUR_NAME.txt` to create a specific proof-of-concept file.
7. Draft report.

## Look for user-input locations

Look for locations where you can submit user input to the application. These include URL paths, parameters, fragments, HTTP request headers and body, file uploads, and more.

Templates are typically used to dynamically generate web pages from stored data or user input. For example, applications often use template engines to generate customised email or home pages based on the user’s information. So to look for template injections, look for endpoints that accept user input that will eventually be displayed back to the user. Since these endpoints typically coincide with the endpoints for possible XXS attacks, you can use the [XSS strategies](xss.md) to identify candidates for template injection. Document these input locations for further testing.

## Detect template injection by submitting test payloads

Next, detect template injection vulnerabilities by injecting a test string into the input fields identified in the previous step. This test string should contain special characters commonly used in template languages. 

* The string `{{1+abcxx}}${1+abcxx}<%1+abcxx%>[abcxx]` ia designed to induce errors in popular template engines. 
* `${...}` is the special syntax for expressions in the FreeMarker and Thymeleaf Java templates.
* `{{...}}` is the syntax for expressions in PHP templates such as Smarty or Twig, and Python
templates like Jinja2.
* `<%= ... %>` is the syntax for the Embedded Ruby template (ERB).

## Determine the template engine in use

Once you’ve confirmed the template injection vulnerability, determine the template engine in use to figure out how to best exploit that vulnerability. To escalate the attack, you will have to write your payload with a programming language that the particular template engine expects.

## Automation

[tplmap](https://github.com/epinna/tplmap/) can scan for template injections, determine the template engine in use, and construct exploits. While this tool does not support every template engine, it does provide a good starting point for the most popular ones.

## Escalation

The impact of server-side template injection vulnerabilities is generally critical, resulting in [remote code execution](rce.md) by taking full control of the back-end server. Even without the code execution, the attacker may be able to [read sensitive data on the server](disclosure.md). There are also rare cases where an SSTI vulnerability is not critical, depending on the template engine.

Once you’ve determined the template engine in use, you can escalate the vulnerability found. Most of the time, you can use the `7*7 payload`:

    GET /display_name?name=7*7
    Host: example.com

But if you can show that the template injection can be used to accomplish more than simple mathematics, you can prove the impact of the bug and show the security team its value.

The method of escalating the attack will depend on the template engine you are targeting. To learn more about it, read the official documentation of the template engine and the accompanying programming language. 

Being able to [execute system commands](rce.md) might allow for [reading sensitive system files](disclosure.md) like customer data and source code files, update system configurations, escalate their privileges on the system, and attack other machines on the network.

## Portswigger lab writeups

* [Basic server-side template injection](../burp/ssti/1.md)
* [Basic server-side template injection (code context)](../burp/ssti/2.md)
* [Server-side template injection using documentation](../burp/ssti/3.md)
* [Server-side template injection in an unknown language with a documented exploit](../burp/ssti/4.md)
* [Server-side template injection with information disclosure via user-supplied objects](../burp/ssti/5.md)
* [Server-side template injection in a sandboxed environment](../burp/ssti/6.md)
* [Server-side template injection with a custom exploit](../burp/ssti/7.md)

## Remediation

* Remediation for SSTI vulnerabilities depend on the different template engines in use.
* Do not create templates from user-controlled input. User input should be passed to the template using template parameters. Sanitise the input before passing it into the templates by removing unwanted and risky characters before parsing the data. This minimises the vulnerabilities for any malicious probing of your templates.
* If allowing risky characters is a requirement to render attributes of a template, assume that malicious code execution is inevitable, and use a sandbox within a safe environment. With the template environment in a docker container, you can use docker security to craft a secure environment that limits malicious activities.

## Resources

* [Server-Side Template Injection: RCE for the modern webapp, James Kettle](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)
* [Portswigger: Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection)
* [OWASP: Testing for Server Side Template Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)


