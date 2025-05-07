# XML external entity (XXE) injection

* We can modify XML documents and define the document using a DTD. If an entity is declared within a DTD it is called as internal entity.

```text
<!ENTITY entity_name "entity_value">
```

* If an entity is declared outside a DTD it is called as external entity. Identified by SYSTEM.

    `<!ENTITY entity_name SYSTEM "entity_value">`
  
* Parsers can resolve external references that could be displayed to the user.
* You can use [these XXE Templates](https://raw.githubusercontent.com/tymyrddin/scripts-webapp/main/resources/xxe-templates.md).

## Steps

1. Find data entry points that you can use to submit XML data.
2. Determine whether the entry point is a candidate for a classic or blind XXE. The endpoint might be vulnerable to classic XXE if it returns the parsed XML data in the HTTP response. If the endpoint does not return results, it might still be vulnerable to blind XXE, and you should
set up a callback listener for your tests.
3. Try out a few test payloads to see if the parser is improperly configured. In the case of classic XXEs, you can check whether the parser is processing external entities. In the case of blind XXEs, you can make the server send requests to your callback listener to see if you can trigger outbound interaction.
4. If the XML parser has the functionalities that make it vulnerable to XXE attacks, try to exfiltrate a common system file, like /etc/hostname.
5. You can also try to retrieve some more sensitive system files, like `/etc/shadow` or `~/.bash_history`.
6. If you cannot exfiltrate the entire file with a simple XXE payload, try to use an alternative data exfiltration method.
7. See if you can launch an SSRF attack using the XXE.
8. Draft up report.

## Escalation

What can be achieved with an XXE vulnerability depends on the permissions given to the XML parser. Generally, XXEs can be used to access and exfiltrate system files, source code, and directory listings on the local machine. You can also use XXEs to perform [SSRF attacks](ssrf.md) to port-scan the target’s network, read files on the network, and access resources that are hidden behind a firewall. And, attackers sometimes use XXEs to launch DoS attacks.

* Disclosing local files containing sensitive data, like passwords, using file: schemes or relative paths in the system identifier.
* XXE attacks rely on the application that processes the XML document. A trusted application can be used to move to different internal systems.
* If the XML processor library is vulnerable to client-side memory corruption, it may be possible to dereference a malicious URI to allow [arbitrary code execution](rce.md) under the application account.
* Some XML attacks might allow actors to access local resources that do not stop returning data. If too many processes or threads are not released, it can negatively impact application availability.

## Portswigger lab writeups

* [Exploiting XXE using external entities to retrieve files](../burp/xxe/1.md)
* [Exploiting XXE to perform SSRF attacks](../burp/xxe/2.md)
* [Blind XXE with out-of-band interaction](../burp/xxe/3.md)
* [Blind XXE with out-of-band interaction via XML parameter entities](../burp/xxe/4.md)
* [Exploiting blind XXE to exfiltrate data using a malicious external DTD](../burp/xxe/5.md)
* [Exploiting blind XXE to retrieve data via error messages](../burp/xxe/6.md)
* [Exploiting XInclude to retrieve files](../burp/xxe/7.md)
* [Exploiting XXE via image file upload](../burp/xxe/8.md)
* [Exploiting XXE to retrieve data by repurposing a local DTD](../burp/xxe/9.md)

## Remediation

* Manual XXE Prevention: Prevent vulnerabilities in entities outside XML by configuring the XML parser to disallow custom DTDs. Applications rarely require DTD, because there are very few functional trade-offs. Every parser in each programming language comes with its own requirements for setting this parameter. A project containing several analyses might require manually configuring each solver correctly.
* If you cannot disable DTDs, mitigate this risk by disabling the external entity functionality.
* Implement some application server instrumentation using runtime application self protection (RASP) to add personalised protection for applications and interactive application security testing (IAST) to find vulnerabilities during execution.

## Resources

* [Portswigger: XML external entity (XXE) injection](https://portswigger.net/web-security/xxe)
* [OWASP: XML External Entity (XXE) Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
* [OWASP: XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)


