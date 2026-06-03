# XML external entity (XXE) injection

* We can modify XML documents and define the document using a DTD. If an entity is declared within a DTD it is called as
  internal entity.

```text
<!ENTITY entity_name "entity_value">
```

* If an entity is declared outside a DTD it is called as external entity. Identified by SYSTEM.

  `<!ENTITY entity_name SYSTEM "entity_value">`

* Parsers can resolve external references that could be displayed to the user.
* [These XXE Templates](https://raw.githubusercontent.com/tymyrddin/scripts-webapp/main/resources/xxe-templates.md) help.

## Steps

1. Find data entry points that accept XML data.
2. Determine whether the entry point is a candidate for a classic or blind XXE. The endpoint might be vulnerable to
   classic XXE if it returns the parsed XML data in the HTTP response. If the endpoint does not return results, it might
   still be vulnerable to blind XXE; set up a callback listener for the tests.
3. Try a few test payloads to see whether the parser is improperly configured. For classic XXE, check whether the parser
   processes external entities. For blind XXE, make the server send requests to the callback listener to see whether
   outbound interaction can be triggered.
4. If the XML parser has the functionalities that make it vulnerable to XXE attacks, try to exfiltrate a common system
   file, like /etc/hostname.
5. More sensitive system files, like `/etc/shadow` or `~/.bash_history`, are worth retrieving too.
6. If a simple XXE payload cannot exfiltrate the entire file, use an alternative data exfiltration method.
7. Check whether the XXE can launch an SSRF attack.
8. Draft up report.

## Escalation

What can be achieved with an XXE vulnerability depends on the permissions given to the XML parser. Generally, XXEs can
be used to access and exfiltrate system files, source code, and directory listings on the local machine. XXEs can also
perform [SSRF attacks](ssrf.md) to port-scan the target’s network, read files on the network, and access resources that
are hidden behind a firewall. And, attackers sometimes use XXEs to launch DoS attacks.

* Disclosing local files containing sensitive data, like passwords, using file: schemes or relative paths in the system
  identifier.
* XXE attacks rely on the application that processes the XML document. A trusted application can be used to move to
  different internal systems.
* If the XML processor library is vulnerable to client-side memory corruption, it may be possible to dereference a
  malicious URI to allow [arbitrary code execution](rce.md) under the application account.
* Some XML attacks might allow actors to access local resources that do not stop returning data. If too many processes
  or threads are not released, it can negatively impact application availability.

## Variants

The classic case retrieves files through external entities or pivots to SSRF. The blind cases
rely on out-of-band interaction, including via XML parameter entities, exfiltration through a
malicious external DTD, error-based retrieval, and repurposing a local DTD already on the
server. XInclude reaches files where the input is not a full XML document, and image upload
(SVG) is a common entry point. The [server-side injection runbook](../runbooks/injection.md)
covers OOB exfiltration, error-based retrieval, and XInclude.

## Resources

* [Portswigger: XML external entity (XXE) injection](https://portswigger.net/web-security/xxe)
* [OWASP: XML External Entity (XXE) Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
* [OWASP: XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

## Counter moves

XML external entity (XXE) injection is the variant in play. These come back to the same answers: validated input,
encoded output, server-side authorisation, and patched dependencies. Defenders' notes on this are
under [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
