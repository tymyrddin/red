# Remote code execution (RCE)

Remote code execution (RCE) occurs when an attacker can execute arbitrary code on a target machine because of a
vulnerability or misconfiguration. RCEs are extremely dangerous, as attackers can often ultimately compromise the web
application or even the underlying web server. This control can be used further in several ways, including lateral
movement through the internal network using the trust the target server has with other systems on the network.

It is often not obvious which, if any, inputs might influence command-line execution. Common vulnerabilities to look for
that can lead to a command injection attack:

* Applications may enable users to run arbitrary commands, and run these commands as is to the underlying host.
* An application may allow users to upload files with arbitrary file extensions, these files could include malicious
  commands. On most web servers, placing such files in the webroot will result in command injection.
* [Insecure serial](id.md): If deserialisation is performed without proper verification, it can result in command
  injection.
* [Server-side template injection (SSTI)](ssti.md): If applications use server-side templates to generate dynamic HTML
  responses, it may be possible to insert malicious server-side templates.
* [XML external entity injection (XXE)](xxe.md) occurs in applications that use a poorly-configured XML parser to parse
  user-controlled XML input. This vulnerability can cause exposure of sensitive
  data, [server-side request forgery (SSRF)](ssrf.md), or denial of service attacks.

Many pentesters, red teamers and bounty hunters aim to find command injection vulnerabilities due to the impact they can
have.

## Steps

1. Gather information about the target. Identify suspicious user-input locations. For code injections, take note of
   every user-input location, including URL parameters, HTTP headers, body parameters, and file uploads. To find
   potential file inclusion vulnerabilities, check for input locations being used to determine or construct filenames
   and for file-upload functions.
2. Try test payloads to the input locations in order to detect potential vulnerabilities.
3. If requests are blocked, try protection-bypass techniques and see if the payload succeeds.
4. Confirm the vulnerability by trying to execute harmless commands such as `whoami`, `ls`, and `sleep 5`.
5. Avoid reading sensitive system files or altering any files with the vulnerability found.
6. Draft report.

## Gather information about the target

The first step to finding any vulnerability is to [gather information](https://recon.tymyrddin.dev/docs/app/README)
about the target. When hunting for RCEs, this step is especially important because the route to achieving an RCE is
extremely dependent on the way the target is built. The web server, programming language, and other technologies in
use determine which payloads carry the proper syntax.

## Identify suspicious user input locations

As with finding many other vulnerabilities, the next step to finding any RCE is to identify the locations where users
can submit input to the application. When hunting for code injections, take note of every direct user-input location,
including URL parameters, HTTP headers, body parameters, and file uploads.

Sometimes applications parse user-supplied files and concatenate their contents unsafely into executed code, so any
input that eventually reaches a command is worth watching. Potential file inclusion shows up in input locations used to
determine filenames or paths, and in any file-upload functionality.

## Submit test payloads

The next thing is to submit test payloads to the application. Use payloads that are meant to be interpreted by the
server as code and see if they get executed. Because the actual command being influenced by an input is often
obfuscated, try a variety of payloads to increase the odds that something will result in a noticeable behaviour that
indicates successful injection. Try:

* Filenames
* URLs
* Statement termination and comments
* Filename wildcards, redirection, substitution, and pipelines

Include blind tests as malicious payloads for:

* Invocations of programs that cause a measurable delay in application such as `sleep` and `ping`.
* Invocations of programs that have discernible impact outside the server such as `ping`, `netcat`, and `curl`.

## Confirm the vulnerability

Finally, confirm the vulnerability by executing harmless commands like `whoami`, `ls`, and `sleep 5`.

## Bypassing protections

Many applications have caught on to the dangers of RCE and employ either input validation or a firewall to stop
potentially malicious requests. Programming languages are flexible enough that an attacker can often work within the
input-validation rules and still land the command.

For Unix system commands, quotes and double quotes can be inserted without changing the command’s behaviour. Wildcards
substitute for arbitrary characters where the system filters certain strings, and empty command-substitution results
slip into the string without altering it. For example, these all print the contents of `/etc/shadow`:

```bash
cat /etc/shadow
cat "/e"tc'/shadow'
cat /etc/sh*dow
cat /etc/sha``dow
cat /etc/sha$()dow
cat /etc/sha${}dow
```

Payloads can be hex-encoded, URL-encoded, double-URL-encoded, and varied in case. Special characters, null bytes,
newlines, escape characters (`\`), and other non-ASCII characters all go in as probes. Observing which are blocked and
which succeed shows where an exploit can be crafted to bypass the filter.

## Escalation

Escalating an RCE calls for caution. Most organisations would rather it were not escalated at all, since that means
someone poking around systems that hold confidential data.

During a penetration test, the usual move after gaining RCE is to enumerate the current user's privileges and attempt
privilege escalation. In a bug bounty context that is rarely appropriate: a stray command can read customer data or
damage the system by altering a critical file, so the program rules are worth reading closely before going further.

For a classic RCE, a proof of concept that runs a harmless command like `whoami` or `ls`, or reads a common system file
such as `/etc/passwd`, is enough to demonstrate the finding.

## Variants

OS command injection runs from the simple case, where output comes straight back, to the
blind cases that carry no visible response: detection through time delays, output redirected
to a readable file, and out-of-band interaction or data exfiltration to a Collaborator
payload. The [server-side injection runbook](../runbooks/injection.md) covers command
injection alongside the other server-side classes that reach code execution.

## Resources

* [Portswigger Lab: Remote code execution via web shell upload](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload)
* [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)

## Counter moves

Remote code execution (RCE) is the case here. These come back to the same answers: validated input, encoded output,
server-side authorisation, and patched dependencies. The defensive counterpart is in the blue notes
on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
