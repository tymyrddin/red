# Remote code execution (RCE)

Remote code execution (RCE) occurs when an attacker can execute arbitrary code on a target machine because of a vulnerability or misconfiguration. RCEs are extremely dangerous, as attackers can often ultimately compromise the web application or even the underlying web server. This control can be used further in several ways, including lateral movement through the internal network using the trust the target server has with other systems on the network.

It is often not obvious which, if any, inputs might influence command-line execution. Common vulnerabilities to look for that can lead to a command injection attack:

* Applications may enable users to run arbitrary commands, and run these commands as is to the underlying host.
* An application may allow users to upload files with arbitrary file extensions, these files could include malicious commands. On most web servers, placing such files in the webroot will result in command injection.
* [Insecure serial](id.md): If deserialisation is performed without proper verification, it can result in command injection.
* [Server-side template injection (SSTI)](ssti.md): If applications use server-side templates to generate dynamic HTML responses, it may be possible to insert malicious server-side templates. 
* [XML external entity injection (XXE)](xxe.md) occurs in applications that use a poorly-configured XML parser to parse user-controlled XML input. This vulnerability can cause exposure of sensitive data, [server-side request forgery (SSRF)](ssrf.md), or denial of service attacks.

Many pentesters, red teamers and bounty hunters aim to find command injection vulnerabilities due to the impact they can have. 

## Steps

1. Gather information about the target. Identify suspicious user-input locations. For code injections, take note of every user-input location, including URL parameters, HTTP headers, body parameters, and file uploads. To find potential file inclusion vulnerabilities, check for input locations being used to determine or construct filenames and for file-upload functions.
2. Try test payloads to the input locations in order to detect potential vulnerabilities.
3. If requests are blocked, try protection-bypass techniques and see if the payload succeeds.
4. Confirm the vulnerability by trying to execute harmless commands such as `whoami`, `ls`, and `sleep 5`.
5. Avoid reading sensitive system files or altering any files with the vulnerability found.
6. Draft report.

## Gather information about the target

The first step to finding any vulnerability is to [gather information](https://recon.tymyrddin.dev/docs/app/README) about the target. When hunting for RCEs, this step is especially important because the route to achieving an RCE is extremely dependent on the way the target is built. Find out information about the web server, programming language, and other technologies used by your current target. These will allow focusing the attacks on using payloads with the proper syntax.

## Identify suspicious user input locations

As with finding many other vulnerabilities, the next step to finding any RCE is to identify the locations where users can submit input to the application. When hunting for code injections, take note of every direct user-input location, including URL parameters, HTTP headers, body parameters, and file uploads. 

Sometimes applications parse user-supplied files and concatenate their contents unsafely into executed code, so **any input** that is eventually passed into commands is something you should look out for. To find potential file inclusion vulnerabilities, check for input locations being used to determine filenames or paths, as well as any file-upload functionalities in the application.

## Submit test payloads

The next thing is to submit test payloads to the application. Use payloads that are meant to be interpreted by the server as code and see if they get executed. Because the actual command being influenced by an input is often obfuscated, try a variety of payloads to increase the odds that something will result in a noticeable behaviour that indicates successful injection. Try:

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

Many applications have caught on to the dangers of RCE and employ either input validation or a firewall to stop potentially malicious requests. But programming languages are often quite flexible, and that enables us to work within the bounds of the input validation rules to make our attack work.

For Unix system commands, you can insert quotes and double quotes without changing the command’s behaviour. You can also use wildcards to substitute for arbitrary characters if the system is filtering out certain strings. And any empty command substitution results can be inserted into the string without changing the results. For example, these will all print the contents of `/etc/shadow`:

    cat /etc/shadow
    cat "/e"tc'/shadow'
    cat /etc/sh*dow
    cat /etc/sha``dow
    cat /etc/sha$()dow
    cat /etc/sha${}dow

You can hex-encode, URL-encode, double-URL-encode, and vary the cases (uppercase or lowercase characters) of payloads. You can try to insert special characters such as null bytes, newline characters, escape characters (`\`), and other special or non-ASCII characters into the payload. Then, observe which payloads are blocked and which ones succeed, and craft exploits that will bypass the filter to accomplish the desired results.

## Escalation

Be extra cautious when escalating RCE vulnerabilities. Most companies would prefer that you do not try to escalate them at all because they do not want someone poking around systems that contain confidential data. 

During a typical penetration test, a hacker will often try to figure out the privileges of the current user and attempt privilege-escalation attacks after they gain RCE. In a bug bounty context, this is not appropriate. You might accidentally read sensitive information about customers or cause damage to the systems by modifying a critical file. It is important to carefully read the bounty program rules, so you do not cross the lines.

For classic RCEs, create a proof of concept that executes a harmless command like `whoami` or `ls`. You can also prove to have found an RCE by reading a common system file such as `/etc/passwd`.

## Portswigger lab writeups

* [OS command injection, simple case](../burp/os/1.md)
* [Blind OS command injection with time delays](../burp/os/2.md)
* [Blind OS command injection with output redirection](../burp/os/3.md)
* [Blind OS command injection with out-of-band interaction](../burp/os/4.md)
* [Blind OS command injection with out-of-band data exfiltration](../burp/os/5.md)

## Remediation

* Avoid system calls and user input in applications where possible.
* Set up input validation.
* Create a white list of possible inputs, to make sure the system accepts only pre-approved inputs. 
* Use only secure APIs when executing system commands such as `execFile()`. Prevent users from gaining control over the name of the program and map user input to command arguments to prevent user input being passed as-is into program execution.

## Resources

* [Portswigger Lab: Remote code execution via web shell upload](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload)
* [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)



