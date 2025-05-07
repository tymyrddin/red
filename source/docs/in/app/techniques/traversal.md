# Directory traversal

Directory traversal (also called Path traversal) is an exploit which lets attackers access restricted directories, execute commands and view data outside the normal Web server directory where the application content is stored.

By manipulating files with "dot-dot-slash (`../`)" sequences and its variations, or by using absolute file paths, it may be possible to access arbitrary files and directories stored on the filesystem; including application source code, configuration, and other critical system files.

## Steps

1. Enumerate input vectors.
2. Analyse input validation functions.

## Enumeration

List all application components that can accept user input, such as `HTTP`, `POST` and `GET` calls, HTML forms, and file uploads. Check for:

* Request parameters which can potentially be used for file-related operations, such as `getUserProfile.jsp?item=abcd.html`.
* Unusual file extensions, like `index.jsp?file=content`.
* Interesting variable names, for example `main.php?home=index.htm`.

## Analysis

Try inserting relative paths into files existing on the web server, for example:

    ../../../../../../etc/hosts
    ../../../../../../etc/passwd

## Bypass protections

Many applications that place user input have some kind of protection against path traversal attacks:

* Applications can strip or block directory traversal sequences from the user-supplied filename => try an absolute path, nested traversal, and url encoding (in a `multipart/form-data request`).
* Some applications validate start of path => include the required base folder followed by suitable traversal sequences.
* It can be that the filename value must end with an expected file extension => try a null byte like `%00` before inserting a valid extension.

### Absolute paths

Absolute path from the filesystem root to directly reference a file without using any traversal sequences:

    filename=/etc/hosts
    filename=/etc/passwd

### Nested traversal

Nested traversal sequences which will revert to simple traversal sequences when the inner sequence is stripped:

    ....//
    ....\/

### URL encoding

Check whether a system is vulnerable to certain tricks like a `../` removal that uses percent-encoded values:

    url encoding: %2e%2e%2f
    double url encoding: %252e%252e%252f 

### Null byte bypass

    filename=../../../etc/passwd%00.png

## Escalation

With a directory traversal, it may be possible to read arbitrary files on the server that is running the application. This might include application code and data, credentials for back-end systems, and sensitive operating system files. In some cases, it may be possible to write to arbitrary files on the server, modifying application data or behaviour, and ultimately taking full control of the server. 

## Portswigger lab writeups

* [File path traversal, simple case](../burp/traversal/1.md)
* [File path traversal, traversal sequences blocked with absolute path bypass](../burp/traversal/2.md)
* [File path traversal, traversal sequences stripped non-recursively](../burp/traversal/3.md)
* [File path traversal, traversal sequences stripped with superfluous URL-decode](../burp/traversal/4.md)
* [File path traversal, validation of start of path](../burp/traversal/5.md)
* [File path traversal, validation of file extension with null byte bypass](../burp/traversal/6.md)

## Remediation

* Avoid relying on user-supplied input when dealing with filesystem APIs. Oh well, back to the drawing board, because this might require rewriting a major part of the application.
* Prevent the user-supplied directory from being higher up on the filesystem than the directory used to serve static content.
* Sanitise user-supplied data and get rid of unexpected inputs, for example by maintaining a set of allowed filesystem paths and comparing user input against that set or by allowing only alphanumeric characters and rejecting inputs that contain other characters.
* If that is not possible, consider disallowing dangerous characters explicitly.
* Sanitisation of user input is a never-ending story and requires constant verification against newly discovered ways to bypass known protection methods. It may be better to use a well-maintained open-source library for it. Check these open source libraries with vulnerability scanners to find the best candidates.
* Another option is to build the application with web frameworks, which have built-in support for serving static content.
* Use [secure coding practices](https://devsecops.tymyrddin.dev/docs/notes/coding) at every stage of the development and operations pipeline:
  * Static application security testing (SAST) reviews the source code of the application when it is not running. SAST checks try to identify evidence of known insecure practices and vulnerabilities. SAST solutions employ white-box techniques.
  * Dynamic application security testing (DAST) communicates with the application through its front-end in order to identify security vulnerabilities. A DAST tool does not need any access to source code. It simulates real attacks using a black-box strategy. Security checks are done while executing or running the application or code under review. It can also involve fuzzing to uncover directory traversal vulnerabilities.

## Resources

* [Portswigger: Directory traversal](https://portswigger.net/web-security/file-path-traversal)
* [OWASP: Path traversal](https://owasp.org/www-community/attacks/Path_Traversal)
