# Directory traversal

Directory traversal (also called Path traversal) is an exploit which lets attackers access restricted directories,
execute commands and view data outside the normal Web server directory where the application content is stored.

By manipulating files with "dot-dot-slash (`../`)" sequences and its variations, or by using absolute file paths, it may
be possible to access arbitrary files and directories stored on the filesystem; including application source code,
configuration, and other critical system files.

## Steps

1. Enumerate input vectors.
2. Analyse input validation functions.

## Enumeration

List all application components that can accept user input, such as `HTTP`, `POST` and `GET` calls, HTML forms, and file
uploads. Check for:

* Request parameters which can potentially be used for file-related operations, such as
  `getUserProfile.jsp?item=abcd.html`.
* Unusual file extensions, like `index.jsp?file=content`.
* Interesting variable names, for example `main.php?home=index.htm`.

## Analysis

Try inserting relative paths into files existing on the web server, for example:

```text
../../../../../../etc/hosts
../../../../../../etc/passwd
```

## Bypass protections

Many applications that place user input have some kind of protection against path traversal attacks:

* Applications can strip or block directory traversal sequences from the user-supplied filename ⇒ try an absolute path,
  nested traversal, and url encoding (in a `multipart/form-data request`).
* Some applications validate start of path ⇒ include the required base folder followed by suitable traversal sequences.
* The filename value may have to end with an expected file extension ⇒ try a null byte like `%00` before
  inserting a valid extension.

### Absolute paths

Absolute path from the filesystem root to directly reference a file without using any traversal sequences:

```text
filename=/etc/hosts
filename=/etc/passwd
```

### Nested traversal

Nested traversal sequences which will revert to simple traversal sequences when the inner sequence is stripped:

```text
....//
....\/
```

### URL encoding

Check whether a system is vulnerable to certain tricks like a `../` removal that uses percent-encoded values:

```text
url encoding: %2e%2e%2f
double url encoding: %252e%252e%252f
```

### Null byte bypass

```text
filename=../../../etc/passwd%00.png
```

## Escalation

With a directory traversal, it may be possible to read arbitrary files on the server that is running the application.
This might include application code and data, credentials for back-end systems, and sensitive operating system files. In
some cases, it may be possible to write to arbitrary files on the server, modifying application data or behaviour, and
ultimately taking full control of the server.

## Variants

The cases form a bypass ladder: the simple traversal, an absolute path where sequences are
stripped, nesting where stripping is non-recursive, double URL-decoding where a superfluous
decode happens after the filter, a base directory followed by traversal where the start of
the path is validated, and a null byte before an expected extension. The
[path traversal runbook](../runbooks/traversal.md) walks that ladder rung by rung.

## Resources

* [Portswigger: Directory traversal](https://portswigger.net/web-security/file-path-traversal)
* [OWASP: Path traversal](https://owasp.org/www-community/attacks/Path_Traversal)

## Counter moves

Directory traversal is what this page works through. These come back to the same answers: validated input, encoded
output, server-side authorisation, and patched dependencies. Seen from the other side, this sits in the blue notes
on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
