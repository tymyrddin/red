# Runbook: Path traversal

Path traversal turns a filename parameter into a way to read, and sometimes write, files
outside the directory the application meant to expose. Detection is quick; the work is
climbing the bypass ladder when the application has bolted on partial defences. This runbook
follows that ladder from a clean traversal to the awkward cases.

## Prerequisites

- Parameters that look file-related from recon: `file=`, `path=`, `template=`, `download=`,
  `image=`, and anything ending in a filename.
- A file that reliably exists to confirm a read (`/etc/passwd` on Linux,
  `C:\Windows\win.ini` on Windows).
- Burp Repeater for iterating on encodings.

## Phase 1: Confirm a clean traversal

Point a candidate parameter at a known file with enough `../` sequences to reach the root:

```
file=../../../../../../etc/passwd
```

A response containing the file's contents confirms traversal with no filtering in place.
Record the depth that worked.

## Phase 2: Absolute path

Where traversal sequences are stripped, an absolute path skips them entirely:

```
file=/etc/passwd
```

If the application only blocks `../` but happily opens an absolute path, this is the whole
bypass.

## Phase 3: Non-recursive stripping

Where a filter removes `../` once, in a single pass, nest the sequence so that removing the
inner one leaves a working outer one:

```
....//....//....//etc/passwd
..././..././etc/passwd
```

## Phase 4: Encoding bypasses

Where the filter matches on the literal `../`, encode it so the filter misses it but the
server decodes it back:

```
%2e%2e%2f                # URL-encoded ../
%252e%252e%252f          # double-encoded, for a server that decodes twice
..%c0%af                 # overlong UTF-8 separator on some stacks
```

Double encoding is the one to reach for when a single decode happens before the filter and a
second decode happens after it.

## Phase 5: Start-of-path validation

Where the application insists the path begins with an expected base directory, give it that
base and then traverse out:

```
file=/var/www/images/../../../etc/passwd
```

## Phase 6: Extension validation

Where the value has to end in an expected extension, terminate the real path early with a
null byte and append the expected suffix to satisfy the check:

```
file=../../../etc/passwd%00.png
```

This depends on a backend that truncates at the null byte, which older language runtimes do.

## Output

- The vulnerable parameter and the exact bypass (absolute, nested, encoded, base-relative,
  null byte) that worked.
- File contents retrieved, with attention to credentials, config, and source that feed
  further attacks.
- Any write primitive found, which raises the impact considerably.

## Techniques

- [Directory traversal](../techniques/traversal.md)
- [Server-side injection testing](injection.md)

## Counter moves

Runbook: Path traversal is the case here. Avoiding user input in filesystem calls, resolving
and confirming the canonical path stays within an allowed root, and serving static content
through the framework are the counters. Seen from the other side, this sits in the blue notes
on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
