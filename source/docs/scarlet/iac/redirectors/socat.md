# Socat redirector

For protocols that are not HTTP, the simplest redirector is a TCP or UDP forwarder. Socat does this in one line.

## Plain TCP forward

```bash
socat TCP4-LISTEN:443,fork,reuseaddr TCP4:frontend.<otherdomain>.com:443
```

The fork option spawns a child per connection so the listener stays available. The reuseaddr option lets the
redirector restart without waiting for TIME_WAIT to clear.

## TLS pass-through

For HTTPS where the redirector does not terminate the certificate:

```bash
socat -d -d \
    TCP4-LISTEN:443,fork,reuseaddr \
    TCP4:frontend.<otherdomain>.com:443
```

The frontend keeps the certificate. The redirector just shuffles bytes.

## Persisting it

Either run under tmux, or drop a systemd unit on the bouncer-deployed host:

```ini
[Unit]
Description=Socat redirector
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP4-LISTEN:443,fork,reuseaddr TCP4:frontend.example.com:443
Restart=always

[Install]
WantedBy=multi-user.target
```

## When to choose socat over nginx

* The C2 protocol is not HTTP (raw TCP, custom binary, DNS).
* No filtering or content inspection is needed at this hop.
* The host is short-lived and the smallest possible footprint is wanted.

For HTTP/HTTPS where any inspection or routing is wanted, use [nginx instead](nginx-redirector.md).
